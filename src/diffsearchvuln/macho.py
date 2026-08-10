from __future__ import annotations

import hashlib
import os
import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence
from uuid import uuid4

from .doctor import CommandOutput, Runner, _default_runner
from .vault import CHUNK_SIZE


MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}


class MachOError(RuntimeError):
    pass


@dataclass(frozen=True)
class MachOSlice:
    architecture: str
    uuid: str | None
    cpu_subtype: str | None = None


@dataclass(frozen=True)
class CodeSignature:
    status: str
    valid: bool
    identifier: str | None
    team_identifier: str | None
    cdhashes: tuple[str, ...]
    format: str | None
    authorities: tuple[str, ...]
    detail: str


@dataclass(frozen=True)
class MachOInspection:
    path: str
    sha256: str
    byte_size: int
    universal: bool
    slices: tuple[MachOSlice, ...]
    signature: CodeSignature

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class MachOInspector:
    def __init__(self, runner: Runner = _default_runner) -> None:
        self.runner = runner

    def inspect(self, path: str | Path) -> MachOInspection:
        artifact = Path(path).expanduser().resolve()
        if not artifact.is_file():
            raise MachOError(f"Mach-O artifact is not a regular file: {artifact}")
        with artifact.open("rb") as source:
            magic = source.read(4)
        if magic not in MACHO_MAGICS:
            raise MachOError(f"artifact does not have a Mach-O or universal binary header: {artifact}")

        sha256, byte_size = _digest_file(artifact)
        architectures = self._architectures(artifact)
        uuids = self._uuids(artifact)
        slices = tuple(
            MachOSlice(
                architecture=architecture,
                uuid=uuids.get(architecture),
                cpu_subtype=architecture if architecture == "arm64e" else None,
            )
            for architecture in architectures
        )
        return MachOInspection(
            path=str(artifact),
            sha256=sha256,
            byte_size=byte_size,
            universal=len(slices) > 1,
            slices=slices,
            signature=self._signature(artifact),
        )

    def materialize_slice(
        self,
        path: str | Path,
        architecture: str,
        destination: str | Path,
    ) -> MachOInspection:
        source = Path(path).expanduser().resolve()
        output = Path(destination).expanduser().resolve()
        inspection = self.inspect(source)
        available = {item.architecture for item in inspection.slices}
        if architecture not in available:
            raise MachOError(
                f"requested architecture {architecture} is not present; "
                f"available slices: {', '.join(sorted(available))}"
            )
        if output.exists():
            raise MachOError(f"slice destination already exists: {output}")
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.parent / f".{output.name}.{uuid4()}.partial"
        try:
            if inspection.universal:
                result = self.runner(
                    [
                        "/usr/bin/lipo",
                        str(source),
                        "-thin",
                        architecture,
                        "-output",
                        str(temporary),
                    ],
                    120,
                )
                if result.returncode != 0:
                    raise MachOError(
                        f"lipo could not materialize {architecture}: {_bounded_detail(result)}"
                    )
            else:
                shutil.copyfile(source, temporary)
            derived = self.inspect(temporary)
            derived_architectures = tuple(item.architecture for item in derived.slices)
            if derived.universal or derived_architectures != (architecture,):
                raise MachOError(
                    f"derived slice has unexpected architectures: {derived_architectures}"
                )
            try:
                os.link(temporary, output)
            except FileExistsError as error:
                raise MachOError(f"slice destination already exists: {output}") from error
            return self.inspect(output)
        finally:
            temporary.unlink(missing_ok=True)

    def _architectures(self, path: Path) -> tuple[str, ...]:
        output = self.runner(["/usr/bin/lipo", "-archs", str(path)], 30)
        if output.returncode != 0:
            raise MachOError(f"lipo could not inspect {path}: {_bounded_detail(output)}")
        architectures = tuple(part for part in output.stdout.split() if part)
        if not architectures:
            raise MachOError(f"lipo returned no architecture slices for {path}")
        unsupported = [arch for arch in architectures if arch not in {"arm64", "arm64e", "x86_64"}]
        if unsupported:
            raise MachOError(f"unsupported Mach-O architecture slices: {', '.join(unsupported)}")
        return architectures

    def _uuids(self, path: Path) -> dict[str, str]:
        output = self.runner(["/usr/bin/dwarfdump", "--uuid", str(path)], 30)
        if output.returncode != 0:
            return {}
        uuids: dict[str, str] = {}
        for line in output.stdout.splitlines():
            match = re.match(r"UUID:\s+([0-9A-Fa-f-]+)\s+\(([^)]+)\)", line.strip())
            if match:
                uuids[match.group(2)] = match.group(1).upper()
        return uuids

    def _signature(self, path: Path) -> CodeSignature:
        verification = self.runner(
            [
                "/usr/bin/codesign",
                "--verify",
                "--all-architectures",
                "--strict=all",
                "--verbose=4",
                str(path),
            ],
            30,
        )
        display = self.runner(["/usr/bin/codesign", "-d", "--verbose=4", str(path)], 30)
        detail = "\n".join(part for part in (verification.stderr, display.stderr) if part)
        metadata = _parse_codesign_metadata(display.stderr)
        lowered = detail.lower()
        if "not signed at all" in lowered or "code object is not signed" in lowered:
            status = "unsigned"
        elif verification.returncode == 0:
            status = "valid"
        else:
            status = "invalid"
        cdhashes = tuple(
            value
            for key, value in metadata
            if key in {"CDHash", "CDHashes"}
            for value in value.split(",")
            if value
        )
        authorities = tuple(value for key, value in metadata if key == "Authority")
        return CodeSignature(
            status=status,
            valid=verification.returncode == 0,
            identifier=_first_metadata(metadata, "Identifier"),
            team_identifier=_none_if_unset(_first_metadata(metadata, "TeamIdentifier")),
            cdhashes=cdhashes,
            format=_first_metadata(metadata, "Format"),
            authorities=authorities,
            detail=detail[-4000:],
        )


def _digest_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_size = 0
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            digest.update(chunk)
            byte_size += len(chunk)
    return digest.hexdigest(), byte_size


def _parse_codesign_metadata(text: str) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        pairs.append((key.strip(), value.strip()))
    return tuple(pairs)


def _first_metadata(metadata: Sequence[tuple[str, str]], key: str) -> str | None:
    return next((value for candidate, value in metadata if candidate == key), None)


def _none_if_unset(value: str | None) -> str | None:
    if value is None or value.lower() in {"not set", "none", "n/a"}:
        return None
    return value


def _bounded_detail(output: CommandOutput) -> str:
    return f"{output.stdout}\n{output.stderr}".strip()[-2000:]
