from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Sequence
from uuid import uuid4

from .macho import _digest_file


class SymbolError(RuntimeError):
    pass


@dataclass(frozen=True)
class GoSymbolExport:
    cache_key: str
    cache_path: str
    symbol_path: str
    symbol_sha256: str
    symbol_count: int
    artifact_sha256: str
    go_version: str
    cached: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


Executor = Callable[[Sequence[str], Path, Path, int], int]


def _default_executor(
    command: Sequence[str], stdout_path: Path, stderr_path: Path, timeout: int
) -> int:
    with (
        stdout_path.open("wb") as stdout,
        stderr_path.open("wb") as stderr,
    ):
        try:
            completed = subprocess.run(
                list(command),
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
                check=False,
            )
            return completed.returncode
        except subprocess.TimeoutExpired:
            stderr.write(f"process timeout after {timeout} seconds\n".encode("utf-8"))
            return 124


class GoSymbolExtractor:
    """Recover Go pclntab names without loading or executing the target."""

    def __init__(
        self,
        *,
        cache_root: str | Path,
        go_binary: str | Path = "/opt/homebrew/bin/go",
        source_path: str | Path | None = None,
        executor: Executor = _default_executor,
    ) -> None:
        self.cache_root = Path(cache_root).expanduser().resolve()
        self.go_binary = Path(go_binary).expanduser().resolve()
        self.source_path = (
            Path(source_path).expanduser().resolve()
            if source_path
            else Path(__file__).resolve().parents[2] / "tools/go-symbols/main.go"
        )
        self.executor = executor

    def extract(
        self,
        artifact_path: str | Path,
        *,
        artifact_sha256: str,
        timeout_seconds: int = 300,
    ) -> GoSymbolExport:
        artifact = Path(artifact_path).expanduser().resolve()
        if timeout_seconds < 1:
            raise ValueError("symbol extraction timeout must be positive")
        self._validate_environment(artifact, artifact_sha256)
        go_version = self._go_version()
        source_sha256, _ = _digest_file(self.source_path)
        cache_key = self._cache_key(artifact_sha256, source_sha256, go_version)
        completed = self.cache_root / "completed" / cache_key
        cached = self._load_cached(completed)
        if cached is not None:
            return cached

        tools_root = self.cache_root / "tools"
        staging_root = self.cache_root / "staging"
        failed_root = self.cache_root / "failed"
        locks_root = self.cache_root / ".locks"
        for directory in (completed.parent, tools_root, staging_root, failed_root, locks_root):
            directory.mkdir(parents=True, exist_ok=True)

        helper = self._build_helper(
            tools_root,
            source_sha256=source_sha256,
            go_version=go_version,
            timeout_seconds=timeout_seconds,
        )
        lock = locks_root / f"{cache_key}.lock"
        descriptor: int | None = None
        staging: Path | None = None
        try:
            try:
                descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError as error:
                raise SymbolError(f"symbol extraction is already running for {cache_key}") from error
            os.write(descriptor, str(os.getpid()).encode("ascii"))

            staging = staging_root / f"{cache_key}-{uuid4()}"
            staging.mkdir()
            symbols = staging / "symbols.jsonl"
            log = staging / "extract.log"
            started_at = datetime.now(UTC).isoformat()
            return_code = self.executor(
                [str(helper), str(artifact)], symbols, log, timeout_seconds
            )
            if return_code != 0:
                self._preserve_failure(staging, failed_root, cache_key, return_code)
                detail = log.read_text(encoding="utf-8", errors="replace")[-2000:]
                raise SymbolError(
                    f"Go symbol extraction failed with exit code {return_code}: {detail}"
                )
            symbol_count = _validate_symbols(symbols)
            if symbol_count == 0:
                self._preserve_failure(staging, failed_root, cache_key, return_code)
                raise SymbolError("Go pclntab contained no functions")
            symbol_sha256, _ = _digest_file(symbols)
            manifest = {
                "schema_version": "1.0.0",
                "status": "completed",
                "cache_key": cache_key,
                "artifact_sha256": artifact_sha256,
                "go_version": go_version,
                "source_sha256": source_sha256,
                "symbol_count": symbol_count,
                "symbol_sha256": symbol_sha256,
                "started_at": started_at,
                "completed_at": datetime.now(UTC).isoformat(),
            }
            _write_json(staging / "manifest.json", manifest)
            try:
                os.rename(staging, completed)
            except FileExistsError:
                shutil.rmtree(staging)
                cached_result = self._load_cached(completed)
                if cached_result is None:
                    raise SymbolError(f"invalid concurrent symbol cache for {cache_key}")
                return cached_result
            return self._result(completed, manifest, cached=False)
        except Exception:
            if staging is not None and staging.exists():
                self._preserve_failure(staging, failed_root, cache_key, -1)
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)
            lock.unlink(missing_ok=True)

    def _validate_environment(self, artifact: Path, artifact_sha256: str) -> None:
        if not artifact.is_file():
            raise SymbolError(f"artifact does not exist: {artifact}")
        actual_sha256, _ = _digest_file(artifact)
        if actual_sha256 != artifact_sha256:
            raise SymbolError("artifact digest does not match the requested symbol identity")
        missing = [
            str(path)
            for path in (self.go_binary, self.source_path)
            if not path.is_file()
        ]
        if missing:
            raise SymbolError(f"missing Go symbol dependency: {', '.join(missing)}")

    def _go_version(self) -> str:
        completed = subprocess.run(
            [str(self.go_binary), "version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            raise SymbolError(f"could not determine Go version: {completed.stderr.strip()}")
        return completed.stdout.strip()

    def _build_helper(
        self,
        tools_root: Path,
        *,
        source_sha256: str,
        go_version: str,
        timeout_seconds: int,
    ) -> Path:
        tool_key = hashlib.sha256(
            f"{source_sha256}\0{go_version}".encode("utf-8")
        ).hexdigest()
        directory = tools_root / tool_key
        helper = directory / "go-symbols"
        if helper.is_file():
            return helper
        directory.mkdir(parents=True, exist_ok=True)
        temporary = directory / f"go-symbols-{uuid4()}.partial"
        build_log = directory / "build.log"
        return_code = self.executor(
            [
                str(self.go_binary),
                "build",
                "-trimpath",
                "-o",
                str(temporary),
                str(self.source_path),
            ],
            build_log,
            build_log.with_suffix(".error.log"),
            timeout_seconds,
        )
        if return_code != 0 or not temporary.is_file():
            temporary.unlink(missing_ok=True)
            raise SymbolError(f"could not build Go symbol helper; see {build_log}")
        temporary.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        try:
            os.link(temporary, helper)
        except FileExistsError:
            pass
        finally:
            temporary.unlink(missing_ok=True)
        return helper

    def _load_cached(self, directory: Path) -> GoSymbolExport | None:
        manifest_path = directory / "manifest.json"
        symbol_path = directory / "symbols.jsonl"
        if not manifest_path.is_file() or not symbol_path.is_file():
            return None
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            symbol_sha256, _ = _digest_file(symbol_path)
            if manifest.get("status") != "completed":
                return None
            if symbol_sha256 != manifest.get("symbol_sha256"):
                return None
            if _validate_symbols(symbol_path) != manifest.get("symbol_count"):
                return None
            return self._result(directory, manifest, cached=True)
        except (OSError, ValueError, json.JSONDecodeError, SymbolError):
            return None

    @staticmethod
    def _result(
        directory: Path, manifest: dict[str, object], *, cached: bool
    ) -> GoSymbolExport:
        return GoSymbolExport(
            cache_key=str(manifest["cache_key"]),
            cache_path=str(directory),
            symbol_path=str(directory / "symbols.jsonl"),
            symbol_sha256=str(manifest["symbol_sha256"]),
            symbol_count=int(manifest["symbol_count"]),
            artifact_sha256=str(manifest["artifact_sha256"]),
            go_version=str(manifest["go_version"]),
            cached=cached,
        )

    @staticmethod
    def _cache_key(artifact_sha256: str, source_sha256: str, go_version: str) -> str:
        payload = json.dumps(
            {
                "artifact_sha256": artifact_sha256,
                "source_sha256": source_sha256,
                "go_version": go_version,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _preserve_failure(
        staging: Path, failed_root: Path, cache_key: str, return_code: int
    ) -> None:
        _write_json(
            staging / "failure.json",
            {
                "schema_version": "1.0.0",
                "status": "failed",
                "cache_key": cache_key,
                "return_code": return_code,
                "failed_at": datetime.now(UTC).isoformat(),
            },
        )
        os.rename(staging, failed_root / f"{cache_key}-{uuid4()}")


def load_symbol_map(path: str | Path) -> dict[str, str]:
    symbol_path = Path(path).expanduser().resolve()
    _validate_symbols(symbol_path)
    result: dict[str, str] = {}
    with symbol_path.open("r", encoding="utf-8") as records:
        for line in records:
            if not line.strip():
                continue
            record = json.loads(line)
            result[record["address"].lower().removeprefix("0x")] = record["name"]
    return result


def _validate_symbols(path: Path) -> int:
    if not path.is_file():
        raise SymbolError(f"symbol export does not exist: {path}")
    count = 0
    seen: set[str] = set()
    prior_address = -1
    with path.open("r", encoding="utf-8") as records:
        for line_number, line in enumerate(records, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                address_text = record["address"].lower().removeprefix("0x")
                end_text = record["end"].lower().removeprefix("0x")
                name = record["name"]
                address = int(address_text, 16)
                end = int(end_text, 16)
            except (json.JSONDecodeError, KeyError, AttributeError, TypeError, ValueError) as error:
                raise SymbolError(f"invalid symbol record on line {line_number}") from error
            if not name or address_text in seen or end <= address or address < prior_address:
                raise SymbolError(f"invalid symbol ordering or identity on line {line_number}")
            seen.add(address_text)
            prior_address = address
            count += 1
    return count


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
