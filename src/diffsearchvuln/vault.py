from __future__ import annotations

import errno
import hashlib
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from uuid import uuid4


CHUNK_SIZE = 1024 * 1024


class VaultError(RuntimeError):
    pass


@dataclass(frozen=True)
class VaultArtifact:
    sha256: str
    byte_size: int
    storage_path: str

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


class ArtifactVault:
    """Content-addressed storage that never executes or overwrites imported data."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.objects = self.root / "objects" / "sha256"
        self.incoming = self.root / ".incoming"

    def object_path(self, sha256: str) -> Path:
        _validate_sha256(sha256)
        return self.objects / sha256[:2] / sha256

    def import_file(self, source: str | Path) -> VaultArtifact:
        source_path = Path(source).expanduser()
        self.incoming.mkdir(parents=True, exist_ok=True)
        temporary = self.incoming / f"{uuid4()}.partial"
        digest = hashlib.sha256()
        byte_size = 0
        source_fd: int | None = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            source_fd = os.open(source_path, flags)
            source_stat = os.fstat(source_fd)
            if not stat.S_ISREG(source_stat.st_mode):
                raise VaultError(f"artifact is not a regular file: {source_path}")
            with os.fdopen(source_fd, "rb", closefd=True) as source_file:
                source_fd = None
                with temporary.open("xb") as destination:
                    while chunk := source_file.read(CHUNK_SIZE):
                        destination.write(chunk)
                        digest.update(chunk)
                        byte_size += len(chunk)
                    destination.flush()
                    os.fsync(destination.fileno())

            sha256 = digest.hexdigest()
            final_path = self.object_path(sha256)
            final_path.parent.mkdir(parents=True, exist_ok=True)
            temporary.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            try:
                os.link(temporary, final_path)
            except OSError as error:
                if error.errno != errno.EEXIST:
                    raise
                self._verify_existing(final_path, sha256, byte_size)
            else:
                self._fsync_directory(final_path.parent)
            return VaultArtifact(sha256, byte_size, str(final_path))
        except FileNotFoundError as error:
            raise VaultError(f"artifact does not exist: {source_path}") from error
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise VaultError(f"symbolic links are not accepted as artifacts: {source_path}") from error
            raise
        finally:
            if source_fd is not None:
                os.close(source_fd)
            temporary.unlink(missing_ok=True)

    def verify(self, sha256: str) -> VaultArtifact:
        path = self.object_path(sha256)
        if not path.is_file():
            raise VaultError(f"artifact is missing from the vault: {sha256}")
        byte_size = path.stat().st_size
        self._verify_existing(path, sha256, byte_size)
        return VaultArtifact(sha256, byte_size, str(path))

    @staticmethod
    def _verify_existing(path: Path, expected_sha256: str, expected_size: int) -> None:
        actual_size = path.stat().st_size
        if actual_size != expected_size:
            raise VaultError(
                f"vault object size mismatch for {expected_sha256}: "
                f"expected {expected_size}, found {actual_size}"
            )
        actual_digest = hashlib.sha256()
        with path.open("rb") as stored:
            while chunk := stored.read(CHUNK_SIZE):
                actual_digest.update(chunk)
        if actual_digest.hexdigest() != expected_sha256:
            raise VaultError(f"vault object digest mismatch for {expected_sha256}")

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _validate_sha256(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
