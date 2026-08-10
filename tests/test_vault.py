import os
import stat
import tempfile
import unittest
from pathlib import Path

from diffsearchvuln.vault import ArtifactVault, VaultError


class ArtifactVaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.vault = ArtifactVault(self.root / "vault")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_import_is_content_addressed_and_idempotent(self) -> None:
        source = self.root / "sample.bin"
        source.write_bytes(b"immutable bytes")
        first = self.vault.import_file(source)
        second = self.vault.import_file(source)
        self.assertEqual(first, second)
        stored = Path(first.storage_path)
        self.assertEqual(b"immutable bytes", stored.read_bytes())
        self.assertEqual(0, stored.stat().st_mode & stat.S_IWUSR)

    def test_rejects_symlink_source(self) -> None:
        source = self.root / "sample.bin"
        source.write_bytes(b"target")
        symlink = self.root / "link.bin"
        os.symlink(source, symlink)
        with self.assertRaisesRegex(VaultError, "symbolic links"):
            self.vault.import_file(symlink)

    def test_detects_corrupted_existing_object(self) -> None:
        source = self.root / "sample.bin"
        source.write_bytes(b"original")
        record = self.vault.import_file(source)
        stored = Path(record.storage_path)
        stored.chmod(stat.S_IRUSR | stat.S_IWUSR)
        stored.write_bytes(b"tampered")
        with self.assertRaisesRegex(VaultError, "mismatch"):
            self.vault.verify(record.sha256)


if __name__ == "__main__":
    unittest.main()
