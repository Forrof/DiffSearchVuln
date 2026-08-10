import sqlite3
import tempfile
import unittest
from pathlib import Path

from diffsearchvuln.models import AnalysisMode
from diffsearchvuln.storage import DATABASE_SCHEMA_VERSION, Storage


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.path = Path(self.temp_dir.name) / "database.sqlite3"
        self.storage = Storage(self.path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_initialize_is_idempotent_and_records_version(self) -> None:
        self.storage.initialize()
        self.storage.initialize()
        self.assertEqual(DATABASE_SCHEMA_VERSION, self.storage.schema_version())

    def test_rejects_database_from_a_newer_application(self) -> None:
        with self.storage.connect() as connection:
            connection.execute(
                "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO schema_meta(key, value) VALUES('schema_version', '999')"
            )
        with self.assertRaisesRegex(RuntimeError, "newer than supported"):
            self.storage.initialize()

    def test_foreign_keys_reject_unknown_product(self) -> None:
        self.storage.initialize()
        with self.assertRaises(sqlite3.IntegrityError):
            self.storage.create_analysis_job(
                mode=AnalysisMode.ADVISORY_GUIDED,
                product_id="missing",
                advisory={"id": "CVE-test"},
            )

    def test_create_and_list_product(self) -> None:
        self.storage.initialize()
        product_id = self.storage.create_product("Example", "Vendor")
        self.assertEqual(
            [{"id": product_id, "name": "Example", "vendor": "Vendor", "created_at": self.storage.list_products()[0]["created_at"]}],
            self.storage.list_products(),
        )

    def test_report_instructions_are_per_job(self) -> None:
        self.storage.initialize()
        job_id = self.storage.create_analysis_job(
            mode=AnalysisMode.BLIND_DISCOVERY,
            report_instructions="Use this case-specific format",
        )
        with self.storage.connect() as connection:
            row = connection.execute(
                "SELECT report_instructions FROM analysis_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        self.assertEqual("Use this case-specific format", row["report_instructions"])

    def test_manual_artifact_pair_can_be_linked_directly(self) -> None:
        self.storage.initialize()
        old_hash = "a" * 64
        new_hash = "b" * 64
        with self.storage.connect() as connection:
            for digest, path in ((old_hash, "/vault/old"), (new_hash, "/vault/new")):
                connection.execute(
                    """
                    INSERT INTO artifacts(
                        sha256, storage_path, byte_size, media_type, created_at
                    ) VALUES(?, ?, 1, 'application/x-mach-binary', 'now')
                    """,
                    (digest, path),
                )
        job_id = self.storage.create_analysis_job(
            mode=AnalysisMode.ADVISORY_GUIDED,
            old_artifact_sha256=old_hash,
            new_artifact_sha256=new_hash,
            advisory={"id": "CVE-test"},
        )
        with self.storage.connect() as connection:
            row = connection.execute(
                """
                SELECT old_artifact_sha256, new_artifact_sha256
                FROM analysis_jobs WHERE id = ?
                """,
                (job_id,),
            ).fetchone()
        self.assertEqual(old_hash, row["old_artifact_sha256"])
        self.assertEqual(new_hash, row["new_artifact_sha256"])

    def test_artifact_identity_cannot_be_rebound(self) -> None:
        self.storage.initialize()
        digest = "a" * 64
        arguments = {
            "sha256": digest,
            "storage_path": "/vault/original",
            "byte_size": 42,
            "media_type": "application/x-mach-binary",
            "signature": {"status": "unsigned"},
            "provenance": {"source": "test"},
        }
        self.storage.record_artifact(**arguments)
        self.storage.record_artifact(**arguments)
        with self.assertRaisesRegex(ValueError, "immutable"):
            self.storage.record_artifact(**{**arguments, "storage_path": "/other"})

    def test_artifact_parent_can_be_added_once_but_not_rebound(self) -> None:
        self.storage.initialize()
        parent_one = "b" * 64
        parent_two = "c" * 64
        child = "d" * 64
        base = {
            "byte_size": 1,
            "media_type": "application/octet-stream",
            "signature": {},
            "provenance": {},
        }
        self.storage.record_artifact(
            sha256=parent_one, storage_path="/vault/parent-one", **base
        )
        self.storage.record_artifact(
            sha256=parent_two, storage_path="/vault/parent-two", **base
        )
        self.storage.record_artifact(sha256=child, storage_path="/vault/child", **base)
        self.storage.record_artifact(
            sha256=child,
            storage_path="/vault/child",
            parent_sha256=parent_one,
            **base,
        )
        self.assertEqual(parent_one, self.storage.get_artifact(child)["parent_sha256"])
        with self.assertRaisesRegex(ValueError, "different immutable parent"):
            self.storage.record_artifact(
                sha256=child,
                storage_path="/vault/child",
                parent_sha256=parent_two,
                **base,
            )


if __name__ == "__main__":
    unittest.main()
