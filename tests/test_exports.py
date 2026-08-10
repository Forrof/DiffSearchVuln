import json
import tempfile
import unittest
from pathlib import Path

from diffsearchvuln.exports import ExportValidationError, validate_function_export


def record(address: str = "1000") -> dict:
    return {
        "schema_version": "1.0.0",
        "artifact_sha256": "a" * 64,
        "architecture": "arm64",
        "ghidra_version": "12.1.2",
        "program_name": "sample",
        "language_id": "AARCH64:LE:64:AppleSilicon",
        "compiler_spec_id": "default",
        "function": {
            "address": address,
            "name": "function",
            "qualified_name": "function",
            "namespace": "Global",
            "body_size": 4,
            "parameter_count": 0,
            "calling_convention": "default",
            "thunk": False,
            "external": False,
            "decompilation": "void function(void) {}",
            "instructions": ["1000|ret"],
            "callers": [],
            "callees": [],
            "strings": [],
            "imports": [],
        },
        "warnings": [],
    }


class ExportValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "functions.jsonl"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, *records: dict) -> None:
        self.path.write_text(
            "".join(json.dumps(value) + "\n" for value in records), encoding="utf-8"
        )

    def test_streams_valid_export_statistics(self) -> None:
        self.write(record("1000"), record("2000"))
        statistics = validate_function_export(
            self.path,
            expected_artifact_sha256="a" * 64,
            expected_architecture="arm64",
        )
        self.assertEqual(2, statistics.function_count)
        self.assertEqual(2, statistics.decompilation_successes)
        self.assertEqual(2, statistics.instruction_count)

    def test_rejects_duplicate_function_addresses(self) -> None:
        self.write(record("1000"), record("1000"))
        with self.assertRaisesRegex(ExportValidationError, "repeats"):
            validate_function_export(self.path)

    def test_rejects_architecture_language_mismatch(self) -> None:
        value = record()
        value["language_id"] = "x86:LE:64:default"
        self.write(value)
        with self.assertRaisesRegex(ExportValidationError, "labels arm64"):
            validate_function_export(self.path, expected_architecture="arm64")


if __name__ == "__main__":
    unittest.main()
