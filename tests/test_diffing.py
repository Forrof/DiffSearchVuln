import json
import tempfile
import unittest
from pathlib import Path

from diffsearchvuln.diffing import DiffSettings, SemanticDiffRunner, normalize_instruction
from diffsearchvuln.dossiers import CandidateCatalog


def function_record(
    artifact: str,
    address: str,
    instructions: list[str],
    *,
    callers: list[str] | None = None,
    callees: list[str] | None = None,
    strings: list[str] | None = None,
) -> dict:
    return {
        "schema_version": "1.0.0",
        "artifact_sha256": artifact,
        "architecture": "arm64",
        "ghidra_version": "12.1.2",
        "program_name": "sample",
        "language_id": "AARCH64:LE:64:AppleSilicon",
        "compiler_spec_id": "default",
        "function": {
            "address": address,
            "name": f"FUN_{address}",
            "qualified_name": f"FUN_{address}",
            "namespace": "Global",
            "body_size": len(instructions) * 4,
            "parameter_count": 0,
            "calling_convention": "default",
            "thunk": False,
            "external": False,
            "decompilation": "void function(void) {}",
            "instructions": instructions,
            "callers": callers or [],
            "callees": callees or [],
            "strings": strings or [],
            "imports": [],
        },
        "warnings": [],
    }


class SemanticDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_jsonl(self, name: str, values: list[dict]) -> Path:
        path = self.root / name
        path.write_text(
            "".join(json.dumps(value) + "\n" for value in values), encoding="utf-8"
        )
        return path

    def write_symbols(self, name: str, values: list[tuple[str, str]]) -> Path:
        path = self.root / name
        path.write_text(
            "".join(
                json.dumps({"address": address, "end": f"{int(address, 16) + 16:x}", "name": symbol})
                + "\n"
                for address, symbol in values
            ),
            encoding="utf-8",
        )
        return path

    def test_address_operands_are_normalized_but_small_constants_remain(self) -> None:
        self.assertEqual("bl <address>", normalize_instruction("1000|BL 0x101234567"))
        self.assertEqual("cmp x0,#0x2e", normalize_instruction("1004|cmp x0,#0x2e"))

    def test_matches_named_functions_and_clusters_added_callee(self) -> None:
        old = self.write_jsonl(
            "old.jsonl",
            [
                function_record(
                    "a" * 64,
                    "1000",
                    ["1000|cmp x0,#0x1", "1004|b.eq 0x10000000", "1008|ret"],
                ),
                function_record("a" * 64, "1100", ["1100|mov x0,x1", "1104|ret"]),
            ],
        )
        new = self.write_jsonl(
            "new.jsonl",
            [
                function_record(
                    "b" * 64,
                    "2000",
                    [
                        "2000|cmp x0,#0x2",
                        "2004|b.eq 0x20000000",
                        "2008|bl 0x2100",
                        "200c|ret",
                    ],
                    callees=["FUN_2100@2100"],
                ),
                function_record(
                    "b" * 64,
                    "2100",
                    ["2100|cmp x1,#0x2e", "2104|b.eq 0x210c", "2108|ret"],
                    callers=["FUN_2000@2000"],
                ),
                function_record("b" * 64, "2200", ["2200|mov x0,x1", "2204|ret"]),
            ],
        )
        old_symbols = self.write_symbols(
            "old-symbols.jsonl",
            [("1000", "example/archive.ArchiveExtract"), ("1100", "example.unchanged")],
        )
        new_symbols = self.write_symbols(
            "new-symbols.jsonl",
            [
                ("2000", "example/archive.ArchiveExtract"),
                ("2100", "example/archive.destPath"),
                ("2200", "example.unchanged"),
            ],
        )
        runner = SemanticDiffRunner(output_root=self.root / "diffs")
        result = runner.diff(
            old,
            new,
            old_symbols=old_symbols,
            new_symbols=new_symbols,
            advisory_text="archive path traversal",
            settings=DiffSettings(tournament_pool_size=10),
        )
        records = [
            json.loads(line)
            for line in Path(result.candidate_path).read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(2, result.candidate_count)
        self.assertEqual(
            {"example/archive.ArchiveExtract", "example/archive.destPath"},
            {record["primary_name"] for record in records[:2]},
        )
        by_name = {record["primary_name"]: record for record in records}
        self.assertEqual("modified", by_name["example/archive.ArchiveExtract"]["match_kind"])
        self.assertEqual("added", by_name["example/archive.destPath"]["match_kind"])
        self.assertEqual(
            "example/archive.destPath",
            by_name["example/archive.ArchiveExtract"]["cluster_members"][0]["name"],
        )
        self.assertEqual(1, result.unchanged_count)
        self.assertFalse(result.cached)
        catalog = CandidateCatalog.load(result.cache_path)
        self.assertEqual(2, catalog.candidate_count)
        self.assertEqual(2, catalog.page(offset=1, limit=1)[0]["deterministic_rank"])
        cached = runner.diff(
            old,
            new,
            old_symbols=old_symbols,
            new_symbols=new_symbols,
            advisory_text="archive path traversal",
            settings=DiffSettings(tournament_pool_size=10),
        )
        self.assertTrue(cached.cached)


if __name__ == "__main__":
    unittest.main()
