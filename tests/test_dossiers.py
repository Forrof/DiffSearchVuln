import json
import tempfile
import unittest
from pathlib import Path

from diffsearchvuln.diffing import DiffSettings, SemanticDiffRunner
from diffsearchvuln.dossiers import CandidateCatalog


def export_record(
    artifact: str,
    address: str,
    name: str,
    decompilation: str,
    *,
    callers: list[str] | None = None,
    callees: list[str] | None = None,
    strings: list[str] | None = None,
    imports: list[str] | None = None,
) -> dict:
    return {
        "schema_version": "1.0.0",
        "artifact_sha256": artifact,
        "architecture": "arm64",
        "ghidra_version": "12.1.2",
        "program_name": "sibling-fixture",
        "language_id": "AARCH64:LE:64:AppleSilicon",
        "compiler_spec_id": "default",
        "function": {
            "address": address,
            "name": name,
            "qualified_name": f"example.{name}",
            "namespace": "example",
            "body_size": 16,
            "parameter_count": 1,
            "calling_convention": "default",
            "thunk": False,
            "external": False,
            "decompilation": decompilation,
            "instructions": [f"{address}|ret"],
            "callers": callers or [],
            "callees": callees or [],
            "strings": strings or [],
            "imports": imports or [],
        },
        "warnings": [],
    }


class SiblingSearchTests(unittest.TestCase):
    def test_whole_export_scan_finds_direct_callers_and_similar_implementations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_export = root / "old.jsonl"
            new_export = root / "new.jsonl"
            old_symbols = root / "old-symbols.jsonl"
            new_symbols = root / "new-symbols.jsonl"
            old_records = [
                export_record("a" * 64, "1000", "patchTarget", "return process(input);"),
                export_record(
                    "a" * 64,
                    "1100",
                    "directCaller",
                    "return patchTarget(input);",
                    callees=["patchTarget@1000"],
                ),
                export_record(
                    "a" * 64,
                    "1200",
                    "similarHandler",
                    "return normalize(input);",
                    callees=["validatePath@1400"],
                    strings=["invalid path"],
                    imports=["normalize_path"],
                ),
                export_record("a" * 64, "1300", "unrelated", "return 7;"),
                export_record("a" * 64, "1400", "validatePath", "return input != 0;"),
            ]
            new_records = [
                export_record(
                    "b" * 64,
                    "2000",
                    "patchTarget",
                    "if (!validatePath(input)) return -1; return process(input);",
                    callers=["directCaller@2100"],
                    callees=["validatePath@2400"],
                    strings=["invalid path"],
                    imports=["normalize_path"],
                ),
                export_record(
                    "b" * 64,
                    "2100",
                    "directCaller",
                    "return patchTarget(input);",
                    callees=["patchTarget@2000"],
                ),
                export_record(
                    "b" * 64,
                    "2200",
                    "similarHandler",
                    "return normalize(input);",
                    callees=["validatePath@2400"],
                    strings=["invalid path"],
                    imports=["normalize_path"],
                ),
                export_record("b" * 64, "2300", "unrelated", "return 7;"),
                export_record("b" * 64, "2400", "validatePath", "return input != 0;"),
            ]
            old_export.write_text(
                "".join(json.dumps(record) + "\n" for record in old_records),
                encoding="utf-8",
            )
            new_export.write_text(
                "".join(json.dumps(record) + "\n" for record in new_records),
                encoding="utf-8",
            )
            old_symbols.write_text(
                "".join(
                    json.dumps(
                        {
                            "address": record["function"]["address"],
                            "end": f"{int(record['function']['address'], 16) + 16:x}",
                            "name": record["function"]["qualified_name"],
                        }
                    )
                    + "\n"
                    for record in old_records
                ),
                encoding="utf-8",
            )
            new_symbols.write_text(
                "".join(
                    json.dumps(
                        {
                            "address": record["function"]["address"],
                            "end": f"{int(record['function']['address'], 16) + 16:x}",
                            "name": record["function"]["qualified_name"],
                        }
                    )
                    + "\n"
                    for record in new_records
                ),
                encoding="utf-8",
            )
            diff = SemanticDiffRunner(output_root=root / "diffs").diff(
                old_export,
                new_export,
                old_symbols=old_symbols,
                new_symbols=new_symbols,
                advisory_text="path validation patch",
                settings=DiffSettings(tournament_pool_size=10),
            )
            catalog = CandidateCatalog.load(diff.cache_path)
            patch_candidate = next(
                candidate
                for candidate in catalog.page(limit=50)
                if candidate["primary_name"] == "example.patchTarget"
            )

            evidence = catalog.sibling_search_evidence((patch_candidate["candidate_id"],))

            self.assertEqual(5, evidence["coverage"]["functions_scanned"])
            self.assertEqual(
                "example.directCaller",
                evidence["same_function_call_sites"][0]["function"]["qualified_name"],
            )
            similar_names = {
                item["function"]["qualified_name"]
                for item in evidence["similar_implementations"]
            }
            self.assertIn("example.similarHandler", similar_names)
            self.assertNotIn("example.unrelated", similar_names)
            self.assertTrue(
                all(
                    item["evidence_label"] == "OBSERVED"
                    for item in evidence["same_function_call_sites"]
                    + evidence["similar_implementations"]
                )
            )


if __name__ == "__main__":
    unittest.main()
