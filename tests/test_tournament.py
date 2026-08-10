import json
import tempfile
import unittest
from pathlib import Path

from diffsearchvuln.codex_client import CodexTurnResult
from diffsearchvuln.diffing import DiffSettings, SemanticDiffRunner
from diffsearchvuln.tournament import TournamentRunner, TournamentSettings, make_groups


def export_record(artifact: str, address: str, value: int) -> dict:
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
            "body_size": 8,
            "parameter_count": 0,
            "calling_convention": "default",
            "thunk": False,
            "external": False,
            "decompilation": f"int candidate(void) {{ return {value}; }}",
            "instructions": [f"{address}|mov x0,#0x{value:x}", f"{int(address, 16) + 4:x}|ret"],
            "callers": [],
            "callees": [],
            "strings": [],
            "imports": [],
        },
        "warnings": [],
    }


class FakeCodex:
    def __init__(self) -> None:
        self.calls = 0

    def default_model(self) -> str:
        return "test-model"

    def run_isolated(self, prompt: str, *, output_schema: dict, **kwargs) -> CodexTurnResult:
        del kwargs
        self.calls += 1
        marker = (
            "UNTRUSTED_FINALIST_EVIDENCE_JSON:\n"
            if "finding_state" in output_schema["properties"]
            else "UNTRUSTED_BINARY_EVIDENCE_JSON:\n"
        )
        dossiers = json.loads(prompt.split(marker, 1)[1])
        ordered = sorted(
            dossiers,
            key=lambda dossier: dossier["candidate"]["deterministic_rank"],
        )
        ids = [dossier["candidate"]["candidate_id"] for dossier in ordered]
        if "finding_state" in output_schema["properties"]:
            response = {
                "finding_state": "likely_patch",
                "selected_candidate_ids": ids[:2],
                "confidence": 0.9,
                "vulnerable_behavior": "old behavior",
                "attacker_preconditions": ["input"],
                "security_invariant": "validated path",
                "patch_explanation": "new check",
                "observed_evidence": ["comparison"],
                "inferences": ["likely"],
                "bypass_hypotheses": ["alternate separator"],
            }
        else:
            response = {
                "no_strong_candidate": False,
                "ranking": [
                    {
                        "cluster_id": candidate_id,
                        "rank": rank,
                        "absolute_score": max(0.1, 1.0 - rank / 10),
                        "explanation": "deterministic fake judgment",
                    }
                    for rank, candidate_id in enumerate(ids, start=1)
                ],
            }
        return CodexTurnResult(
            thread_id=f"thread-{self.calls}",
            turn_id=f"turn-{self.calls}",
            model="test-model",
            final_response=response,
            duration_ms=1,
            token_usage=None,
            event_count=1,
        )


class TournamentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_jsonl(self, path: Path, values: list[dict]) -> None:
        path.write_text(
            "".join(json.dumps(value) + "\n" for value in values), encoding="utf-8"
        )

    def test_grouping_never_leaves_a_single_candidate(self) -> None:
        self.assertEqual([3, 3], [len(group) for group in make_groups(list("abcdef"), seed=1, round_index=0)])
        self.assertEqual(
            [4, 4, 3],
            [len(group) for group in make_groups(list("abcdefghijk"), seed=1, round_index=0)],
        )

    def test_two_pass_tournament_is_resumable_and_keeps_two_finalists(self) -> None:
        old_export = self.root / "old.jsonl"
        new_export = self.root / "new.jsonl"
        old_symbols = self.root / "old-symbols.jsonl"
        new_symbols = self.root / "new-symbols.jsonl"
        old_records = []
        new_records = []
        old_symbol_records = []
        new_symbol_records = []
        for index in range(10):
            old_address = f"{0x1000 + index * 0x20:x}"
            new_address = f"{0x2000 + index * 0x20:x}"
            old_records.append(export_record("a" * 64, old_address, index + 1))
            new_records.append(export_record("b" * 64, new_address, index + 20))
            name = f"example.securityCandidate{index}"
            old_symbol_records.append(
                {"address": old_address, "end": f"{int(old_address, 16) + 8:x}", "name": name}
            )
            new_symbol_records.append(
                {"address": new_address, "end": f"{int(new_address, 16) + 8:x}", "name": name}
            )
        self.write_jsonl(old_export, old_records)
        self.write_jsonl(new_export, new_records)
        self.write_jsonl(old_symbols, old_symbol_records)
        self.write_jsonl(new_symbols, new_symbol_records)
        diff = SemanticDiffRunner(output_root=self.root / "diffs").diff(
            old_export,
            new_export,
            old_symbols=old_symbols,
            new_symbols=new_symbols,
            advisory_text="security path validation",
            settings=DiffSettings(tournament_pool_size=10),
        )
        fake = FakeCodex()
        runner = TournamentRunner(output_root=self.root / "tournaments", codex=fake)
        settings = TournamentSettings(pool_limit=10, model="test-model")
        first = runner.run(
            diff.cache_path,
            advisory_text="security path validation",
            settings=settings,
        )
        self.assertEqual(2, len(first.finalist_ids))
        self.assertEqual(8, first.codex_call_count)
        self.assertFalse(first.cached)
        self.assertEqual(8, fake.calls)
        analysis = json.loads(Path(first.final_analysis_path).read_text(encoding="utf-8"))
        self.assertEqual("likely_patch", analysis["finding_state"])
        second = runner.run(
            diff.cache_path,
            advisory_text="security path validation",
            settings=settings,
        )
        self.assertEqual(first.finalist_ids, second.finalist_ids)
        self.assertTrue(second.cached)
        self.assertEqual(8, fake.calls)


if __name__ == "__main__":
    unittest.main()
