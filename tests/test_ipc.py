import io
import json
import tempfile
import unittest
from pathlib import Path

from diffsearchvuln.codex_client import CodexTurnResult
from diffsearchvuln.ipc import PROTOCOL_VERSION, WorkerService, serve


def request(request_id: str, method: str, params: dict | None = None) -> dict:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "id": request_id,
        "method": method,
        "params": params or {},
    }


class FakeCatalog:
    def __init__(self) -> None:
        self.manifest = {"cache_key": "f" * 64}
        self.candidate_count = 2
        self.records = (
            {"candidate_id": "a" * 64, "primary_name": "first", "deterministic_rank": 1},
            {"candidate_id": "b" * 64, "primary_name": "second", "deterministic_rank": 2},
        )

    def page(self, *, offset: int, limit: int) -> tuple[dict, ...]:
        return self.records[offset : offset + limit]

    def compact_evidence(
        self,
        candidate_id: str,
        *,
        include_related: int,
        include_instructions: bool,
    ) -> dict:
        return {
            "candidate_id": candidate_id,
            "include_related": include_related,
            "include_instructions": include_instructions,
        }


class FakeCodexClient:
    def __init__(self) -> None:
        self.started = False
        self.closed = False

    def start(self) -> None:
        self.started = True

    def close(self) -> None:
        self.closed = True

    def run_isolated(self, prompt: str, **kwargs) -> CodexTurnResult:
        return CodexTurnResult(
            thread_id="thread",
            turn_id="turn",
            model=kwargs["model"],
            final_response={
                "verdict": "known_path_blocked",
                "summary": "The known parent-component path is blocked.",
                "attempted_hypothesis": "parent traversal",
                "exploit_chain": [],
                "test_cases": [],
                "bypass_candidates": [],
                "artifacts": [],
                "limitations": ["Target binary not executed"],
                "next_action": "Run in disposable VM",
            },
            duration_ms=10,
            token_usage=None,
            event_count=2,
        )


class IPCTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "state.sqlite3"
        self.catalog = FakeCatalog()
        self.catalog_loads = 0

        def load_catalog(_: str | Path) -> FakeCatalog:
            self.catalog_loads += 1
            return self.catalog

        self.service = WorkerService(catalog_loader=load_catalog)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_hello_reports_explicit_dynamic_guest_boundary(self) -> None:
        response = self.service.dispatch(request("hello", "system.hello"))
        self.assertEqual("hello", response["id"])
        self.assertEqual(PROTOCOL_VERSION, response["result"]["protocol_version"])
        self.assertEqual(
            "static_by_default_explicit_contained_dynamic",
            response["result"]["safety_mode"],
        )
        self.assertIn(
            "contained_host_dynamic_testing",
            response["result"]["capabilities"],
        )
        self.assertIn(
            "disposable_utm_dynamic_testing",
            response["result"]["capabilities"],
        )

    def test_protocol_mismatch_and_unknown_fields_fail_cleanly(self) -> None:
        wrong = request("wrong", "system.hello")
        wrong["protocol_version"] = "9.0.0"
        response = self.service.dispatch(wrong)
        self.assertEqual("protocol_mismatch", response["error"]["code"])
        extra = request("extra", "system.hello")
        extra["unexpected"] = True
        response = self.service.dispatch(extra)
        self.assertEqual("invalid_request", response["error"]["code"])

    def test_worker_continues_after_malformed_json(self) -> None:
        input_stream = io.StringIO(
            "not-json\n" + json.dumps(request("hello", "system.hello")) + "\n"
        )
        output_stream = io.StringIO()
        self.assertEqual(
            0,
            serve(input_stream, output_stream, service=self.service),
        )
        responses = [json.loads(line) for line in output_stream.getvalue().splitlines()]
        self.assertEqual("parse_error", responses[0]["error"]["code"])
        self.assertEqual("hello", responses[1]["id"])

    def test_create_and_list_local_products(self) -> None:
        create = self.service.dispatch(
            request(
                "create",
                "products.create",
                {
                    "database": str(self.database),
                    "name": "Example App",
                    "vendor": "Example Vendor",
                },
            )
        )
        self.assertEqual("Example App", create["result"]["product"]["name"])
        listed = self.service.dispatch(
            request("list", "products.list", {"database": str(self.database)})
        )
        self.assertEqual(1, listed["result"]["count"])
        self.assertEqual("Example App", listed["result"]["products"][0]["name"])

    def test_candidate_paging_and_evidence_are_structured(self) -> None:
        listed = self.service.dispatch(
            request(
                "candidates",
                "candidates.list",
                {"diff_directory": "/diff", "offset": 1, "limit": 1},
            )
        )
        self.assertEqual("second", listed["result"]["candidates"][0]["primary_name"])
        evidence = self.service.dispatch(
            request(
                "evidence",
                "candidate.evidence",
                {
                    "diff_directory": "/diff",
                    "candidate_id": "b" * 64,
                    "include_related": 2,
                    "include_instructions": True,
                },
            )
        )
        self.assertTrue(evidence["result"]["evidence"]["include_instructions"])
        self.assertEqual(2, evidence["result"]["evidence"]["include_related"])
        self.assertEqual(1, self.catalog_loads)

    def test_invalid_parameter_types_are_rejected(self) -> None:
        response = self.service.dispatch(
            request(
                "bad-limit",
                "candidates.list",
                {"diff_directory": "/diff", "limit": True},
            )
        )
        self.assertEqual("invalid_params", response["error"]["code"])

    def test_completed_tournament_is_validated_and_returned(self) -> None:
        run = Path(self.temporary.name) / "run"
        (run / "final-analysis").mkdir(parents=True)
        finalist_ids = ["a" * 64, "b" * 64]
        analysis = {
            "finding_state": "likely_patch",
            "selected_candidate_ids": finalist_ids,
            "confidence": 0.91,
            "vulnerable_behavior": "old behavior",
            "attacker_preconditions": ["controlled input"],
            "security_invariant": "validated input",
            "patch_explanation": "new validation",
            "observed_evidence": ["comparison"],
            "inferences": ["likely intent"],
            "bypass_hypotheses": ["alternate normalization"],
            "sibling_implementation_search": {
                "status": "partial",
                "searched_function_ids": finalist_ids,
                "same_function_call_sites": [
                    {
                        "function": "example.routeRequest",
                        "relationship": "direct caller of the patched validator",
                        "evidence": "The call edge targets the patched function.",
                        "risk": "uncertain",
                        "next_test": "Exercise the alternate route with malformed input.",
                    }
                ],
                "similar_implementations": [],
                "coverage_notes": ["The patched export was scanned."],
                "unresolved_gaps": ["One caller requires dynamic confirmation."],
            },
        }
        state = {
            "schema_version": "1.0.0",
            "run_key": "c" * 64,
            "status": "completed",
            "diff_cache_key": "d" * 64,
            "model": "test-model",
            "pool_ids": finalist_ids,
            "group_count": 3,
            "codex_call_count": 4,
            "reused_decision_count": 0,
            "finalist_ids": finalist_ids,
            "pass_finalists": finalist_ids,
            "started_at": "now",
            "completed_at": "later",
            "final_analysis": analysis,
        }
        (run / "state.json").write_text(json.dumps(state), encoding="utf-8")
        (run / "final-analysis/analysis.json").write_text(
            json.dumps(analysis), encoding="utf-8"
        )
        response = self.service.dispatch(
            request(
                "tournament",
                "tournament.inspect",
                {"run_directory": str(run)},
            )
        )
        result = response["result"]["run"]
        self.assertEqual("completed", result["status"])
        self.assertEqual(0.91, result["final_analysis"]["confidence"])
        self.assertEqual(
            "partial",
            result["final_analysis"]["sibling_implementation_search"]["status"],
        )
        self.assertEqual(finalist_ids, result["finalist_ids"])

    def test_codex_exploit_attempt_is_explicit_and_recoverable(self) -> None:
        run = Path(self.temporary.name) / "exploit-run"
        (run / "final-analysis").mkdir(parents=True)
        (run / "state.json").write_text(
            json.dumps({"model": "test-model", "finalist_ids": ["a" * 64]}),
            encoding="utf-8",
        )
        (run / "final-analysis/analysis.json").write_text(
            json.dumps({"finding_state": "likely_patch"}), encoding="utf-8"
        )
        (run / "final-analysis/prompt.txt").write_text(
            "old and new evidence", encoding="utf-8"
        )
        fake = FakeCodexClient()
        service = WorkerService(codex_factory=lambda: fake)
        response = service.dispatch(
            request(
                "exploit",
                "exploit.codex_attempt",
                {
                    "run_directory": str(run),
                    "attempt_id": "ui-attempt-ipc",
                    "analysis_context": {
                        "analysis_title": "fixture",
                        "selected_hypothesis": "parent traversal",
                    },
                },
            )
        )
        self.assertTrue(fake.started)
        self.assertTrue(fake.closed)
        self.assertEqual(
            "known_path_blocked",
            response["result"]["attempt"]["result"]["verdict"],
        )
        self.assertEqual(
            "ui-attempt-ipc", response["result"]["attempt"]["attempt_id"]
        )
        latest = service.dispatch(
            request("latest", "exploit.latest", {"run_directory": str(run)})
        )
        self.assertEqual(
            response["result"]["attempt"]["attempt_id"],
            latest["result"]["attempt"]["attempt_id"],
        )


if __name__ == "__main__":
    unittest.main()
