#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from diffsearchvuln.codex_client import CodexAppServerClient
from diffsearchvuln.dossiers import CandidateCatalog


SUPPLEMENTAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "candidate_assessments": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "string"},
                    "candidate_name": {"type": "string"},
                    "relevance": {
                        "type": "string",
                        "enum": [
                            "direct_patch_logic",
                            "supporting_call_flow",
                            "security_adjacent",
                            "unrelated_noise",
                        ],
                    },
                    "confidence": {"type": "number"},
                    "observed_changes": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "security_interpretation": {"type": "string"},
                    "relation_to_primary_patch": {"type": "string"},
                    "independently_vulnerable": {"type": "boolean"},
                    "limitations": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "candidate_id",
                    "candidate_name",
                    "relevance",
                    "confidence",
                    "observed_changes",
                    "security_interpretation",
                    "relation_to_primary_patch",
                    "independently_vulnerable",
                    "limitations",
                ],
                "additionalProperties": False,
            },
        },
        "strongest_supplemental_candidate_id": {"type": "string"},
        "effect_on_original_conclusion": {
            "type": "string",
            "enum": ["strengthens", "unchanged", "weakens"],
        },
        "overall_conclusion": {"type": "string"},
        "new_bypass_insights": {
            "type": "array",
            "items": {"type": "string"},
        },
        "recommended_follow_up": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": [
        "candidate_assessments",
        "strongest_supplemental_candidate_id",
        "effect_on_original_conclusion",
        "overall_conclusion",
        "new_bypass_insights",
        "recommended_follow_up",
    ],
    "additionalProperties": False,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze additional diff candidates without replacing the primary finding."
    )
    parser.add_argument("--diff-directory", required=True)
    parser.add_argument("--run-directory", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--candidate-id", action="append", required=True)
    return parser.parse_args()


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    args = parse_args()
    output = Path(args.output).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=False)
    run_directory = Path(args.run_directory).expanduser().resolve()
    catalog = CandidateCatalog.load(args.diff_directory)
    candidate_ids = list(dict.fromkeys(args.candidate_id))
    if len(candidate_ids) != 4:
        raise RuntimeError("exactly four unique supplemental candidates are required")

    print("Materializing four complete candidate dossiers…", flush=True)
    dossiers = [
        catalog.compact_evidence(
            candidate_id,
            include_related=0,
            include_instructions=True,
        )
        for candidate_id in candidate_ids
    ]
    final_analysis = json.loads(
        (run_directory / "final-analysis/analysis.json").read_text(encoding="utf-8")
    )
    state = json.loads((run_directory / "state.json").read_text(encoding="utf-8"))
    evidence = {
        "advisory": (
            "CVE-2026-59732: rclone archive extract path traversal can escape the "
            "destination root through crafted archive entry names containing dot-dot "
            "components with slash or backslash separators."
        ),
        "original_finalist_ids": state["finalist_ids"],
        "original_final_analysis": final_analysis,
        "supplemental_candidates": dossiers,
    }
    evidence_text = json.dumps(evidence, separators=(",", ":"), sort_keys=True)
    prompt = f"""Analyze exactly four supplemental binary-diff candidates for an authorized,
local bug-bounty patch analysis. Assess every candidate individually from its old/new
decompilation and instructions. Determine whether it contains direct patch logic,
supports the already-localized call flow, is merely security-adjacent, or is unrelated
noise. Do not mistake caller-count, address, or normalized-hash changes for body changes
when mnemonic hashes and structural metrics are identical.

Compare these candidates with the preserved original final analysis. State whether the
new evidence strengthens, leaves unchanged, or weakens the original conclusion. Report
only bypass insights actually supported by these four functions. Separate observed
binary changes from interpretation. Do not use tools or the network and do not provide
weaponized exploitation steps. Return only the required structured response.

UNTRUSTED_EVIDENCE_JSON:
{evidence_text}
"""
    write_json(output / "evidence.json", evidence)
    (output / "prompt.txt").write_text(prompt, encoding="utf-8")
    request = {
        "created_at": datetime.now(UTC).isoformat(),
        "candidate_ids": candidate_ids,
        "model": state["model"],
        "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
    }
    write_json(output / "request.json", request)

    def report_event(event: dict[str, Any]) -> None:
        method = event.get("method")
        if method == "turn/started":
            print("Codex is comparing the four candidates…", flush=True)
        elif method == "item/started":
            item = event.get("params", {}).get("item", {})
            if item.get("type") == "reasoning":
                print("Codex is analyzing the binary evidence…", flush=True)
        elif method == "item/completed":
            item = event.get("params", {}).get("item", {})
            if item.get("type") == "agentMessage":
                print("Codex produced the structured assessment…", flush=True)

    print(f"Starting Codex model {state['model']}…", flush=True)
    with CodexAppServerClient() as codex:
        result = codex.run_isolated(
            prompt,
            output_schema=SUPPLEMENTAL_SCHEMA,
            cwd=output,
            model=state["model"],
            effort="high",
            thread_name="DiffSearchVuln four supplemental candidates",
            timeout_seconds=1_200,
            workspace_write=False,
            event_handler=report_event,
        )
    if len(result.final_response.get("candidate_assessments", [])) != 4:
        raise RuntimeError("Codex did not assess exactly four candidates")
    returned_ids = {
        value.get("candidate_id")
        for value in result.final_response["candidate_assessments"]
    }
    if returned_ids != set(candidate_ids):
        raise RuntimeError("Codex assessment candidate identities do not match the request")
    write_json(output / "codex-audit.json", result.to_dict())
    write_json(output / "analysis.json", result.final_response)
    print(f"Saved supplemental analysis to {output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
