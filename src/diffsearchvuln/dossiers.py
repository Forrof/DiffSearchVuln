from __future__ import annotations

import json
import re
from dataclasses import dataclass
from heapq import heappush, heapreplace
from pathlib import Path
from typing import Any

from .macho import _digest_file


class DossierError(RuntimeError):
    pass


_TOURNAMENT_DECOMPILATION_LIMIT = 30_000
_SIBLING_DECOMPILATION_LIMIT = 8_000
_NAME_TOKEN_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9]{2,}")
_GENERIC_NAME_TOKENS = {
    "fun",
    "function",
    "global",
    "internal",
    "local",
    "sub",
}


@dataclass
class CandidateCatalog:
    diff_directory: Path
    manifest: dict[str, Any]
    pool_candidates: tuple[dict[str, Any], ...]
    candidate_path: Path

    @classmethod
    def load(cls, diff_directory: str | Path) -> "CandidateCatalog":
        directory = Path(diff_directory).expanduser().resolve()
        manifest_path = directory / "manifest.json"
        candidate_path = directory / "candidates.jsonl"
        if not manifest_path.is_file() or not candidate_path.is_file():
            raise DossierError(f"semantic diff is incomplete: {directory}")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise DossierError(f"invalid semantic diff manifest: {error}") from error
        candidate_sha256, _ = _digest_file(candidate_path)
        if candidate_sha256 != manifest.get("candidates", {}).get("sha256"):
            raise DossierError("candidate catalog digest does not match its manifest")
        for side in ("old", "new"):
            export_identity = manifest.get(f"{side}_export", {})
            export_path = Path(export_identity.get("path", ""))
            if not export_path.is_file():
                raise DossierError(f"indexed {side} export is missing: {export_path}")
            export_sha256, _ = _digest_file(export_path)
            if export_sha256 != export_identity.get("sha256"):
                raise DossierError(f"{side} export digest changed after candidate indexing")
        pool_candidates: list[dict[str, Any]] = []
        seen: set[str] = set()
        with candidate_path.open("r", encoding="utf-8") as records:
            for line_number, line in enumerate(records, start=1):
                if not line.strip():
                    continue
                try:
                    candidate = json.loads(line)
                    candidate_id = candidate["candidate_id"]
                except (json.JSONDecodeError, KeyError) as error:
                    raise DossierError(
                        f"invalid candidate record on line {line_number}"
                    ) from error
                if candidate_id in seen:
                    raise DossierError(f"duplicate candidate identity {candidate_id}")
                seen.add(candidate_id)
                if not candidate.get("in_tournament_pool"):
                    break
                pool_candidates.append(candidate)
        if len(pool_candidates) != manifest.get("candidates", {}).get(
            "tournament_pool_count"
        ):
            raise DossierError("candidate pool count does not match its manifest")
        return cls(directory, manifest, tuple(pool_candidates), candidate_path)

    def tournament_pool(self, limit: int | None = None) -> tuple[dict[str, Any], ...]:
        pool = self.pool_candidates
        if limit is None:
            return pool
        if limit < 2:
            raise ValueError("tournament limit must include at least two candidates")
        return pool[:limit]

    def page(self, *, offset: int = 0, limit: int = 50) -> tuple[dict[str, Any], ...]:
        if offset < 0:
            raise ValueError("candidate offset cannot be negative")
        if not 1 <= limit <= 200:
            raise ValueError("candidate page limit must be between 1 and 200")
        candidates: list[dict[str, Any]] = []
        seen = 0
        with self.candidate_path.open("r", encoding="utf-8") as records:
            for line_number, line in enumerate(records, start=1):
                if not line.strip():
                    continue
                if seen < offset:
                    seen += 1
                    continue
                try:
                    candidate = json.loads(line)
                except json.JSONDecodeError as error:
                    raise DossierError(
                        f"invalid candidate record on line {line_number}"
                    ) from error
                candidates.append(candidate)
                if len(candidates) == limit:
                    break
                seen += 1
        return tuple(candidates)

    @property
    def candidate_count(self) -> int:
        try:
            return int(self.manifest["candidates"]["candidate_count"])
        except (KeyError, TypeError, ValueError) as error:
            raise DossierError("semantic diff manifest has no valid candidate count") from error

    def by_id(self, candidate_id: str) -> dict[str, Any]:
        return self.by_ids({candidate_id})[candidate_id]

    def by_ids(self, candidate_ids: set[str]) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for candidate in self.pool_candidates:
            if candidate["candidate_id"] in candidate_ids:
                result[candidate["candidate_id"]] = candidate
        missing = candidate_ids - result.keys()
        if missing:
            with self.candidate_path.open("r", encoding="utf-8") as records:
                for line in records:
                    if not line.strip():
                        continue
                    candidate = json.loads(line)
                    candidate_id = candidate["candidate_id"]
                    if candidate_id in missing:
                        result[candidate_id] = candidate
                        missing.remove(candidate_id)
                        if not missing:
                            break
        if missing:
            raise DossierError(f"unknown candidates: {', '.join(sorted(missing))}")
        return result

    def materialize(
        self,
        candidate_id: str,
        *,
        include_related: int = 0,
    ) -> dict[str, Any]:
        if include_related < 0:
            raise ValueError("related function count cannot be negative")
        candidate = self.by_id(candidate_id)
        related_ids = {
            item["candidate_id"]
            for item in candidate["cluster_members"][:include_related]
        }
        related_by_id = self.by_ids(related_ids) if related_ids else {}
        dossier = {
            "schema_version": "1.0.0",
            "candidate": candidate,
            "old_record": self._record("old", candidate["old_function"]),
            "new_record": self._record("new", candidate["new_function"]),
            "related": [],
        }
        for related in candidate["cluster_members"][:include_related]:
            related_candidate = related_by_id[related["candidate_id"]]
            dossier["related"].append(
                {
                    "candidate": related_candidate,
                    "old_record": self._record("old", related_candidate["old_function"]),
                    "new_record": self._record("new", related_candidate["new_function"]),
                }
            )
        return dossier

    def compact_evidence(
        self,
        candidate_id: str,
        *,
        include_related: int = 2,
        include_instructions: bool = False,
        preserve_complete_decompilation: bool = False,
    ) -> dict[str, Any]:
        dossier = self.materialize(candidate_id, include_related=include_related)
        dossier["old_record"] = _sanitize_record(
            dossier["old_record"],
            include_instructions=include_instructions,
            preserve_complete_decompilation=preserve_complete_decompilation,
        )
        dossier["new_record"] = _sanitize_record(
            dossier["new_record"],
            include_instructions=include_instructions,
            preserve_complete_decompilation=preserve_complete_decompilation,
        )
        for related in dossier["related"]:
            related["old_record"] = _sanitize_record(
                related["old_record"],
                include_instructions=include_instructions,
                preserve_complete_decompilation=preserve_complete_decompilation,
            )
            related["new_record"] = _sanitize_record(
                related["new_record"],
                include_instructions=include_instructions,
                preserve_complete_decompilation=preserve_complete_decompilation,
            )
        return dossier

    def sibling_search_evidence(
        self,
        candidate_ids: tuple[str, ...],
        *,
        direct_record_limit: int = 12,
        similar_record_limit: int = 16,
    ) -> dict[str, Any]:
        """Search the patched export for direct callers and semantic siblings.

        The scan covers every function in the new export. Full decompilation is
        retained only for a bounded number of matches so the resulting evidence
        can be supplied to the final analysis without silently exceeding its
        prompt budget. Coverage fields make every omission explicit.
        """
        if direct_record_limit < 1 or similar_record_limit < 1:
            raise ValueError("sibling search record limits must be positive")

        seeds: list[dict[str, Any]] = []
        unavailable: list[str] = []
        for candidate_id in candidate_ids:
            candidate = self.by_id(candidate_id)
            record = self._record("new", candidate.get("new_function"))
            if record is None:
                unavailable.append(candidate_id)
                continue
            function = record["function"]
            seeds.append(
                {
                    "candidate_id": candidate_id,
                    "address": _normalize_address(function.get("address", "")),
                    "name": _function_name(function),
                    "caller_addresses": {
                        address
                        for value in function.get("callers", [])
                        if (address := _relationship_address(value)) is not None
                    },
                    "callees": _relationship_set(function.get("callees", [])),
                    "imports": _meaningful_values(function.get("imports", [])),
                    "strings": _meaningful_values(function.get("strings", [])),
                    "name_tokens": _name_tokens(function),
                }
            )

        direct_matches: list[dict[str, Any]] = []
        direct_count = 0
        similar_count = 0
        similar_heap: list[tuple[int, str, dict[str, Any]]] = []
        functions_scanned = 0
        export_path = Path(self.manifest["new_export"]["path"])
        with export_path.open("r", encoding="utf-8") as records:
            for line_number, line in enumerate(records, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    function = record["function"]
                except (json.JSONDecodeError, KeyError, TypeError) as error:
                    raise DossierError(
                        f"invalid new export record on line {line_number}"
                    ) from error
                functions_scanned += 1
                address = _normalize_address(function.get("address", ""))
                callees = _relationship_set(function.get("callees", []))
                record_name = _function_name(function)
                is_direct = False
                for seed in seeds:
                    if address == seed["address"]:
                        continue
                    signals: list[str] = []
                    if address in seed["caller_addresses"]:
                        signals.append("listed in the patched function's caller set")
                    if seed["address"] in callees:
                        signals.append("callee edge targets the patched function")
                    if signals:
                        is_direct = True
                        direct_count += 1
                        direct_matches.append(
                            {
                                "evidence_label": "OBSERVED",
                                "seed_candidate_id": seed["candidate_id"],
                                "seed_function": seed["name"],
                                "relationship": "direct_call_site",
                                "match_signals": signals,
                                "function": _function_summary(record),
                                "record": record,
                            }
                        )
                if is_direct or any(address == seed["address"] for seed in seeds):
                    continue

                for seed in seeds:
                    score, signals = _similarity_score(function, callees, seed)
                    if score <= 0:
                        continue
                    similar_count += 1
                    match = {
                        "evidence_label": "OBSERVED",
                        "seed_candidate_id": seed["candidate_id"],
                        "seed_function": seed["name"],
                        "relationship": "similar_implementation_candidate",
                        "similarity_score": score,
                        "match_signals": signals,
                        "function": _function_summary(record),
                        "record": record,
                    }
                    key = f"{seed['candidate_id']}:{address}:{record_name}"
                    item = (score, key, match)
                    if len(similar_heap) < similar_record_limit:
                        heappush(similar_heap, item)
                    elif item[:2] > similar_heap[0][:2]:
                        heapreplace(similar_heap, item)

        direct_matches.sort(
            key=lambda item: (
                item["seed_candidate_id"],
                item["function"]["address"],
                item["function"]["qualified_name"],
            )
        )
        included_direct = direct_matches[:direct_record_limit]
        for item in included_direct:
            item["record"] = _sanitize_sibling_record(item["record"])
        similar_matches = [item[2] for item in sorted(similar_heap, reverse=True)]
        for item in similar_matches:
            item["record"] = _sanitize_sibling_record(item["record"])

        return {
            "schema_version": "1.0.0",
            "evidence_label": "OBSERVED",
            "searched_function_ids": [seed["candidate_id"] for seed in seeds],
            "unavailable_function_ids": unavailable,
            "same_function_call_sites": included_direct,
            "similar_implementations": similar_matches,
            "coverage": {
                "evidence_label": "OBSERVED",
                "export_side": "new",
                "functions_scanned": functions_scanned,
                "direct_matches_found": direct_count,
                "direct_records_included": len(included_direct),
                "direct_records_omitted": max(0, direct_count - len(included_direct)),
                "similar_matches_found": similar_count,
                "similar_records_included": len(similar_matches),
                "similar_records_omitted": max(0, similar_count - len(similar_matches)),
            },
        }

    def _record(self, side: str, reference: dict[str, Any] | None) -> dict[str, Any] | None:
        if reference is None:
            return None
        export_path = Path(self.manifest[f"{side}_export"]["path"])
        offset = int(reference["record_offset"])
        length = int(reference["record_length"])
        with export_path.open("rb") as export:
            export.seek(offset)
            raw_record = export.read(length)
        try:
            record = json.loads(raw_record)
        except json.JSONDecodeError as error:
            raise DossierError(f"could not read indexed {side} function record") from error
        actual_address = record.get("function", {}).get("address", "").lower().removeprefix("0x")
        if actual_address != reference["address"]:
            raise DossierError(f"indexed {side} function address does not match its record")
        return record


def write_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    output = Path(path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.partial")
    if output.exists():
        raise DossierError(f"dossier output already exists: {output}")
    temporary.write_text(
        json.dumps(dossier, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(output)


def _sanitize_record(
    record: dict[str, Any] | None,
    *,
    include_instructions: bool,
    preserve_complete_decompilation: bool,
) -> dict[str, Any] | None:
    if record is None:
        return None
    function = dict(record["function"])
    warnings = list(record.get("warnings", []))
    decompilation = function.get("decompilation")
    if (
        not preserve_complete_decompilation
        and isinstance(decompilation, str)
        and len(decompilation) > _TOURNAMENT_DECOMPILATION_LIMIT
    ):
        half = _TOURNAMENT_DECOMPILATION_LIMIT // 2
        omitted = len(decompilation) - (half * 2)
        function["decompilation"] = (
            decompilation[:half]
            + f"\n/* {omitted} decompilation characters omitted from preliminary "
            "tournament view */\n"
            + decompilation[-half:]
        )
        warnings.append(
            f"decompilation: omitted {omitted} middle characters from the preliminary "
            "tournament view; finalist analysis restores the complete decompilation"
        )
    if not include_instructions and function.get("decompilation") is not None:
        instruction_count = len(function.get("instructions", []))
        function["instructions"] = []
        warnings.append(
            f"{instruction_count} instructions omitted from this tournament view because the "
            "complete decompilation is present; finalist analysis can restore them"
        )
    for field in ("strings", "imports"):
        values = function.get(field, [])
        accepted = [value for value in values if isinstance(value, str) and len(value) <= 512]
        omitted = len(values) - len(accepted)
        function[field] = accepted
        if omitted:
            warnings.append(f"{field}: omitted {omitted} values longer than 512 characters")
    return {
        "schema_version": record["schema_version"],
        "artifact_sha256": record["artifact_sha256"],
        "architecture": record["architecture"],
        "ghidra_version": record["ghidra_version"],
        "language_id": record["language_id"],
        "compiler_spec_id": record["compiler_spec_id"],
        "function": function,
        "warnings": warnings,
    }


def _sanitize_sibling_record(record: dict[str, Any]) -> dict[str, Any]:
    sanitized = _sanitize_record(
        record,
        include_instructions=False,
        preserve_complete_decompilation=True,
    )
    assert sanitized is not None
    function = sanitized["function"]
    decompilation = function.get("decompilation")
    if isinstance(decompilation, str) and len(decompilation) > _SIBLING_DECOMPILATION_LIMIT:
        half = _SIBLING_DECOMPILATION_LIMIT // 2
        omitted = len(decompilation) - (half * 2)
        function["decompilation"] = (
            decompilation[:half]
            + f"\n/* {omitted} sibling-search decompilation characters omitted */\n"
            + decompilation[-half:]
        )
        sanitized["warnings"].append(
            f"decompilation: omitted {omitted} middle characters from sibling-search evidence"
        )
    return sanitized


def _normalize_address(value: Any) -> str:
    return str(value).strip().lower().removeprefix("0x")


def _relationship_address(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    address = value.rsplit("@", 1)[-1]
    normalized = _normalize_address(address)
    return normalized or None


def _relationship_set(values: Any) -> set[str]:
    if not isinstance(values, list):
        return set()
    return {
        address
        for value in values
        if (address := _relationship_address(value)) is not None
    }


def _meaningful_values(values: Any) -> set[str]:
    if not isinstance(values, list):
        return set()
    return {
        value.strip().lower()
        for value in values
        if isinstance(value, str) and 3 <= len(value.strip()) <= 512
    }


def _name_tokens(function: dict[str, Any]) -> set[str]:
    names = " ".join(
        str(function.get(field, "")) for field in ("name", "qualified_name", "namespace")
    )
    return {
        token.lower()
        for token in _NAME_TOKEN_PATTERN.findall(names)
        if token.lower() not in _GENERIC_NAME_TOKENS
    }


def _function_name(function: dict[str, Any]) -> str:
    return str(function.get("qualified_name") or function.get("name") or function.get("address"))


def _function_summary(record: dict[str, Any]) -> dict[str, Any]:
    function = record["function"]
    return {
        "address": _normalize_address(function.get("address", "")),
        "name": str(function.get("name", "")),
        "qualified_name": _function_name(function),
        "namespace": str(function.get("namespace", "")),
        "body_size": int(function.get("body_size", 0)),
    }


def _similarity_score(
    function: dict[str, Any], callees: set[str], seed: dict[str, Any]
) -> tuple[int, list[str]]:
    shared_callees = sorted(callees & seed["callees"])
    shared_imports = sorted(_meaningful_values(function.get("imports", [])) & seed["imports"])
    shared_strings = sorted(_meaningful_values(function.get("strings", [])) & seed["strings"])
    shared_name_tokens = sorted(_name_tokens(function) & seed["name_tokens"])
    score = (
        len(shared_callees) * 7
        + len(shared_imports) * 5
        + min(len(shared_strings), 4) * 3
        + min(len(shared_name_tokens), 3) * 2
    )
    strong_signal = bool(shared_callees or shared_imports or shared_strings)
    if not strong_signal and len(shared_name_tokens) < 2:
        return 0, []
    signals: list[str] = []
    if shared_callees:
        signals.append(f"shared callees: {', '.join(shared_callees[:6])}")
    if shared_imports:
        signals.append(f"shared imports: {', '.join(shared_imports[:6])}")
    if shared_strings:
        signals.append(f"shared strings: {', '.join(shared_strings[:4])}")
    if shared_name_tokens:
        signals.append(f"shared name terms: {', '.join(shared_name_tokens[:6])}")
    return score, signals
