from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .macho import _digest_file


class DossierError(RuntimeError):
    pass


_TOURNAMENT_DECOMPILATION_LIMIT = 30_000


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
