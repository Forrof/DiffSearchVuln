from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from .macho import _digest_file
from .symbols import load_symbol_map


DIFF_ENGINE_VERSION = "1.0.0"
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{8,}")
_WORDS = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,}")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_STOP_WORDS = {
    "and",
    "are",
    "but",
    "can",
    "for",
    "from",
    "has",
    "into",
    "its",
    "new",
    "not",
    "old",
    "the",
    "then",
    "this",
    "use",
    "version",
    "was",
    "with",
}
_NOISE_PREFIXES = (
    "runtime.",
    "internal/",
    "vendor/",
    "type:.",
)


class DiffError(RuntimeError):
    pass


@dataclass(frozen=True)
class DiffSettings:
    tournament_pool_size: int = 500
    max_cluster_members: int = 8

    def __post_init__(self) -> None:
        if self.tournament_pool_size < 1:
            raise ValueError("tournament pool size must be positive")
        if self.max_cluster_members < 0:
            raise ValueError("maximum cluster members cannot be negative")


@dataclass(frozen=True)
class SemanticDiffResult:
    cache_key: str
    cache_path: str
    manifest_path: str
    match_path: str
    candidate_path: str
    index_path: str
    match_count: int
    unchanged_count: int
    candidate_count: int
    tournament_pool_count: int
    cached: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class SemanticDiffRunner:
    """Streaming, deterministic matching over two Ghidra JSONL exports."""

    def __init__(self, *, output_root: str | Path) -> None:
        self.output_root = Path(output_root).expanduser().resolve()

    def diff(
        self,
        old_export: str | Path,
        new_export: str | Path,
        *,
        old_symbols: str | Path | None = None,
        new_symbols: str | Path | None = None,
        advisory_text: str = "",
        settings: DiffSettings | None = None,
    ) -> SemanticDiffResult:
        settings = settings or DiffSettings()
        old_path = Path(old_export).expanduser().resolve()
        new_path = Path(new_export).expanduser().resolve()
        if not old_path.is_file() or not new_path.is_file():
            raise DiffError("both function exports must exist")
        old_export_sha256, _ = _digest_file(old_path)
        new_export_sha256, _ = _digest_file(new_path)
        old_symbol_path, old_symbol_sha256 = _optional_input(old_symbols)
        new_symbol_path, new_symbol_sha256 = _optional_input(new_symbols)
        cache_key = _cache_key(
            old_export_sha256,
            new_export_sha256,
            old_symbol_sha256,
            new_symbol_sha256,
            advisory_text,
            settings,
        )
        final_directory = self.output_root / "completed" / cache_key
        cached = self._load_cached(final_directory)
        if cached is not None:
            return cached

        staging_root = self.output_root / "staging"
        failed_root = self.output_root / "failed"
        locks_root = self.output_root / ".locks"
        for directory in (final_directory.parent, staging_root, failed_root, locks_root):
            directory.mkdir(parents=True, exist_ok=True)
        lock = locks_root / f"{cache_key}.lock"
        descriptor: int | None = None
        staging: Path | None = None
        try:
            try:
                descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError as error:
                raise DiffError(f"semantic diff is already running for {cache_key}") from error
            os.write(descriptor, str(os.getpid()).encode("ascii"))
            staging = staging_root / f"{cache_key}-{uuid4()}"
            staging.mkdir()
            index_path = staging / "index.sqlite3"
            connection = sqlite3.connect(index_path)
            connection.row_factory = sqlite3.Row
            try:
                _initialize_index(connection)
                old_metadata = _index_export(
                    connection,
                    "old",
                    old_path,
                    load_symbol_map(old_symbol_path) if old_symbol_path else {},
                )
                new_metadata = _index_export(
                    connection,
                    "new",
                    new_path,
                    load_symbol_map(new_symbol_path) if new_symbol_path else {},
                )
                if old_metadata["architecture"] != new_metadata["architecture"]:
                    raise DiffError("exports use different architectures")
                matches = _match_functions(connection)
                match_stats = _write_matches(connection, staging / "matches.jsonl", matches)
                candidate_stats = _write_candidates(
                    connection,
                    staging / "candidates.jsonl",
                    matches,
                    advisory_text=advisory_text,
                    settings=settings,
                )
                connection.commit()
            finally:
                connection.close()

            match_sha256, _ = _digest_file(staging / "matches.jsonl")
            candidate_sha256, _ = _digest_file(staging / "candidates.jsonl")
            manifest = {
                "schema_version": "1.0.0",
                "status": "completed",
                "engine": "diffsearchvuln-semantic",
                "engine_version": DIFF_ENGINE_VERSION,
                "cache_key": cache_key,
                "old_export": {
                    "path": str(old_path),
                    "sha256": old_export_sha256,
                    **old_metadata,
                    "symbol_path": str(old_symbol_path) if old_symbol_path else None,
                    "symbol_sha256": old_symbol_sha256,
                },
                "new_export": {
                    "path": str(new_path),
                    "sha256": new_export_sha256,
                    **new_metadata,
                    "symbol_path": str(new_symbol_path) if new_symbol_path else None,
                    "symbol_sha256": new_symbol_sha256,
                },
                "advisory_text_sha256": hashlib.sha256(
                    advisory_text.encode("utf-8")
                ).hexdigest(),
                "advisory_terms": sorted(_advisory_terms(advisory_text)),
                "settings": asdict(settings),
                "matches": {**match_stats, "sha256": match_sha256},
                "candidates": {**candidate_stats, "sha256": candidate_sha256},
                "completed_at": datetime.now(UTC).isoformat(),
            }
            _write_json(staging / "manifest.json", manifest)
            try:
                os.rename(staging, final_directory)
            except FileExistsError:
                shutil.rmtree(staging)
                cached_result = self._load_cached(final_directory)
                if cached_result is None:
                    raise DiffError(f"invalid concurrent diff cache for {cache_key}")
                return cached_result
            return self._result(final_directory, manifest, cached=False)
        except Exception as error:
            if staging is not None and staging.exists():
                _write_json(
                    staging / "failure.json",
                    {
                        "schema_version": "1.0.0",
                        "status": "failed",
                        "cache_key": cache_key,
                        "error": str(error),
                        "failed_at": datetime.now(UTC).isoformat(),
                    },
                )
                os.rename(staging, failed_root / f"{cache_key}-{uuid4()}")
            if isinstance(error, (DiffError, ValueError)):
                raise
            raise DiffError(str(error)) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            lock.unlink(missing_ok=True)

    def _load_cached(self, directory: Path) -> SemanticDiffResult | None:
        manifest_path = directory / "manifest.json"
        match_path = directory / "matches.jsonl"
        candidate_path = directory / "candidates.jsonl"
        index_path = directory / "index.sqlite3"
        if not all(path.is_file() for path in (manifest_path, match_path, candidate_path, index_path)):
            return None
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            match_sha256, _ = _digest_file(match_path)
            candidate_sha256, _ = _digest_file(candidate_path)
            if manifest.get("status") != "completed":
                return None
            if match_sha256 != manifest["matches"]["sha256"]:
                return None
            if candidate_sha256 != manifest["candidates"]["sha256"]:
                return None
            return self._result(directory, manifest, cached=True)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return None

    @staticmethod
    def _result(
        directory: Path, manifest: dict[str, Any], *, cached: bool
    ) -> SemanticDiffResult:
        return SemanticDiffResult(
            cache_key=manifest["cache_key"],
            cache_path=str(directory),
            manifest_path=str(directory / "manifest.json"),
            match_path=str(directory / "matches.jsonl"),
            candidate_path=str(directory / "candidates.jsonl"),
            index_path=str(directory / "index.sqlite3"),
            match_count=manifest["matches"]["match_count"],
            unchanged_count=manifest["matches"]["unchanged_count"],
            candidate_count=manifest["candidates"]["candidate_count"],
            tournament_pool_count=manifest["candidates"]["tournament_pool_count"],
            cached=cached,
        )


def normalize_instruction(instruction: str) -> str:
    text = instruction.split("|", 1)[-1].strip().lower()
    return _ADDRESS.sub("<address>", text)


def _initialize_index(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        CREATE TABLE functions (
            side TEXT NOT NULL CHECK(side IN ('old', 'new')),
            address TEXT NOT NULL,
            raw_name TEXT NOT NULL,
            resolved_name TEXT,
            name_source TEXT,
            body_size INTEGER NOT NULL,
            instruction_count INTEGER NOT NULL,
            normalized_hash TEXT NOT NULL,
            mnemonic_hash TEXT NOT NULL,
            branch_count INTEGER NOT NULL,
            compare_count INTEGER NOT NULL,
            call_count INTEGER NOT NULL,
            return_count INTEGER NOT NULL,
            strings_json TEXT NOT NULL,
            imports_json TEXT NOT NULL,
            callers_json TEXT NOT NULL,
            callees_json TEXT NOT NULL,
            warnings_json TEXT NOT NULL,
            dropped_string_count INTEGER NOT NULL,
            record_offset INTEGER NOT NULL,
            record_length INTEGER NOT NULL,
            PRIMARY KEY(side, address)
        );
        CREATE INDEX idx_functions_name ON functions(side, resolved_name);
        CREATE INDEX idx_functions_normalized ON functions(side, normalized_hash);
        CREATE INDEX idx_functions_mnemonic ON functions(side, mnemonic_hash);
        CREATE TABLE matches (
            old_address TEXT PRIMARY KEY,
            new_address TEXT UNIQUE NOT NULL,
            method TEXT NOT NULL,
            confidence REAL NOT NULL
        );
        """
    )


def _index_export(
    connection: sqlite3.Connection,
    side: str,
    path: Path,
    symbols: dict[str, str],
) -> dict[str, Any]:
    batch: list[tuple[Any, ...]] = []
    function_count = 0
    artifact_sha256: str | None = None
    architecture: str | None = None
    ghidra_version: str | None = None
    with path.open("rb") as records:
        while True:
            offset = records.tell()
            raw_line = records.readline()
            if not raw_line:
                break
            if not raw_line.strip():
                continue
            try:
                record = json.loads(raw_line)
                function = record["function"]
                address = function["address"].lower().removeprefix("0x")
                int(address, 16)
            except (json.JSONDecodeError, KeyError, AttributeError, ValueError) as error:
                raise DiffError(f"invalid {side} export record at byte {offset}") from error
            artifact_sha256 = _consistent(
                artifact_sha256, record.get("artifact_sha256"), f"{side} artifact"
            )
            architecture = _consistent(
                architecture, record.get("architecture"), f"{side} architecture"
            )
            ghidra_version = _consistent(
                ghidra_version, record.get("ghidra_version"), f"{side} Ghidra version"
            )
            instructions = [normalize_instruction(item) for item in function["instructions"]]
            mnemonics = [item.split(None, 1)[0] if item else "" for item in instructions]
            counts = Counter(mnemonics)
            raw_name = function["qualified_name"] or function["name"]
            symbol_name = symbols.get(address)
            if symbol_name:
                resolved_name = symbol_name
                name_source = "go_pclntab"
            elif raw_name and not raw_name.startswith("FUN_"):
                resolved_name = raw_name
                name_source = "ghidra"
            else:
                resolved_name = None
                name_source = None
            strings, dropped_strings = _bounded_strings(function.get("strings", []))
            imports, _ = _bounded_strings(function.get("imports", []))
            batch.append(
                (
                    side,
                    address,
                    raw_name,
                    resolved_name,
                    name_source,
                    int(function["body_size"]),
                    len(instructions),
                    _hash_lines(instructions),
                    _hash_lines(mnemonics),
                    sum(counts[item] for item in counts if item.startswith("b")),
                    counts["cmp"] + counts["cmn"] + counts["tst"],
                    counts["bl"] + counts["blr"],
                    counts["ret"],
                    json.dumps(strings, sort_keys=True, separators=(",", ":")),
                    json.dumps(imports, sort_keys=True, separators=(",", ":")),
                    json.dumps(function.get("callers", []), separators=(",", ":")),
                    json.dumps(function.get("callees", []), separators=(",", ":")),
                    json.dumps(record.get("warnings", []), separators=(",", ":")),
                    dropped_strings,
                    offset,
                    len(raw_line),
                )
            )
            function_count += 1
            if len(batch) >= 1000:
                _insert_functions(connection, batch)
                batch.clear()
    if batch:
        _insert_functions(connection, batch)
    if not function_count or not artifact_sha256 or not architecture or not ghidra_version:
        raise DiffError(f"{side} export contains no usable functions")
    connection.commit()
    return {
        "artifact_sha256": artifact_sha256,
        "architecture": architecture,
        "ghidra_version": ghidra_version,
        "function_count": function_count,
        "named_function_count": connection.execute(
            "SELECT COUNT(*) FROM functions WHERE side = ? AND resolved_name IS NOT NULL",
            (side,),
        ).fetchone()[0],
    }


def _insert_functions(connection: sqlite3.Connection, batch: list[tuple[Any, ...]]) -> None:
    try:
        connection.executemany(
            """
            INSERT INTO functions VALUES(
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            batch,
        )
    except sqlite3.IntegrityError as error:
        raise DiffError(f"function export contains duplicate identities: {error}") from error


def _match_functions(connection: sqlite3.Connection) -> list[tuple[str, str, str, float]]:
    matches: list[tuple[str, str, str, float]] = []
    used_old: set[str] = set()
    used_new: set[str] = set()

    old_names = _unique_values(connection, "old", "resolved_name", used_old)
    new_names = _unique_values(connection, "new", "resolved_name", used_new)
    for name in sorted(old_names.keys() & new_names.keys()):
        old_address = old_names[name]
        new_address = new_names[name]
        matches.append((old_address, new_address, "exact_name", 1.0))
        used_old.add(old_address)
        used_new.add(new_address)

    for column, method, confidence in (
        ("normalized_hash", "exact_normalized_instructions", 0.98),
        ("mnemonic_hash", "exact_mnemonic_sequence", 0.90),
    ):
        old_values = _unique_values(connection, "old", column, used_old)
        new_values = _unique_values(connection, "new", column, used_new)
        for value in sorted(old_values.keys() & new_values.keys()):
            old_address = old_values[value]
            new_address = new_values[value]
            matches.append((old_address, new_address, method, confidence))
            used_old.add(old_address)
            used_new.add(new_address)

    connection.executemany(
        "INSERT INTO matches(old_address, new_address, method, confidence) VALUES(?, ?, ?, ?)",
        matches,
    )
    connection.commit()
    return matches


def _unique_values(
    connection: sqlite3.Connection,
    side: str,
    column: str,
    used: set[str],
) -> dict[str, str]:
    if column not in {"resolved_name", "normalized_hash", "mnemonic_hash"}:
        raise ValueError("invalid match column")
    result: dict[str, str | None] = {}
    rows = connection.execute(
        f"SELECT address, {column} AS value FROM functions "
        f"WHERE side = ? AND {column} IS NOT NULL ORDER BY address",
        (side,),
    )
    for row in rows:
        if row["address"] in used:
            continue
        value = row["value"]
        if value in result:
            result[value] = None
        else:
            result[value] = row["address"]
    return {value: address for value, address in result.items() if address is not None}


def _write_matches(
    connection: sqlite3.Connection,
    path: Path,
    matches: Iterable[tuple[str, str, str, float]],
) -> dict[str, int]:
    unchanged_count = 0
    modified_count = 0
    data_only_count = 0
    match_count = 0
    query = """
        SELECT
            o.resolved_name AS old_name, n.resolved_name AS new_name,
            o.normalized_hash AS old_hash, n.normalized_hash AS new_hash,
            o.strings_json AS old_strings, n.strings_json AS new_strings,
            o.imports_json AS old_imports, n.imports_json AS new_imports
        FROM functions o, functions n
        WHERE o.side = 'old' AND n.side = 'new'
          AND o.address = ? AND n.address = ?
    """
    with path.open("w", encoding="utf-8") as output:
        for old_address, new_address, method, confidence in matches:
            row = connection.execute(query, (old_address, new_address)).fetchone()
            if row["old_hash"] == row["new_hash"]:
                if (
                    row["old_strings"] != row["new_strings"]
                    or row["old_imports"] != row["new_imports"]
                ):
                    status = "data_only"
                    data_only_count += 1
                else:
                    status = "unchanged"
                    unchanged_count += 1
            else:
                status = "modified"
                modified_count += 1
            record = {
                "schema_version": "1.0.0",
                "old_address": old_address,
                "new_address": new_address,
                "name": row["new_name"] or row["old_name"],
                "method": method,
                "confidence": confidence,
                "status": status,
            }
            output.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            match_count += 1
    return {
        "match_count": match_count,
        "unchanged_count": unchanged_count,
        "modified_count": modified_count,
        "data_only_count": data_only_count,
    }


def _write_candidates(
    connection: sqlite3.Connection,
    path: Path,
    matches: list[tuple[str, str, str, float]],
    *,
    advisory_text: str,
    settings: DiffSettings,
) -> dict[str, Any]:
    advisory_terms = _advisory_terms(advisory_text)
    candidates: list[dict[str, Any]] = []
    by_old_address: dict[str, str] = {}
    by_new_address: dict[str, str] = {}
    match_query = """
        SELECT o.*, n.address AS n_address, n.raw_name AS n_raw_name,
            n.resolved_name AS n_resolved_name, n.name_source AS n_name_source,
            n.body_size AS n_body_size, n.instruction_count AS n_instruction_count,
            n.normalized_hash AS n_normalized_hash, n.mnemonic_hash AS n_mnemonic_hash,
            n.branch_count AS n_branch_count, n.compare_count AS n_compare_count,
            n.call_count AS n_call_count, n.return_count AS n_return_count,
            n.strings_json AS n_strings_json, n.imports_json AS n_imports_json,
            n.callers_json AS n_callers_json, n.callees_json AS n_callees_json,
            n.warnings_json AS n_warnings_json,
            n.dropped_string_count AS n_dropped_string_count,
            n.record_offset AS n_record_offset, n.record_length AS n_record_length
        FROM functions o, functions n
        WHERE o.side = 'old' AND n.side = 'new'
          AND o.address = ? AND n.address = ?
    """
    for old_address, new_address, method, confidence in matches:
        row = connection.execute(match_query, (old_address, new_address)).fetchone()
        old = _side_summary(row, "old")
        new = _side_summary(row, "new")
        if old["normalized_hash"] == new["normalized_hash"]:
            if old["strings"] == new["strings"] and old["imports"] == new["imports"]:
                continue
            kind = "data_only"
        elif confidence < 0.95:
            kind = "low_confidence_match"
        else:
            kind = "modified"
        candidate = _candidate(kind, old, new, confidence, advisory_terms)
        candidates.append(candidate)
        by_old_address[old_address] = candidate["candidate_id"]
        by_new_address[new_address] = candidate["candidate_id"]

    for side, kind, address_map in (
        ("old", "deleted", by_old_address),
        ("new", "added", by_new_address),
    ):
        rows = connection.execute(
            f"""
            SELECT f.* FROM functions f
            LEFT JOIN matches m ON m.{'old_address' if side == 'old' else 'new_address'} = f.address
            WHERE f.side = ? AND m.{'old_address' if side == 'old' else 'new_address'} IS NULL
            ORDER BY f.address
            """,
            (side,),
        )
        for row in rows:
            summary = _single_side_summary(row)
            candidate = _candidate(
                kind,
                summary if side == "old" else None,
                summary if side == "new" else None,
                None,
                advisory_terms,
            )
            candidates.append(candidate)
            address_map[summary["address"]] = candidate["candidate_id"]

    by_id = {candidate["candidate_id"]: candidate for candidate in candidates}
    for candidate in candidates:
        related: set[str] = set()
        for side, address_map in ((candidate["old_function"], by_old_address), (candidate["new_function"], by_new_address)):
            if side is None:
                continue
            for relationship in side["callers"] + side["callees"]:
                address = _relationship_address(relationship)
                related_id = address_map.get(address)
                if related_id and related_id != candidate["candidate_id"]:
                    related.add(related_id)
        ordered_related = sorted(
            related,
            key=lambda candidate_id: (
                -by_id[candidate_id]["deterministic_score"],
                candidate_id,
            ),
        )[: settings.max_cluster_members]
        candidate["cluster_members"] = [
            {
                "candidate_id": candidate_id,
                "name": by_id[candidate_id]["primary_name"],
                "kind": by_id[candidate_id]["match_kind"],
            }
            for candidate_id in ordered_related
        ]

    candidates.sort(key=lambda item: (-item["deterministic_score"], item["candidate_id"]))
    kind_counts: Counter[str] = Counter()
    for rank, candidate in enumerate(candidates, start=1):
        candidate["deterministic_rank"] = rank
        candidate["in_tournament_pool"] = rank <= settings.tournament_pool_size
        kind_counts[candidate["match_kind"]] += 1
        candidate["old_function"] = _compact_side(candidate["old_function"])
        candidate["new_function"] = _compact_side(candidate["new_function"])
    with path.open("w", encoding="utf-8") as output:
        for candidate in candidates:
            output.write(json.dumps(candidate, sort_keys=True, separators=(",", ":")) + "\n")
    return {
        "candidate_count": len(candidates),
        "tournament_pool_count": min(len(candidates), settings.tournament_pool_size),
        "kind_counts": dict(sorted(kind_counts.items())),
    }


def _side_summary(row: sqlite3.Row, side: str) -> dict[str, Any]:
    if side == "old":
        return {
            "address": row["address"],
            "raw_name": row["raw_name"],
            "name": row["resolved_name"],
            "name_source": row["name_source"],
            "body_size": row["body_size"],
            "instruction_count": row["instruction_count"],
            "normalized_hash": row["normalized_hash"],
            "mnemonic_hash": row["mnemonic_hash"],
            "branch_count": row["branch_count"],
            "compare_count": row["compare_count"],
            "call_count": row["call_count"],
            "return_count": row["return_count"],
            "strings": json.loads(row["strings_json"]),
            "imports": json.loads(row["imports_json"]),
            "callers": json.loads(row["callers_json"]),
            "callees": json.loads(row["callees_json"]),
            "warnings": json.loads(row["warnings_json"]),
            "dropped_string_count": row["dropped_string_count"],
            "record_offset": row["record_offset"],
            "record_length": row["record_length"],
        }
    return {
        "address": row["n_address"],
        "raw_name": row["n_raw_name"],
        "name": row["n_resolved_name"],
        "name_source": row["n_name_source"],
        "body_size": row["n_body_size"],
        "instruction_count": row["n_instruction_count"],
        "normalized_hash": row["n_normalized_hash"],
        "mnemonic_hash": row["n_mnemonic_hash"],
        "branch_count": row["n_branch_count"],
        "compare_count": row["n_compare_count"],
        "call_count": row["n_call_count"],
        "return_count": row["n_return_count"],
        "strings": json.loads(row["n_strings_json"]),
        "imports": json.loads(row["n_imports_json"]),
        "callers": json.loads(row["n_callers_json"]),
        "callees": json.loads(row["n_callees_json"]),
        "warnings": json.loads(row["n_warnings_json"]),
        "dropped_string_count": row["n_dropped_string_count"],
        "record_offset": row["n_record_offset"],
        "record_length": row["n_record_length"],
    }


def _single_side_summary(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "address": row["address"],
        "raw_name": row["raw_name"],
        "name": row["resolved_name"],
        "name_source": row["name_source"],
        "body_size": row["body_size"],
        "instruction_count": row["instruction_count"],
        "normalized_hash": row["normalized_hash"],
        "mnemonic_hash": row["mnemonic_hash"],
        "branch_count": row["branch_count"],
        "compare_count": row["compare_count"],
        "call_count": row["call_count"],
        "return_count": row["return_count"],
        "strings": json.loads(row["strings_json"]),
        "imports": json.loads(row["imports_json"]),
        "callers": json.loads(row["callers_json"]),
        "callees": json.loads(row["callees_json"]),
        "warnings": json.loads(row["warnings_json"]),
        "dropped_string_count": row["dropped_string_count"],
        "record_offset": row["record_offset"],
        "record_length": row["record_length"],
    }


def _candidate(
    kind: str,
    old: dict[str, Any] | None,
    new: dict[str, Any] | None,
    confidence: float | None,
    advisory_terms: set[str],
) -> dict[str, Any]:
    primary = new or old
    assert primary is not None
    name = primary["name"] or primary["raw_name"]
    name_terms = _identifier_terms(name)
    matched_terms = sorted(advisory_terms & name_terms)
    strings_added = sorted(set((new or {}).get("strings", [])) - set((old or {}).get("strings", [])))
    strings_removed = sorted(set((old or {}).get("strings", [])) - set((new or {}).get("strings", [])))
    imports_added = sorted(set((new or {}).get("imports", [])) - set((old or {}).get("imports", [])))
    imports_removed = sorted(set((old or {}).get("imports", [])) - set((new or {}).get("imports", [])))
    for value in strings_added + strings_removed:
        lowered = value.lower()
        matched_terms.extend(term for term in advisory_terms if term in lowered)
    matched_terms = sorted(set(matched_terms))

    score = {
        "modified": 35.0,
        "added": 28.0,
        "deleted": 24.0,
        "low_confidence_match": 18.0,
        "data_only": 12.0,
    }[kind]
    score += min(30.0, 10.0 * len(matched_terms))
    old_count = old["instruction_count"] if old else 0
    new_count = new["instruction_count"] if new else 0
    instruction_delta = abs(new_count - old_count)
    score += min(12.0, 24.0 * instruction_delta / max(old_count, new_count, 1))
    compare_delta = (new["compare_count"] if new else 0) - (old["compare_count"] if old else 0)
    branch_delta = (new["branch_count"] if new else 0) - (old["branch_count"] if old else 0)
    if compare_delta > 0:
        score += min(5.0, float(compare_delta))
    if branch_delta > 0:
        score += min(5.0, float(branch_delta))
    score += min(8.0, 2.0 * (len(strings_added) + len(imports_added)))
    noise_signals: list[str] = []
    if name.startswith(_NOISE_PREFIXES):
        score -= 12.0
        noise_signals.append("compiler_or_runtime_namespace")
    if primary["dropped_string_count"]:
        noise_signals.append("oversized_string_reference_suppressed")
    if confidence is not None and confidence < 0.95:
        noise_signals.append("low_confidence_match")
    score = round(max(0.0, score), 3)
    identity = f"{kind}\0{(old or {}).get('address')}\0{(new or {}).get('address')}\0{name}"
    candidate_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    change_hash = hashlib.sha256(
        f"{(old or {}).get('normalized_hash')}\0{(new or {}).get('normalized_hash')}".encode(
            "utf-8"
        )
    ).hexdigest()
    return {
        "schema_version": "1.0.0",
        "candidate_id": candidate_id,
        "component_key": "primary-mach-o",
        "primary_name": name,
        "match_kind": kind,
        "match_confidence": confidence,
        "deterministic_score": score,
        "deterministic_rank": 0,
        "in_tournament_pool": False,
        "old_function": old,
        "new_function": new,
        "change_evidence": {
            "normalized_change_hash": change_hash,
            "instruction_count_delta": new_count - old_count,
            "body_size_delta": (new["body_size"] if new else 0)
            - (old["body_size"] if old else 0),
            "compare_count_delta": compare_delta,
            "branch_count_delta": branch_delta,
            "strings_added": strings_added,
            "strings_removed": strings_removed,
            "imports_added": imports_added,
            "imports_removed": imports_removed,
            "advisory_terms_matched": matched_terms,
            "noise_signals": noise_signals,
        },
        "cluster_members": [],
    }


def _bounded_strings(values: Iterable[Any]) -> tuple[list[str], int]:
    accepted: set[str] = set()
    dropped = 0
    for value in values:
        if not isinstance(value, str) or len(value) < 2 or len(value) > 512:
            dropped += 1
            continue
        accepted.add(value)
    return sorted(accepted), dropped


def _compact_side(side: dict[str, Any] | None) -> dict[str, Any] | None:
    if side is None:
        return None
    return {
        "address": side["address"],
        "raw_name": side["raw_name"],
        "name": side["name"],
        "name_source": side["name_source"],
        "body_size": side["body_size"],
        "instruction_count": side["instruction_count"],
        "normalized_hash": side["normalized_hash"],
        "mnemonic_hash": side["mnemonic_hash"],
        "branch_count": side["branch_count"],
        "compare_count": side["compare_count"],
        "call_count": side["call_count"],
        "return_count": side["return_count"],
        "caller_count": len(side["callers"]),
        "callee_count": len(side["callees"]),
        "warning_count": len(side["warnings"]),
        "record_offset": side["record_offset"],
        "record_length": side["record_length"],
    }


def _relationship_address(value: str) -> str:
    return value.rsplit("@", 1)[-1].lower().removeprefix("0x")


def _identifier_terms(value: str) -> set[str]:
    expanded = _CAMEL_BOUNDARY.sub(" ", value.replace("_", " ").replace("-", " "))
    return {word.lower() for word in _WORDS.findall(expanded)}


def _advisory_terms(value: str) -> set[str]:
    return {word for word in _identifier_terms(value) if word not in _STOP_WORDS}


def _hash_lines(values: Iterable[str]) -> str:
    digest = hashlib.sha256()
    for value in values:
        digest.update(value.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _consistent(current: str | None, candidate: Any, label: str) -> str:
    if not isinstance(candidate, str) or not candidate:
        raise DiffError(f"missing {label} identity")
    if current is not None and current != candidate:
        raise DiffError(f"inconsistent {label} identity")
    return candidate


def _optional_input(path: str | Path | None) -> tuple[Path | None, str | None]:
    if path is None:
        return None, None
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise DiffError(f"optional diff input does not exist: {resolved}")
    digest, _ = _digest_file(resolved)
    return resolved, digest


def _cache_key(
    old_export_sha256: str,
    new_export_sha256: str,
    old_symbol_sha256: str | None,
    new_symbol_sha256: str | None,
    advisory_text: str,
    settings: DiffSettings,
) -> str:
    payload = json.dumps(
        {
            "engine_version": DIFF_ENGINE_VERSION,
            "old_export_sha256": old_export_sha256,
            "new_export_sha256": new_export_sha256,
            "old_symbol_sha256": old_symbol_sha256,
            "new_symbol_sha256": new_symbol_sha256,
            "advisory_text_sha256": hashlib.sha256(advisory_text.encode("utf-8")).hexdigest(),
            "settings": asdict(settings),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
