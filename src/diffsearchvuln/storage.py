from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from .models import AnalysisMode, JobStatus, utc_now


DATABASE_SCHEMA_VERSION = 1


MIGRATION_1_SQL = """
CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    vendor TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS update_sources (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    configuration_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS releases (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    build TEXT NOT NULL DEFAULT '',
    channel TEXT NOT NULL DEFAULT 'stable',
    architecture TEXT NOT NULL,
    distribution_source TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    UNIQUE(product_id, version, build, channel, architecture, distribution_source)
);

CREATE TABLE IF NOT EXISTS artifacts (
    sha256 TEXT PRIMARY KEY,
    storage_path TEXT NOT NULL,
    byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
    media_type TEXT NOT NULL,
    parent_sha256 TEXT REFERENCES artifacts(sha256),
    signature_json TEXT NOT NULL DEFAULT '{}',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS release_artifacts (
    release_id TEXT NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    artifact_sha256 TEXT NOT NULL REFERENCES artifacts(sha256),
    role TEXT NOT NULL,
    PRIMARY KEY (release_id, artifact_sha256, role)
);

CREATE TABLE IF NOT EXISTS analysis_jobs (
    id TEXT PRIMARY KEY,
    product_id TEXT REFERENCES products(id) ON DELETE SET NULL,
    old_release_id TEXT REFERENCES releases(id),
    new_release_id TEXT REFERENCES releases(id),
    old_artifact_sha256 TEXT REFERENCES artifacts(sha256),
    new_artifact_sha256 TEXT REFERENCES artifacts(sha256),
    mode TEXT NOT NULL CHECK (mode IN ('advisory_guided', 'blind_discovery')),
    advisory_json TEXT,
    report_instructions TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analysis_runs (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    grouping_seed INTEGER NOT NULL,
    settings_json TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS candidate_clusters (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
    component_key TEXT NOT NULL,
    primary_function_key TEXT NOT NULL,
    candidate_kinds_json TEXT NOT NULL,
    deterministic_score REAL NOT NULL,
    evidence_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tournament_groups (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
    pass_index INTEGER NOT NULL CHECK (pass_index >= 0),
    round_index INTEGER NOT NULL CHECK (round_index >= 0),
    group_index INTEGER NOT NULL CHECK (group_index >= 0),
    status TEXT NOT NULL,
    UNIQUE(run_id, pass_index, round_index, group_index)
);

CREATE TABLE IF NOT EXISTS tournament_entries (
    group_id TEXT NOT NULL REFERENCES tournament_groups(id) ON DELETE CASCADE,
    candidate_id TEXT NOT NULL REFERENCES candidate_clusters(id) ON DELETE CASCADE,
    rank INTEGER,
    absolute_score REAL,
    advanced INTEGER CHECK (advanced IN (0, 1)),
    explanation TEXT,
    PRIMARY KEY (group_id, candidate_id)
);

CREATE TABLE IF NOT EXISTS codex_interactions (
    id TEXT PRIMARY KEY,
    group_id TEXT REFERENCES tournament_groups(id) ON DELETE SET NULL,
    purpose TEXT NOT NULL,
    model TEXT NOT NULL,
    thread_id TEXT,
    prompt_version TEXT NOT NULL,
    request_manifest_json TEXT NOT NULL,
    response_json TEXT,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS user_overrides (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
    candidate_id TEXT NOT NULL REFERENCES candidate_clusters(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_releases_product ON releases(product_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON analysis_jobs(status);
CREATE INDEX IF NOT EXISTS idx_runs_job ON analysis_runs(job_id);
CREATE INDEX IF NOT EXISTS idx_candidates_run ON candidate_clusters(run_id);
CREATE INDEX IF NOT EXISTS idx_groups_run_round
    ON tournament_groups(run_id, pass_index, round_index);
"""


MIGRATIONS = {1: MIGRATION_1_SQL}


class Storage:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_meta "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            row = connection.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            current_version = int(row["value"]) if row else 0
            if current_version > DATABASE_SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema {current_version} is newer than supported "
                    f"schema {DATABASE_SCHEMA_VERSION}"
                )
            for target_version in range(current_version + 1, DATABASE_SCHEMA_VERSION + 1):
                migration = MIGRATIONS[target_version]
                connection.executescript(
                    "BEGIN IMMEDIATE;\n"
                    f"{migration}\n"
                    "INSERT INTO schema_meta(key, value) "
                    f"VALUES('schema_version', '{target_version}') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value;\n"
                    "COMMIT;"
                )

    def schema_version(self) -> int | None:
        if not self.path.exists():
            return None
        with self.connect() as connection:
            try:
                row = connection.execute(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                ).fetchone()
            except sqlite3.OperationalError:
                return None
        return int(row["value"]) if row else None

    def create_product(self, name: str, vendor: str | None = None) -> str:
        product_id = str(uuid4())
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO products(id, name, vendor, created_at) VALUES(?, ?, ?, ?)",
                (product_id, name, vendor, utc_now()),
            )
        return product_id

    def list_products(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, name, vendor, created_at FROM products ORDER BY name, id"
            ).fetchall()
        return [dict(row) for row in rows]

    def record_artifact(
        self,
        *,
        sha256: str,
        storage_path: str,
        byte_size: int,
        media_type: str,
        signature: dict[str, Any],
        provenance: dict[str, Any],
        parent_sha256: str | None = None,
    ) -> None:
        timestamp = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO artifacts(
                    sha256, storage_path, byte_size, media_type, parent_sha256,
                    signature_json, provenance_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sha256) DO NOTHING
                """,
                (
                    sha256,
                    storage_path,
                    byte_size,
                    media_type,
                    parent_sha256,
                    json.dumps(signature, sort_keys=True),
                    json.dumps(provenance, sort_keys=True),
                    timestamp,
                ),
            )
            row = connection.execute(
                """
                SELECT storage_path, byte_size, media_type, parent_sha256
                FROM artifacts WHERE sha256 = ?
                """,
                (sha256,),
            ).fetchone()
            actual = (
                row["storage_path"],
                row["byte_size"],
                row["media_type"],
            )
            immutable_expected = (storage_path, byte_size, media_type)
            if actual != immutable_expected:
                raise ValueError(f"artifact {sha256} conflicts with its immutable database record")
            existing_parent = row["parent_sha256"]
            if existing_parent is None and parent_sha256 is not None:
                connection.execute(
                    "UPDATE artifacts SET parent_sha256 = ? WHERE sha256 = ?",
                    (parent_sha256, sha256),
                )
            elif parent_sha256 is not None and existing_parent != parent_sha256:
                raise ValueError(f"artifact {sha256} already has a different immutable parent")

    def get_artifact(self, sha256: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM artifacts WHERE sha256 = ?", (sha256,)
            ).fetchone()
        if row is None:
            return None
        artifact = dict(row)
        artifact["signature"] = json.loads(artifact.pop("signature_json"))
        artifact["provenance"] = json.loads(artifact.pop("provenance_json"))
        return artifact

    def create_analysis_job(
        self,
        *,
        mode: AnalysisMode,
        product_id: str | None = None,
        old_release_id: str | None = None,
        new_release_id: str | None = None,
        old_artifact_sha256: str | None = None,
        new_artifact_sha256: str | None = None,
        advisory: dict[str, Any] | None = None,
        report_instructions: str | None = None,
    ) -> str:
        job_id = str(uuid4())
        timestamp = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO analysis_jobs(
                    id, product_id, old_release_id, new_release_id,
                    old_artifact_sha256, new_artifact_sha256, mode, advisory_json,
                    report_instructions, status, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    product_id,
                    old_release_id,
                    new_release_id,
                    old_artifact_sha256,
                    new_artifact_sha256,
                    mode.value,
                    json.dumps(advisory, sort_keys=True) if advisory is not None else None,
                    report_instructions,
                    JobStatus.QUEUED.value,
                    timestamp,
                    timestamp,
                ),
            )
        return job_id
