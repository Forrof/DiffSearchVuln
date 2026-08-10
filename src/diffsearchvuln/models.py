from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


SCHEMA_VERSION = "1.0.0"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class AnalysisMode(StrEnum):
    ADVISORY_GUIDED = "advisory_guided"
    BLIND_DISCOVERY = "blind_discovery"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CandidateKind(StrEnum):
    MODIFIED = "modified"
    ADDED = "added"
    DELETED = "deleted"
    LOW_CONFIDENCE_MATCH = "low_confidence_match"
    DATA_ONLY = "data_only"
    CALL_GRAPH_NEIGHBOR = "call_graph_neighbor"


class FindingState(StrEnum):
    CANDIDATE = "candidate"
    LIKELY_PATCH = "likely_patch"
    BEHAVIORALLY_VALIDATED = "behaviorally_validated"
    PATCH_NOT_LOCALIZED = "patch_not_localized"


@dataclass(frozen=True)
class ToolVersion:
    name: str
    version: str
    path: str


@dataclass(frozen=True)
class ArtifactIdentity:
    sha256: str
    byte_size: int
    architecture: str
    cpu_subtype: str | None = None
    macho_uuid: str | None = None
    parent_sha256: str | None = None


@dataclass(frozen=True)
class FunctionIdentity:
    component_sha256: str
    address: str
    name: str | None = None


@dataclass(frozen=True)
class CandidateCluster:
    cluster_id: str
    component_key: str
    primary_function: FunctionIdentity
    related_functions: tuple[FunctionIdentity, ...] = ()
    candidate_kinds: tuple[CandidateKind, ...] = ()
    deterministic_score: float = 0.0
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AnalysisManifest:
    job_id: str
    run_id: str
    mode: AnalysisMode
    old_artifact: ArtifactIdentity
    new_artifact: ArtifactIdentity
    tools: tuple[ToolVersion, ...]
    settings: dict[str, Any]
    advisory: dict[str, Any] | None = None
    schema_version: str = SCHEMA_VERSION
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["mode"] = self.mode.value
        return value


@dataclass(frozen=True)
class RankedCandidate:
    cluster_id: str
    rank: int
    absolute_score: float
    advanced: bool
    explanation: str


@dataclass(frozen=True)
class TournamentDecision:
    group_id: str
    pass_index: int
    round_index: int
    no_strong_candidate: bool
    ranking: tuple[RankedCandidate, ...]
    model: str
    prompt_version: str
    schema_version: str = SCHEMA_VERSION
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not 2 <= len(self.ranking) <= 5:
            raise ValueError("a tournament group must rank between two and five candidates")
        ranks = sorted(candidate.rank for candidate in self.ranking)
        if ranks != list(range(1, len(self.ranking) + 1)):
            raise ValueError("candidate ranks must be contiguous and start at one")
        advanced = [candidate for candidate in self.ranking if candidate.advanced]
        if len(advanced) != min(2, len(self.ranking)):
            raise ValueError("exactly the top two candidates must advance")
        if any(candidate.rank > 2 for candidate in advanced):
            raise ValueError("only rank one and rank two may advance")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
