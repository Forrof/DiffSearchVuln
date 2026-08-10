from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Mapping, Sequence
from uuid import uuid4

from .macho import _digest_file


class GhidraError(RuntimeError):
    pass


@dataclass(frozen=True)
class GhidraSettings:
    analysis_timeout_seconds: int = 1800
    process_timeout_seconds: int = 14400
    function_timeout_seconds: int = 30
    max_cpu: int = 4
    max_functions: int = 0

    def __post_init__(self) -> None:
        if self.analysis_timeout_seconds < 1:
            raise ValueError("analysis timeout must be positive")
        if self.process_timeout_seconds < self.analysis_timeout_seconds:
            raise ValueError("process timeout must not be shorter than analysis timeout")
        if self.function_timeout_seconds < 1:
            raise ValueError("function timeout must be positive")
        if self.max_cpu < 1:
            raise ValueError("max_cpu must be positive")
        if self.max_functions < 0:
            raise ValueError("max_functions must be zero or positive")


@dataclass(frozen=True)
class GhidraAnalysisResult:
    cache_key: str
    cache_path: str
    project_path: str
    dossier_path: str
    dossier_sha256: str
    function_count: int
    ghidra_version: str
    artifact_sha256: str
    architecture: str
    cached: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


Executor = Callable[[Sequence[str], Mapping[str, str], Path, int], int]


def _default_executor(
    command: Sequence[str], environment: Mapping[str, str], log_path: Path, timeout: int
) -> int:
    with log_path.open("w", encoding="utf-8") as log:
        try:
            completed = subprocess.run(
                list(command),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                env=dict(environment),
                timeout=timeout,
                check=False,
            )
            return completed.returncode
        except subprocess.TimeoutExpired:
            log.write(f"\nDiffSearchVuln process timeout after {timeout} seconds\n")
            return 124


class GhidraRunner:
    def __init__(
        self,
        *,
        analysis_root: str | Path,
        ghidra_root: str | Path = "/opt/homebrew/opt/ghidra/libexec",
        java_home: str | Path = "/opt/homebrew/opt/openjdk@21",
        script_path: str | Path | None = None,
        executor: Executor = _default_executor,
    ) -> None:
        self.analysis_root = Path(analysis_root).expanduser().resolve()
        self.ghidra_root = Path(ghidra_root).expanduser().resolve()
        self.java_home = Path(java_home).expanduser().resolve()
        self.script_path = (
            Path(script_path).expanduser().resolve()
            if script_path
            else Path(__file__).resolve().parents[2] / "ghidra_scripts"
        )
        self.executor = executor

    def analyze(
        self,
        artifact_path: str | Path,
        *,
        artifact_sha256: str,
        architecture: str,
        settings: GhidraSettings | None = None,
    ) -> GhidraAnalysisResult:
        settings = settings or GhidraSettings()
        artifact = Path(artifact_path).expanduser().resolve()
        self._validate_environment(artifact, artifact_sha256, architecture)
        ghidra_version = self._ghidra_version()
        script = self.script_path / "ExportFunctionDossiers.java"
        script_sha256, _ = _digest_file(script)
        cache_key = self._cache_key(
            artifact_sha256,
            architecture,
            ghidra_version,
            script_sha256,
            settings,
        )
        final_directory = self.analysis_root / "completed" / cache_key
        cached = self._load_cached(final_directory)
        if cached is not None:
            return cached

        locks = self.analysis_root / ".locks"
        staging_root = self.analysis_root / "staging"
        failed_root = self.analysis_root / "failed"
        for directory in (locks, staging_root, failed_root, final_directory.parent):
            directory.mkdir(parents=True, exist_ok=True)
        lock_path = locks / f"{cache_key}.lock"
        lock_descriptor: int | None = None
        try:
            try:
                lock_descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError as error:
                raise GhidraError(f"analysis is already running for cache key {cache_key}") from error
            os.write(lock_descriptor, str(os.getpid()).encode("ascii"))

            staging = staging_root / f"{cache_key}-{uuid4()}"
            staging.mkdir()
            project_directory = staging / "project"
            project_directory.mkdir()
            dossier_path = staging / "functions.jsonl"
            console_log_path = staging / "console.log"
            application_log_path = staging / "application.log"
            script_log_path = staging / "script.log"
            command = self._command(
                artifact,
                project_directory,
                dossier_path,
                application_log_path,
                script_log_path,
                artifact_sha256,
                architecture,
                settings,
            )
            environment = dict(os.environ)
            environment.update(
                {
                    "JAVA_HOME": str(self.java_home),
                    "LC_ALL": "C",
                    "LANG": "C",
                }
            )
            started_at = datetime.now(UTC).isoformat()
            return_code = self.executor(
                command,
                environment,
                console_log_path,
                settings.process_timeout_seconds,
            )
            if return_code != 0 or not dossier_path.is_file():
                failure_detail = self._combined_log_tail(
                    console_log_path, application_log_path, script_log_path
                )
                self._preserve_failure(
                    staging,
                    failed_root,
                    cache_key,
                    return_code,
                    started_at,
                    command,
                )
                raise GhidraError(
                    f"Ghidra analysis failed with exit code {return_code}: {failure_detail}"
                )

            dossier_sha256, _ = _digest_file(dossier_path)
            function_count = _count_jsonl_records(dossier_path)
            if function_count == 0:
                self._preserve_failure(
                    staging,
                    failed_root,
                    cache_key,
                    return_code,
                    started_at,
                    command,
                )
                raise GhidraError("Ghidra exported no function dossiers")
            manifest = {
                "schema_version": "1.0.0",
                "status": "completed",
                "cache_key": cache_key,
                "artifact_sha256": artifact_sha256,
                "architecture": architecture,
                "ghidra_version": ghidra_version,
                "script_sha256": script_sha256,
                "settings": asdict(settings),
                "command": list(command),
                "started_at": started_at,
                "completed_at": datetime.now(UTC).isoformat(),
                "analysis_timed_out": self._logs_indicate_analysis_timeout(
                    console_log_path, application_log_path
                ),
                "function_count": function_count,
                "dossier_sha256": dossier_sha256,
            }
            _write_json(staging / "manifest.json", manifest)
            try:
                os.rename(staging, final_directory)
            except FileExistsError:
                shutil.rmtree(staging)
                cached_result = self._load_cached(final_directory)
                if cached_result is None:
                    raise GhidraError(f"invalid concurrent cache result for {cache_key}")
                return cached_result
            return self._result_from_manifest(final_directory, manifest, cached=False)
        finally:
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            lock_path.unlink(missing_ok=True)

    def _validate_environment(self, artifact: Path, sha256: str, architecture: str) -> None:
        if not artifact.is_file():
            raise GhidraError(f"artifact does not exist: {artifact}")
        actual_sha256, _ = _digest_file(artifact)
        if actual_sha256 != sha256:
            raise GhidraError("artifact digest does not match the requested analysis identity")
        if architecture not in {"arm64", "arm64e"}:
            raise GhidraError(f"unsupported analysis architecture: {architecture}")
        required = (
            self.ghidra_root / "support/analyzeHeadless",
            self.java_home / "bin/java",
            self.script_path / "ExportFunctionDossiers.java",
        )
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            raise GhidraError(f"missing Ghidra analysis dependency: {', '.join(missing)}")

    def _ghidra_version(self) -> str:
        properties = self.ghidra_root / "Ghidra/application.properties"
        for line in properties.read_text(encoding="utf-8").splitlines():
            if line.startswith("application.version="):
                return line.split("=", 1)[1].strip()
        raise GhidraError(f"could not determine Ghidra version from {properties}")

    @staticmethod
    def _cache_key(
        artifact_sha256: str,
        architecture: str,
        ghidra_version: str,
        script_sha256: str,
        settings: GhidraSettings,
    ) -> str:
        payload = json.dumps(
            {
                "artifact_sha256": artifact_sha256,
                "architecture": architecture,
                "ghidra_version": ghidra_version,
                "script_sha256": script_sha256,
                "settings": asdict(settings),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _command(
        self,
        artifact: Path,
        project_directory: Path,
        dossier_path: Path,
        application_log_path: Path,
        script_log_path: Path,
        artifact_sha256: str,
        architecture: str,
        settings: GhidraSettings,
    ) -> list[str]:
        return [
            str(self.ghidra_root / "support/analyzeHeadless"),
            str(project_directory),
            "analysis",
            "-import",
            str(artifact),
            "-analysisTimeoutPerFile",
            str(settings.analysis_timeout_seconds),
            "-max-cpu",
            str(settings.max_cpu),
            "-scriptPath",
            str(self.script_path),
            "-postScript",
            "ExportFunctionDossiers.java",
            str(dossier_path),
            artifact_sha256,
            architecture,
            str(settings.max_functions),
            str(settings.function_timeout_seconds),
            "-log",
            str(application_log_path),
            "-scriptlog",
            str(script_log_path),
        ]

    def _load_cached(self, directory: Path) -> GhidraAnalysisResult | None:
        manifest_path = directory / "manifest.json"
        dossier_path = directory / "functions.jsonl"
        if not manifest_path.is_file() or not dossier_path.is_file():
            return None
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            dossier_sha256, _ = _digest_file(dossier_path)
            if manifest.get("status") != "completed" or dossier_sha256 != manifest.get("dossier_sha256"):
                return None
            if _count_jsonl_records(dossier_path) != manifest.get("function_count"):
                return None
            return self._result_from_manifest(directory, manifest, cached=True)
        except (OSError, ValueError, json.JSONDecodeError):
            return None

    @staticmethod
    def _result_from_manifest(
        directory: Path, manifest: dict[str, object], *, cached: bool
    ) -> GhidraAnalysisResult:
        return GhidraAnalysisResult(
            cache_key=str(manifest["cache_key"]),
            cache_path=str(directory),
            project_path=str(directory / "project"),
            dossier_path=str(directory / "functions.jsonl"),
            dossier_sha256=str(manifest["dossier_sha256"]),
            function_count=int(manifest["function_count"]),
            ghidra_version=str(manifest["ghidra_version"]),
            artifact_sha256=str(manifest["artifact_sha256"]),
            architecture=str(manifest["architecture"]),
            cached=cached,
        )

    @staticmethod
    def _preserve_failure(
        staging: Path,
        failed_root: Path,
        cache_key: str,
        return_code: int,
        started_at: str,
        command: Sequence[str],
    ) -> None:
        _write_json(
            staging / "failure.json",
            {
                "schema_version": "1.0.0",
                "status": "failed",
                "cache_key": cache_key,
                "return_code": return_code,
                "started_at": started_at,
                "failed_at": datetime.now(UTC).isoformat(),
                "command": list(command),
            },
        )
        os.rename(staging, failed_root / f"{cache_key}-{uuid4()}")

    @staticmethod
    def _log_tail(path: Path, maximum: int = 4000) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")[-maximum:]
        except OSError:
            return "headless log unavailable"

    @classmethod
    def _combined_log_tail(cls, *paths: Path) -> str:
        return "\n".join(f"[{path.name}]\n{cls._log_tail(path)}" for path in paths)

    @staticmethod
    def _logs_indicate_analysis_timeout(*paths: Path) -> bool:
        for path in paths:
            try:
                lowered = path.read_text(encoding="utf-8", errors="replace").lower()
            except OSError:
                continue
            if "analysis" in lowered and "timed out" in lowered:
                return True
        return False


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _count_jsonl_records(path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8") as records:
        for line in records:
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict) or value.get("schema_version") != "1.0.0":
                raise ValueError("invalid function export record")
            count += 1
    return count
