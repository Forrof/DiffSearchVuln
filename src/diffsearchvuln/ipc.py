from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TextIO

from . import __version__
from .codex_client import CodexAppServerClient
from .doctor import EnvironmentDoctor
from .dossiers import CandidateCatalog
from .exploit_lab import (
    load_latest_codex_exploit_attempt,
    run_codex_exploit_attempt,
)
from .storage import Storage
from .tournament import validate_final_analysis


PROTOCOL_VERSION = "1.0.0"
MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 67_108_864
_CANDIDATE_ID = re.compile(r"^[a-f0-9]{64}$")


class IPCError(RuntimeError):
    def __init__(self, code: str, message: str, *, data: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


@dataclass(frozen=True)
class Request:
    request_id: str
    method: str
    params: dict[str, Any]


class WorkerService:
    def __init__(
        self,
        *,
        doctor_factory: Callable[[], EnvironmentDoctor] = EnvironmentDoctor,
        storage_factory: Callable[[str | Path], Storage] = Storage,
        catalog_loader: Callable[[str | Path], CandidateCatalog] = CandidateCatalog.load,
        codex_factory: Callable[[], CodexAppServerClient] = CodexAppServerClient,
    ) -> None:
        self.doctor_factory = doctor_factory
        self.storage_factory = storage_factory
        self.catalog_loader = catalog_loader
        self.codex_factory = codex_factory
        self._catalogs: dict[Path, CandidateCatalog] = {}

    def dispatch(self, value: Any) -> dict[str, Any]:
        request_id = value.get("id") if isinstance(value, dict) else None
        try:
            request = _parse_request(value)
            result = self._invoke(request.method, request.params)
            return _success(request.request_id, result)
        except IPCError as error:
            return _failure(request_id, error)
        except (OSError, RuntimeError, UnicodeError, ValueError) as error:
            return _failure(
                request_id,
                IPCError("operation_failed", str(error) or type(error).__name__),
            )
        except Exception:
            return _failure(
                request_id,
                IPCError("internal_error", "the worker could not complete the request"),
            )

    def _invoke(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "system.hello": self._hello,
            "system.doctor": self._doctor,
            "store.initialize": self._initialize_store,
            "products.list": self._list_products,
            "products.create": self._create_product,
            "candidates.list": self._list_candidates,
            "candidate.evidence": self._candidate_evidence,
            "tournament.inspect": self._inspect_tournament,
            "exploit.codex_attempt": self._codex_exploit_attempt,
            "exploit.latest": self._latest_exploit_attempt,
        }
        handler = handlers.get(method)
        if handler is None:
            raise IPCError("method_not_found", f"unknown worker method: {method}")
        return handler(params)

    def _hello(self, params: dict[str, Any]) -> dict[str, Any]:
        _validate_params(params, allowed=set())
        return {
            "worker_version": __version__,
            "protocol_version": PROTOCOL_VERSION,
            "capabilities": [
                "candidate_evidence",
                "candidate_paging",
                "environment_doctor",
                "controlled_codex_exploit_attempt",
                "contained_host_dynamic_testing",
                "disposable_utm_dynamic_testing",
                "local_products",
                "tournament_inspection",
            ],
            "safety_mode": "static_by_default_explicit_contained_dynamic",
        }

    def _doctor(self, params: dict[str, Any]) -> dict[str, Any]:
        _validate_params(params, allowed={"deep"})
        deep = params.get("deep", False)
        if not isinstance(deep, bool):
            raise IPCError("invalid_params", "deep must be a boolean")
        return self.doctor_factory().run(deep=deep).to_dict()

    def _initialize_store(self, params: dict[str, Any]) -> dict[str, Any]:
        _validate_params(params, allowed={"database"}, required={"database"})
        storage = self._storage(params["database"])
        storage.initialize()
        return {"database": str(storage.path), "schema_version": storage.schema_version()}

    def _list_products(self, params: dict[str, Any]) -> dict[str, Any]:
        _validate_params(params, allowed={"database"}, required={"database"})
        storage = self._storage(params["database"])
        storage.initialize()
        products = storage.list_products()
        return {"products": products, "count": len(products)}

    def _create_product(self, params: dict[str, Any]) -> dict[str, Any]:
        _validate_params(
            params,
            allowed={"database", "name", "vendor"},
            required={"database", "name"},
        )
        name = _nonempty_string(params["name"], "name")
        vendor_value = params.get("vendor")
        if vendor_value is not None and not isinstance(vendor_value, str):
            raise IPCError("invalid_params", "vendor must be a string or null")
        vendor = vendor_value.strip() if isinstance(vendor_value, str) else None
        storage = self._storage(params["database"])
        storage.initialize()
        product_id = storage.create_product(name, vendor or None)
        product = next(
            product for product in storage.list_products() if product["id"] == product_id
        )
        return {"product": product}

    def _list_candidates(self, params: dict[str, Any]) -> dict[str, Any]:
        _validate_params(
            params,
            allowed={"diff_directory", "offset", "limit"},
            required={"diff_directory"},
        )
        offset = _integer(params.get("offset", 0), "offset", minimum=0)
        limit = _integer(params.get("limit", 50), "limit", minimum=1, maximum=200)
        catalog = self._catalog(params["diff_directory"])
        candidates = list(catalog.page(offset=offset, limit=limit))
        return {
            "diff_cache_key": catalog.manifest["cache_key"],
            "offset": offset,
            "limit": limit,
            "total_count": catalog.candidate_count,
            "candidates": candidates,
        }

    def _candidate_evidence(self, params: dict[str, Any]) -> dict[str, Any]:
        _validate_params(
            params,
            allowed={
                "diff_directory",
                "candidate_id",
                "include_related",
                "include_instructions",
            },
            required={"diff_directory", "candidate_id"},
        )
        candidate_id = _nonempty_string(params["candidate_id"], "candidate_id")
        if _CANDIDATE_ID.fullmatch(candidate_id) is None:
            raise IPCError("invalid_params", "candidate_id must be a lowercase SHA-256 value")
        include_related = _integer(
            params.get("include_related", 0),
            "include_related",
            minimum=0,
            maximum=8,
        )
        include_instructions = params.get("include_instructions", False)
        if not isinstance(include_instructions, bool):
            raise IPCError("invalid_params", "include_instructions must be a boolean")
        catalog = self._catalog(params["diff_directory"])
        evidence = catalog.compact_evidence(
            candidate_id,
            include_related=include_related,
            include_instructions=include_instructions,
        )
        return {"evidence": evidence}

    def _storage(self, value: Any) -> Storage:
        return self.storage_factory(_path_string(value, "database"))

    def _inspect_tournament(self, params: dict[str, Any]) -> dict[str, Any]:
        _validate_params(
            params,
            allowed={"run_directory"},
            required={"run_directory"},
        )
        run_path = Path(
            _path_string(params["run_directory"], "run_directory")
        ).expanduser().resolve()
        state = _read_json_object(run_path / "state.json", "tournament state")
        finalist_ids_value = state.get("finalist_ids")
        if (
            not isinstance(finalist_ids_value, list)
            or any(not isinstance(value, str) for value in finalist_ids_value)
        ):
            raise IPCError("operation_failed", "tournament state has invalid finalists")
        finalist_ids = tuple(finalist_ids_value)
        analysis_path = run_path / "final-analysis/analysis.json"
        analysis: dict[str, Any] | None = None
        if analysis_path.is_file():
            analysis = _read_json_object(analysis_path, "final analysis")
            validate_final_analysis(analysis, finalist_ids)
            if state.get("final_analysis") != analysis:
                raise IPCError(
                    "operation_failed",
                    "tournament state and final analysis disagree",
                )
        elif state.get("status") == "completed":
            raise IPCError("operation_failed", "completed tournament has no final analysis")
        required = {
            "run_key": str,
            "status": str,
            "diff_cache_key": str,
            "model": str,
            "pool_ids": list,
        }
        for field, expected_type in required.items():
            if not isinstance(state.get(field), expected_type):
                raise IPCError(
                    "operation_failed", f"tournament state has invalid {field}"
                )
        run = {
            "schema_version": state.get("schema_version", "1.0.0"),
            "run_key": state["run_key"],
            "run_path": str(run_path),
            "status": state["status"],
            "diff_cache_key": state["diff_cache_key"],
            "model": state["model"],
            "pool_count": len(state["pool_ids"]),
            "group_count": int(state.get("group_count", 0)),
            "codex_call_count": int(state.get("codex_call_count", 0)),
            "reused_decision_count": int(state.get("reused_decision_count", 0)),
            "finalist_ids": list(finalist_ids),
            "pass_finalists": state.get("pass_finalists", []),
            "started_at": state.get("started_at"),
            "completed_at": state.get("completed_at"),
            "final_analysis": analysis,
        }
        return {"run": run}

    def _codex_exploit_attempt(self, params: dict[str, Any]) -> dict[str, Any]:
        _validate_params(
            params,
            allowed={"run_directory", "analysis_context", "attempt_id"},
            required={"run_directory", "analysis_context"},
        )
        run_directory = _path_string(params["run_directory"], "run_directory")
        context = _analysis_context(params["analysis_context"])
        attempt_id_value = params.get("attempt_id")
        attempt_id = (
            _nonempty_string(attempt_id_value, "attempt_id")
            if attempt_id_value is not None
            else None
        )
        codex = self.codex_factory()
        codex.start()
        try:
            attempt = run_codex_exploit_attempt(
                run_directory=run_directory,
                analysis_context=context,
                codex=codex,
                attempt_id=attempt_id,
            )
        finally:
            codex.close()
        return {"attempt": attempt}

    def _latest_exploit_attempt(self, params: dict[str, Any]) -> dict[str, Any]:
        _validate_params(
            params,
            allowed={"run_directory"},
            required={"run_directory"},
        )
        run_directory = _path_string(params["run_directory"], "run_directory")
        return {"attempt": load_latest_codex_exploit_attempt(run_directory)}

    def _catalog(self, value: Any) -> CandidateCatalog:
        path = Path(_path_string(value, "diff_directory")).expanduser().resolve()
        catalog = self._catalogs.get(path)
        if catalog is None:
            catalog = self.catalog_loader(path)
            self._catalogs[path] = catalog
        return catalog


def serve(
    input_stream: TextIO,
    output_stream: TextIO,
    *,
    service: WorkerService | None = None,
) -> int:
    service = service or WorkerService()
    for line in input_stream:
        if not line.strip():
            continue
        if len(line.encode("utf-8")) > MAX_REQUEST_BYTES:
            response = _failure(
                None,
                IPCError(
                    "request_too_large",
                    f"request exceeds the {MAX_REQUEST_BYTES}-byte protocol limit",
                ),
            )
        else:
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                response = _failure(
                    None,
                    IPCError(
                        "parse_error",
                        "request is not valid JSON",
                        data={"line": error.lineno, "column": error.colno},
                    ),
                )
            else:
                response = service.dispatch(value)
        encoded = json.dumps(response, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_RESPONSE_BYTES:
            encoded = json.dumps(
                _failure(
                    response.get("id"),
                    IPCError(
                        "response_too_large",
                        f"response exceeds the {MAX_RESPONSE_BYTES}-byte protocol limit",
                    ),
                ),
                sort_keys=True,
                separators=(",", ":"),
            )
        output_stream.write(encoded + "\n")
        output_stream.flush()
    return 0


def serve_stdio() -> int:
    return serve(sys.stdin, sys.stdout)


def _parse_request(value: Any) -> Request:
    if not isinstance(value, dict):
        raise IPCError("invalid_request", "request must be a JSON object")
    expected = {"protocol_version", "id", "method", "params"}
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unexpected = sorted(set(value) - expected)
        raise IPCError(
            "invalid_request",
            "request fields do not match the protocol",
            data={"missing": missing, "unexpected": unexpected},
        )
    if value["protocol_version"] != PROTOCOL_VERSION:
        raise IPCError(
            "protocol_mismatch",
            f"worker requires protocol version {PROTOCOL_VERSION}",
            data={"supported": [PROTOCOL_VERSION]},
        )
    request_id = _nonempty_string(value["id"], "id")
    method = _nonempty_string(value["method"], "method")
    params = value["params"]
    if not isinstance(params, dict):
        raise IPCError("invalid_request", "params must be a JSON object")
    return Request(request_id, method, params)


def _validate_params(
    params: dict[str, Any],
    *,
    allowed: set[str],
    required: set[str] | None = None,
) -> None:
    required = required or set()
    missing = sorted(required - set(params))
    unexpected = sorted(set(params) - allowed)
    if missing or unexpected:
        raise IPCError(
            "invalid_params",
            "method parameters do not match the contract",
            data={"missing": missing, "unexpected": unexpected},
        )


def _nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IPCError("invalid_params", f"{field} must be a non-empty string")
    return value.strip()


def _path_string(value: Any, field: str) -> str:
    result = _nonempty_string(value, field)
    if "\0" in result:
        raise IPCError("invalid_params", f"{field} contains a null byte")
    return result


def _integer(
    value: Any,
    field: str,
    *,
    minimum: int,
    maximum: int | None = None,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise IPCError("invalid_params", f"{field} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        suffix = f" and at most {maximum}" if maximum is not None else ""
        raise IPCError("invalid_params", f"{field} must be at least {minimum}{suffix}")
    return value


def _analysis_context(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise IPCError("invalid_params", "analysis_context must be an object")
    allowed = {
        "analysis_title",
        "provenance",
        "source_url",
        "selected_hypothesis",
        "test_input",
        "expected_outcome",
        "lab_notes",
        "execution_mode",
        "vm_identifier",
    }
    unexpected = sorted(set(value) - allowed)
    if unexpected:
        raise IPCError(
            "invalid_params",
            "analysis_context contains unexpected fields",
            data={"unexpected": unexpected},
        )
    result: dict[str, str] = {}
    for field in sorted(allowed):
        default = "simulation" if field == "execution_mode" else ""
        field_value = value.get(field, default)
        if not isinstance(field_value, str):
            raise IPCError("invalid_params", f"analysis_context.{field} must be a string")
        if len(field_value) > 100_000:
            raise IPCError("invalid_params", f"analysis_context.{field} is too large")
        result[field] = field_value
    return result


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise IPCError("operation_failed", f"missing {label}: {path}") from error
    except (OSError, json.JSONDecodeError) as error:
        raise IPCError("operation_failed", f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise IPCError("operation_failed", f"{label} must be a JSON object")
    return value


def _success(request_id: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "id": request_id,
        "result": result,
    }


def _failure(request_id: Any, error: IPCError) -> dict[str, Any]:
    value: dict[str, Any] = {
        "protocol_version": PROTOCOL_VERSION,
        "id": request_id if isinstance(request_id, str) else None,
        "error": {"code": error.code, "message": error.message},
    }
    if error.data is not None:
        value["error"]["data"] = error.data
    return value
