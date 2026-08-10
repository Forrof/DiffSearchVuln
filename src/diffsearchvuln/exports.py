from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class ExportValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExportStatistics:
    path: str
    function_count: int
    decompilation_successes: int
    decompilation_failures: int
    warning_count: int
    instruction_count: int
    language_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def validate_function_export(
    path: str | Path,
    *,
    expected_artifact_sha256: str | None = None,
    expected_architecture: str | None = None,
) -> ExportStatistics:
    export_path = Path(path).expanduser().resolve()
    if not export_path.is_file():
        raise ExportValidationError(f"function export does not exist: {export_path}")

    addresses: set[str] = set()
    languages: set[str] = set()
    decompilation_successes = 0
    decompilation_failures = 0
    warning_count = 0
    instruction_count = 0
    function_count = 0

    with export_path.open("r", encoding="utf-8") as records:
        for line_number, line in enumerate(records, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ExportValidationError(
                    f"line {line_number} is not valid JSON: {error}"
                ) from error
            _validate_record(
                record,
                line_number=line_number,
                expected_artifact_sha256=expected_artifact_sha256,
                expected_architecture=expected_architecture,
            )
            function = record["function"]
            address = function["address"]
            if address in addresses:
                raise ExportValidationError(
                    f"line {line_number} repeats function address {address}"
                )
            addresses.add(address)
            languages.add(record["language_id"])
            if function["decompilation"] is None:
                decompilation_failures += 1
            else:
                decompilation_successes += 1
            warning_count += len(record["warnings"])
            instruction_count += len(function["instructions"])
            function_count += 1

    if function_count == 0:
        raise ExportValidationError("function export contains no records")
    return ExportStatistics(
        path=str(export_path),
        function_count=function_count,
        decompilation_successes=decompilation_successes,
        decompilation_failures=decompilation_failures,
        warning_count=warning_count,
        instruction_count=instruction_count,
        language_ids=tuple(sorted(languages)),
    )


def _validate_record(
    record: Any,
    *,
    line_number: int,
    expected_artifact_sha256: str | None,
    expected_architecture: str | None,
) -> None:
    if not isinstance(record, dict):
        raise ExportValidationError(f"line {line_number} must contain a JSON object")
    required = {
        "schema_version",
        "artifact_sha256",
        "architecture",
        "ghidra_version",
        "program_name",
        "language_id",
        "compiler_spec_id",
        "function",
        "warnings",
    }
    missing = required - record.keys()
    if missing:
        raise ExportValidationError(
            f"line {line_number} is missing fields: {', '.join(sorted(missing))}"
        )
    if record["schema_version"] != "1.0.0":
        raise ExportValidationError(f"line {line_number} has an unsupported schema version")
    if expected_artifact_sha256 and record["artifact_sha256"] != expected_artifact_sha256:
        raise ExportValidationError(f"line {line_number} has the wrong artifact identity")
    if expected_architecture and record["architecture"] != expected_architecture:
        raise ExportValidationError(f"line {line_number} has the wrong architecture")
    if expected_architecture in {"arm64", "arm64e"} and not record["language_id"].startswith(
        "AARCH64:"
    ):
        raise ExportValidationError(
            f"line {line_number} labels {expected_architecture} as {record['language_id']}"
        )
    function = record["function"]
    if not isinstance(function, dict):
        raise ExportValidationError(f"line {line_number} has no function object")
    function_fields = {
        "address",
        "name",
        "qualified_name",
        "namespace",
        "body_size",
        "parameter_count",
        "calling_convention",
        "thunk",
        "external",
        "decompilation",
        "instructions",
        "callers",
        "callees",
        "strings",
        "imports",
    }
    missing_function_fields = function_fields - function.keys()
    if missing_function_fields:
        raise ExportValidationError(
            f"line {line_number} function is missing fields: "
            f"{', '.join(sorted(missing_function_fields))}"
        )
    for array_field in ("instructions", "callers", "callees", "strings", "imports"):
        if not isinstance(function[array_field], list):
            raise ExportValidationError(
                f"line {line_number} function field {array_field} must be an array"
            )
    if not isinstance(record["warnings"], list):
        raise ExportValidationError(f"line {line_number} warnings must be an array")
