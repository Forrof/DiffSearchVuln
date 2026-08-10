from __future__ import annotations

import argparse
import json
from pathlib import Path

from .codex_client import CodexAppServerClient, CodexClientError
from .diffing import DiffError, DiffSettings, SemanticDiffRunner
from .dossiers import CandidateCatalog, DossierError, write_dossier
from .doctor import CheckStatus, EnvironmentDoctor
from .exports import ExportValidationError, validate_function_export
from .ghidra import GhidraError, GhidraRunner, GhidraSettings
from .ipc import serve_stdio
from .macho import MachOError, MachOInspector
from .storage import Storage
from .symbols import GoSymbolExtractor, SymbolError
from .tournament import TournamentError, TournamentRunner, TournamentSettings
from .vault import ArtifactVault, VaultError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="diffsearchvuln")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "worker", help="serve the versioned native-app protocol over JSON Lines"
    )

    doctor = subparsers.add_parser("doctor", help="validate the local analysis toolchain")
    doctor.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    doctor.add_argument("--deep", action="store_true", help="run a real Ghidra Mach-O import")

    init_store = subparsers.add_parser("init-store", help="initialize a local SQLite store")
    init_store.add_argument("--path", type=Path, required=True)

    schema_version = subparsers.add_parser("schema-version", help="print a store schema version")
    schema_version.add_argument("--path", type=Path, required=True)

    inspect_macho = subparsers.add_parser("inspect-mach-o", help="inspect a Mach-O without executing it")
    inspect_macho.add_argument("--path", type=Path, required=True)

    thin_macho = subparsers.add_parser(
        "thin-mach-o", help="materialize one architecture from a universal Mach-O"
    )
    thin_macho.add_argument("--path", type=Path, required=True)
    thin_macho.add_argument("--architecture", choices=("arm64", "arm64e"), required=True)
    thin_macho.add_argument("--output", type=Path, required=True)

    import_artifact = subparsers.add_parser(
        "import-artifact", help="copy a Mach-O into the immutable local vault"
    )
    import_artifact.add_argument("--path", type=Path, required=True)
    import_artifact.add_argument("--vault", type=Path, required=True)
    import_artifact.add_argument("--database", type=Path, required=True)
    import_artifact.add_argument("--source-url")
    import_artifact.add_argument("--version")
    import_artifact.add_argument("--build")
    import_artifact.add_argument("--parent-sha256")

    import_file = subparsers.add_parser(
        "import-file", help="copy any original download into the immutable local vault"
    )
    import_file.add_argument("--path", type=Path, required=True)
    import_file.add_argument("--vault", type=Path, required=True)
    import_file.add_argument("--database", type=Path, required=True)
    import_file.add_argument("--media-type", required=True)
    import_file.add_argument("--source-url")
    import_file.add_argument("--version")
    import_file.add_argument("--build")

    analyze_macho = subparsers.add_parser(
        "analyze-mach-o", help="run a cached Ghidra function export"
    )
    analyze_macho.add_argument("--path", type=Path, required=True)
    analyze_macho.add_argument("--analysis-root", type=Path, required=True)
    analyze_macho.add_argument("--architecture", choices=("arm64", "arm64e"), default="arm64")
    analyze_macho.add_argument("--analysis-timeout", type=int, default=1800)
    analyze_macho.add_argument("--process-timeout", type=int, default=14400)
    analyze_macho.add_argument("--function-timeout", type=int, default=30)
    analyze_macho.add_argument("--max-cpu", type=int, default=4)
    analyze_macho.add_argument("--max-functions", type=int, default=0)

    validate_export = subparsers.add_parser(
        "validate-export", help="stream and validate a Ghidra function export"
    )
    validate_export.add_argument("--path", type=Path, required=True)
    validate_export.add_argument("--artifact-sha256")
    validate_export.add_argument("--architecture", choices=("arm64", "arm64e"))

    extract_symbols = subparsers.add_parser(
        "extract-go-symbols", help="recover Go pclntab function names without executing the binary"
    )
    extract_symbols.add_argument("--path", type=Path, required=True)
    extract_symbols.add_argument("--cache-root", type=Path, required=True)
    extract_symbols.add_argument("--timeout", type=int, default=300)

    diff_exports = subparsers.add_parser(
        "diff-exports", help="match two Ghidra function exports and rank changed candidates"
    )
    diff_exports.add_argument("--old-export", type=Path, required=True)
    diff_exports.add_argument("--new-export", type=Path, required=True)
    diff_exports.add_argument("--old-symbols", type=Path)
    diff_exports.add_argument("--new-symbols", type=Path)
    diff_exports.add_argument("--output-root", type=Path, required=True)
    advisory = diff_exports.add_mutually_exclusive_group()
    advisory.add_argument("--advisory-text", default="")
    advisory.add_argument("--advisory-file", type=Path)
    diff_exports.add_argument("--tournament-pool-size", type=int, default=500)
    diff_exports.add_argument("--max-cluster-members", type=int, default=8)

    list_candidates = subparsers.add_parser(
        "list-candidates", help="print compact top candidates from a semantic diff"
    )
    list_candidates.add_argument("--path", type=Path, required=True)
    list_candidates.add_argument("--limit", type=int, default=20)

    materialize_candidate = subparsers.add_parser(
        "materialize-candidate", help="recover complete old/new evidence for one candidate"
    )
    materialize_candidate.add_argument("--diff-directory", type=Path, required=True)
    materialize_candidate.add_argument("--candidate-id", required=True)
    materialize_candidate.add_argument("--include-related", type=int, default=0)
    materialize_candidate.add_argument("--output", type=Path, required=True)

    run_tournament = subparsers.add_parser(
        "run-tournament", help="run two five-candidate Codex tournament passes"
    )
    run_tournament.add_argument("--diff-directory", type=Path, required=True)
    run_tournament.add_argument("--output-root", type=Path, required=True)
    tournament_advisory = run_tournament.add_mutually_exclusive_group(required=True)
    tournament_advisory.add_argument("--advisory-text")
    tournament_advisory.add_argument("--advisory-file", type=Path)
    run_tournament.add_argument("--pool-limit", type=int, default=25)
    run_tournament.add_argument("--include-related", type=int, default=0)
    run_tournament.add_argument("--max-prompt-characters", type=int, default=600_000)
    run_tournament.add_argument("--model")
    run_tournament.add_argument("--effort", default="high")
    run_tournament.add_argument("--turn-timeout", type=int, default=900)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "worker":
        return serve_stdio()
    if args.command == "doctor":
        report = EnvironmentDoctor().run(deep=args.deep)
        if args.json:
            print(report.to_json())
        else:
            for check in report.checks:
                marker = {
                    CheckStatus.PASS: "PASS",
                    CheckStatus.WARN: "WARN",
                    CheckStatus.FAIL: "FAIL",
                }[check.status]
                suffix = f" ({check.version})" if check.version else ""
                print(f"[{marker}] {check.name}: {check.summary}{suffix}")
                if check.detail:
                    print(f"       {check.detail}")
                if check.path:
                    print(f"       {check.path}")
        return 0 if report.ok else 1

    if args.command == "init-store":
        storage = Storage(args.path)
        storage.initialize()
        print(f"initialized {storage.path} at schema version {storage.schema_version()}")
        return 0

    if args.command == "schema-version":
        version = Storage(args.path).schema_version()
        print("uninitialized" if version is None else version)
        return 0 if version is not None else 1
    if args.command == "inspect-mach-o":
        try:
            inspection = MachOInspector().inspect(args.path)
        except MachOError as error:
            print(json.dumps({"error": str(error)}, indent=2))
            return 1
        print(json.dumps(inspection.to_dict(), indent=2, sort_keys=True))
        return 0
    if args.command == "thin-mach-o":
        try:
            inspection = MachOInspector().materialize_slice(
                args.path, args.architecture, args.output
            )
        except MachOError as error:
            print(json.dumps({"error": str(error)}, indent=2))
            return 1
        print(json.dumps(inspection.to_dict(), indent=2, sort_keys=True))
        return 0
    if args.command == "import-artifact":
        try:
            vault_artifact = ArtifactVault(args.vault).import_file(args.path)
            inspection = MachOInspector().inspect(vault_artifact.storage_path)
            storage = Storage(args.database)
            storage.initialize()
            provenance = {
                key: value
                for key, value in {
                    "source_path": str(args.path.expanduser().resolve()),
                    "source_url": args.source_url,
                    "version": args.version,
                    "build": args.build,
                }.items()
                if value is not None
            }
            storage.record_artifact(
                sha256=vault_artifact.sha256,
                storage_path=vault_artifact.storage_path,
                byte_size=vault_artifact.byte_size,
                media_type="application/x-mach-binary",
                signature=inspection.to_dict()["signature"],
                provenance=provenance,
                parent_sha256=args.parent_sha256,
            )
        except (MachOError, VaultError, ValueError) as error:
            print(json.dumps({"error": str(error)}, indent=2))
            return 1
        print(
            json.dumps(
                {
                    "artifact": vault_artifact.to_dict(),
                    "inspection": inspection.to_dict(),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "import-file":
        try:
            vault_artifact = ArtifactVault(args.vault).import_file(args.path)
            storage = Storage(args.database)
            storage.initialize()
            provenance = {
                key: value
                for key, value in {
                    "source_path": str(args.path.expanduser().resolve()),
                    "source_url": args.source_url,
                    "version": args.version,
                    "build": args.build,
                }.items()
                if value is not None
            }
            storage.record_artifact(
                sha256=vault_artifact.sha256,
                storage_path=vault_artifact.storage_path,
                byte_size=vault_artifact.byte_size,
                media_type=args.media_type,
                signature={},
                provenance=provenance,
            )
        except (VaultError, ValueError) as error:
            print(json.dumps({"error": str(error)}, indent=2))
            return 1
        print(json.dumps({"artifact": vault_artifact.to_dict()}, indent=2, sort_keys=True))
        return 0
    if args.command == "analyze-mach-o":
        try:
            inspection = MachOInspector().inspect(args.path)
            architectures = {item.architecture for item in inspection.slices}
            if args.architecture not in architectures:
                raise GhidraError(
                    f"requested architecture {args.architecture} is not present; "
                    f"available slices: {', '.join(sorted(architectures))}"
                )
            if inspection.universal:
                raise GhidraError(
                    "universal Mach-O inputs must be thinned with thin-mach-o before Ghidra analysis"
                )
            result = GhidraRunner(analysis_root=args.analysis_root).analyze(
                args.path,
                artifact_sha256=inspection.sha256,
                architecture=args.architecture,
                settings=GhidraSettings(
                    analysis_timeout_seconds=args.analysis_timeout,
                    process_timeout_seconds=args.process_timeout,
                    function_timeout_seconds=args.function_timeout,
                    max_cpu=args.max_cpu,
                    max_functions=args.max_functions,
                ),
            )
        except (GhidraError, MachOError, ValueError) as error:
            print(json.dumps({"error": str(error)}, indent=2))
            return 1
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0
    if args.command == "validate-export":
        try:
            statistics = validate_function_export(
                args.path,
                expected_artifact_sha256=args.artifact_sha256,
                expected_architecture=args.architecture,
            )
        except ExportValidationError as error:
            print(json.dumps({"error": str(error)}, indent=2))
            return 1
        print(json.dumps(statistics.to_dict(), indent=2, sort_keys=True))
        return 0
    if args.command == "extract-go-symbols":
        try:
            inspection = MachOInspector().inspect(args.path)
            if inspection.universal:
                raise SymbolError("universal Mach-O inputs must be thinned before symbol extraction")
            result = GoSymbolExtractor(cache_root=args.cache_root).extract(
                args.path,
                artifact_sha256=inspection.sha256,
                timeout_seconds=args.timeout,
            )
        except (MachOError, SymbolError, ValueError) as error:
            print(json.dumps({"error": str(error)}, indent=2))
            return 1
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0
    if args.command == "diff-exports":
        try:
            advisory_text = args.advisory_text
            if args.advisory_file:
                advisory_text = args.advisory_file.read_text(encoding="utf-8")
            result = SemanticDiffRunner(output_root=args.output_root).diff(
                args.old_export,
                args.new_export,
                old_symbols=args.old_symbols,
                new_symbols=args.new_symbols,
                advisory_text=advisory_text,
                settings=DiffSettings(
                    tournament_pool_size=args.tournament_pool_size,
                    max_cluster_members=args.max_cluster_members,
                ),
            )
        except (DiffError, OSError, UnicodeError, ValueError) as error:
            print(json.dumps({"error": str(error)}, indent=2))
            return 1
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0
    if args.command == "list-candidates":
        if args.limit < 1:
            print(json.dumps({"error": "limit must be positive"}, indent=2))
            return 1
        try:
            candidates = []
            with args.path.expanduser().resolve().open("r", encoding="utf-8") as records:
                for line in records:
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    candidates.append(
                        {
                            "rank": record["deterministic_rank"],
                            "score": record["deterministic_score"],
                            "kind": record["match_kind"],
                            "name": record["primary_name"],
                            "candidate_id": record["candidate_id"],
                            "advisory_terms": record["change_evidence"][
                                "advisory_terms_matched"
                            ],
                            "cluster_members": record["cluster_members"],
                        }
                    )
                    if len(candidates) >= args.limit:
                        break
        except (OSError, KeyError, json.JSONDecodeError) as error:
            print(json.dumps({"error": str(error)}, indent=2))
            return 1
        print(json.dumps(candidates, indent=2, sort_keys=True))
        return 0
    if args.command == "materialize-candidate":
        try:
            dossier = CandidateCatalog.load(args.diff_directory).compact_evidence(
                args.candidate_id,
                include_related=args.include_related,
                include_instructions=True,
            )
            write_dossier(args.output, dossier)
        except (DossierError, OSError, ValueError) as error:
            print(json.dumps({"error": str(error)}, indent=2))
            return 1
        print(json.dumps({"output": str(args.output.expanduser().resolve())}, indent=2))
        return 0
    if args.command == "run-tournament":
        try:
            advisory_text = args.advisory_text
            if args.advisory_file:
                advisory_text = args.advisory_file.read_text(encoding="utf-8")
            assert advisory_text is not None
            with CodexAppServerClient() as codex:
                result = TournamentRunner(
                    output_root=args.output_root,
                    codex=codex,
                ).run(
                    args.diff_directory,
                    advisory_text=advisory_text,
                    settings=TournamentSettings(
                        pool_limit=args.pool_limit,
                        include_related_per_candidate=args.include_related,
                        max_prompt_characters=args.max_prompt_characters,
                        model=args.model,
                        effort=args.effort,
                        turn_timeout_seconds=args.turn_timeout,
                    ),
                )
        except (
            CodexClientError,
            DossierError,
            OSError,
            TournamentError,
            UnicodeError,
            ValueError,
        ) as error:
            print(json.dumps({"error": str(error)}, indent=2))
            return 1
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0
    return 2
