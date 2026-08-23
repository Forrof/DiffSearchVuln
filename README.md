# DiffSearchVuln

DiffSearchVuln is a local, macOS-first patch-diffing workbench for authorized
bug-bounty research. It tracks releases, compares Apple Silicon Mach-O binaries
with Ghidra, narrows changed code through reproducible five-candidate Codex
tournaments, and preserves the evidence needed to understand a security patch
and investigate possible bypasses.

## What the app is for

DiffSearchVuln helps an authorized vulnerability researcher or vendor-security
engineer answer five questions about adjacent software releases:

1. What security-relevant code actually changed in the shipped binaries?
2. Which changed functions most likely implement the announced patch?
3. Does the old behavior reproduce, and does the patched build block it?
4. Does the patched and latest release still permit a distinct boundary
   violation under controlled testing?
5. Is the same patched function, or a semantically similar implementation,
   reachable elsewhere without an equivalent security check?

The native app organizes products and release-pair workspaces, presents exact
function diffs and reproducible tournament decisions, explains before/after
flows, and exposes a deliberately gated Exploit Lab for contained local proof.
It is evidence tooling, not a live-target scanner, autonomous exploit launcher,
or substitute for researcher review.

The intended users are independent bug-bounty researchers, vendor/project
security engineers, reviewers who audit the evidence trail, and the trusted
operator of the dedicated research Mac. It is not designed for untrusted
multi-tenant use. See the complete [user and application threat
model](docs/THREAT_MODEL.md).

Phases one through four have met their core acceptance conditions. The
repository now includes the architecture, versioned interchange schemas,
SQLite storage, setup doctor, immutable artifact vault, safe Mach-O
inspection/thinning, and cached deterministic Ghidra function exports. It also
recovers Go pclntab names, matches old/new functions, ranks semantic change
candidates, builds directly related function clusters, and runs two-pass,
five-candidate Codex tournaments with an independent final adjudication and
deep patch analysis. Finalist analysis also performs a whole-export sibling
search: it enumerates direct call sites of the patched function, ranks similar
implementations using shared callees/imports/strings/name terms, records exact
coverage and omissions, and turns missing or uncertain checks into dynamic test
targets. The first versioned native-worker protocol is implemented;
its Swift client library builds and passes live cross-language tests. A native
SwiftUI application now connects to that worker and provides persistent,
separately selectable analysis workspaces. Each workspace groups Summary,
Function Diff, Tournament, and Findings tabs; it also records binary provenance
and presents explicit vulnerable-before, patched-now, and possible-bypass
findings. The function view highlights removed lines in red and added lines in
green, while the Findings view includes before/after flow graphs. Each analysis
also has an Exploit Lab for safe local simulation and recording controlled test
attempts without automatically launching imported binaries. An explicit button
can send the complete preserved patch evidence to a fresh, ChatGPT-authenticated
Codex app-server turn; Codex may build and run helper harnesses only in a
network-disabled attempt directory. A live native activity sheet follows its
analysis milestones, helper commands, artifact changes, completion, and errors;
the full structured audit and activity stream are retained with the attempt.
Completed repository cases can include an `app-analysis.json` manifest. The
native app discovers those manifests at launch and upserts their exact diff and
tournament paths into the selector while preserving existing Exploit Lab notes.
Release tracking and the complete tournament/job UI are not yet implemented.

## Current quick start

Requirements:

- macOS on Apple Silicon
- Python 3.12
- OpenJDK 21
- Ghidra 12.1.2
- Codex CLI authenticated with ChatGPT
- Full Xcode for the later SwiftUI application

Run the checks without installing the package:

```bash
PYTHONPATH=src /opt/homebrew/bin/python3.12 -m diffsearchvuln doctor
PYTHONPATH=src /opt/homebrew/bin/python3.12 -m unittest discover -s tests -v
```

Initialize a local development database:

```bash
PYTHONPATH=src /opt/homebrew/bin/python3.12 -m diffsearchvuln init-store \
  --path ./diffsearchvuln.sqlite3
```

The doctor can also run a real Ghidra headless import smoke test:

```bash
PYTHONPATH=src /opt/homebrew/bin/python3.12 -m diffsearchvuln doctor --deep
```

Inspect and import a manually supplied Mach-O without executing it:

```bash
PYTHONPATH=src /opt/homebrew/bin/python3.12 -m diffsearchvuln inspect-mach-o \
  --path /path/to/binary

PYTHONPATH=src /opt/homebrew/bin/python3.12 -m diffsearchvuln import-artifact \
  --path /path/to/binary \
  --vault ./artifacts \
  --database ./diffsearchvuln.sqlite3
```

The original archive can be preserved first and linked as the binary's parent:

```bash
PYTHONPATH=src /opt/homebrew/bin/python3.12 -m diffsearchvuln import-file \
  --path /path/to/download.zip \
  --media-type application/zip \
  --vault /Volumes/AnalysisSSD/DiffSearchVuln/vault \
  --database ./diffsearchvuln.sqlite3

PYTHONPATH=src /opt/homebrew/bin/python3.12 -m diffsearchvuln import-artifact \
  --path /path/to/extracted-binary \
  --parent-sha256 SHA256_OF_DOWNLOAD \
  --vault /Volumes/AnalysisSSD/DiffSearchVuln/vault \
  --database ./diffsearchvuln.sqlite3
```

Universal binaries must be materialized to one exact architecture before
analysis, preventing Ghidra from silently choosing a different slice:

```bash
PYTHONPATH=src /opt/homebrew/bin/python3.12 -m diffsearchvuln thin-mach-o \
  --path /path/to/universal-binary \
  --architecture arm64 \
  --output /path/to/derived-arm64-binary
```

Run a cached Ghidra function export:

```bash
PYTHONPATH=src /opt/homebrew/bin/python3.12 -m diffsearchvuln analyze-mach-o \
  --path /path/to/thin-arm64-binary \
  --architecture arm64 \
  --analysis-root ./ghidra-projects
```

For Go binaries, recover pclntab names and then rank the semantic diff:

```bash
PYTHONPATH=src /opt/homebrew/bin/python3.12 -m diffsearchvuln extract-go-symbols \
  --path /path/to/thin-arm64-binary \
  --cache-root /Volumes/AnalysisSSD/DiffSearchVuln/go-symbols

PYTHONPATH=src /opt/homebrew/bin/python3.12 -m diffsearchvuln diff-exports \
  --old-export /path/to/old/functions.jsonl \
  --new-export /path/to/new/functions.jsonl \
  --old-symbols /path/to/old/symbols.jsonl \
  --new-symbols /path/to/new/symbols.jsonl \
  --output-root /Volumes/AnalysisSSD/DiffSearchVuln/diffs \
  --advisory-file /path/to/advisory.txt
```

Run the Codex tournament over the ranked pool. Each group is isolated and all
prompts, structured decisions, thread identifiers, timing, and token usage are
preserved under the output root:

```bash
PYTHONPATH=src /opt/homebrew/bin/python3.12 -m diffsearchvuln run-tournament \
  --diff-directory /path/to/completed/diff \
  --output-root /Volumes/AnalysisSSD/DiffSearchVuln/tournaments \
  --advisory-file /path/to/advisory.txt \
  --pool-limit 25
```

Repeating an identical completed run validates and returns the cached final
analysis without making another Codex call.

Start the local JSON Lines worker used by the future native application:

```bash
PYTHONPATH=src /opt/homebrew/bin/python3.12 -m diffsearchvuln worker
```

Build and test the native client library with the command-line Swift toolchain:

```bash
cd macos/DiffSearchVulnCore
swift test
```

Generate and build the native application with Xcode 26.6:

```bash
cd macos/DiffSearchVulnApp
xcodegen generate
xcodebuild -project DiffSearchVuln.xcodeproj \
  -scheme DiffSearchVuln \
  -destination 'platform=macOS,arch=arm64' \
  CODE_SIGNING_ALLOWED=NO build
```

## Design documents

- [Architecture](docs/ARCHITECTURE.md)
- [User and application threat model](docs/THREAT_MODEL.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Research references and acceptance fixtures](docs/REFERENCES.md)
- [Phase 2 acceptance results](docs/PHASE2_RESULTS.md)
- [Phase 3 acceptance results](docs/PHASE3_RESULTS.md)
- [Phase 4 acceptance results](docs/PHASE4_RESULTS.md)
- [Native worker protocol](docs/IPC_PROTOCOL.md)
- [Phase 5 application progress](docs/PHASE5_PROGRESS.md)
- [Analysis manifest schema](schemas/analysis-manifest.schema.json)
- [Function dossier schema](schemas/function-dossier.schema.json)
- [Function export schema](schemas/function-export.schema.json)
- [Candidate cluster schema](schemas/candidate-cluster.schema.json)
- [Tournament decision schema](schemas/tournament-decision.schema.json)
- [Final analysis schema](schemas/final-analysis.schema.json)
- [IPC request schema](schemas/ipc-request.schema.json)
- [IPC response schema](schemas/ipc-response.schema.json)
- [Swift worker client](macos/DiffSearchVulnCore/Sources/DiffSearchVulnCore/WorkerClient.swift)
- [Native app project specification](macos/DiffSearchVulnApp/project.yml)

## Safety boundary

Imported binaries are hostile input. DiffSearchVuln never launches one as a side
effect of import or static analysis. The explicit Findings campaign may stage
the selected old/new pair in a disposable directory on a dedicated research
Mac. Each target runs through macOS sandbox-exec with networking denied, user
files unreadable, writes confined to the disposable directory, sanitized
environment variables, resource/time limits, and a hash check immediately
before execution. Codex receives only narrow dynamic tools; the command audit
is sealed outside its writable directory until the turn ends. UTM remains an
optional stronger isolation mode.
