# Implementation plan

## Phase 1: foundation — complete

- Record architecture and threat boundaries.
- Define versioned JSON schemas for manifests, function dossiers, and tournament
  decisions.
- Create the SQLite metadata schema with migrations.
- Implement a setup doctor for host architecture, Xcode, Python, Java, Ghidra,
  Codex authentication, and required Apple tooling.
- Add deterministic unit tests.

Exit condition: tests pass and the doctor identifies every missing or mismatched
dependency without exposing credentials.

## Phase 2: manual Mach-O analysis — complete

- Import an old/new Mach-O pair into the immutable version vault.
- Capture SHA-256, Mach-O slice, UUID, and code-signing provenance.
- Run Ghidra headlessly with pinned settings and isolated projects.
- Export complete, deterministic function dossiers.
- Cache all stage outputs and resume interrupted jobs.

Exit condition: both rclone fixtures import and decompile reproducibly without
executing either binary.

Acceptance evidence is recorded in [PHASE2_RESULTS.md](PHASE2_RESULTS.md).

## Phase 3: semantic diff and candidates — complete

- Integrate the first deterministic Ghidra-export matching adapter while
  retaining an engine-independent boundary for a later Ghidriff adapter.
- Add normalized matching, call relationships, added/deleted functions,
  low-confidence matches, strings/imports, and compiler-noise indicators.
- Generate high-recall candidate clusters and deterministic pre-rank scores.
- Compare results against the public source patch oracle.

Exit condition: the rclone ground-truth cluster enters the tournament pool.

Acceptance evidence is recorded in [PHASE3_RESULTS.md](PHASE3_RESULTS.md).

## Phase 4: Codex tournament — core acceptance complete

- Connect through local Codex app-server using the existing ChatGPT login. ✓
- Version structured prompts and validate structured responses. ✓
- Run isolated groups, two grouping passes, top-two advancement, and independent
  final adjudication. ✓
- Preserve complete finalist evidence, audit logs, thread/turn identifiers, token
  usage, deterministic grouping, pause/resume, and `patch_not_localized`
  handling. ✓
- Add evidence-linked chunking for inputs beyond the configured prompt limit and
  expose user pin/restore overrides in the application. These are UI-era
  hardening items; no evidence is currently discarded when a prompt is too large.

Exit condition: rclone's ground-truth cluster reaches the final two and Codex
correctly describes the fix. Met by the bounded Phase 4 acceptance pilot.

Acceptance evidence is recorded in [PHASE4_RESULTS.md](PHASE4_RESULTS.md).

## Phase 5: native macOS application

- Create the strict, versioned local worker protocol. ✓
- Create and live-test the native Swift IPC client. ✓
- Create and build the native SwiftUI application with a reproducible XcodeGen
  project. ✓
- Implement overview, products, candidate ranking, old/new evidence, and local
  storage settings views. ✓
- Inspect completed tournaments, finalists, final patch analyses, observed
  evidence, inferences, and bypass hypotheses. ✓
- Implement releases, asynchronous jobs, tournament execution/overrides, and
  report-generation views.
- Add native progress, cancellation, resumption, notifications, and Keychain
  access.
- Let the vault and analysis cache live on independently selected external
  volumes, with volume-identity and free-space preflight checks.

Exit condition: the complete rclone workflow can be driven without the CLI.

Current implementation and runtime evidence are recorded in
[PHASE5_PROGRESS.md](PHASE5_PROGRESS.md).

## Phase 6: `.app` bundles

- Inventory nested code and compare matching components.
- Rank changed Mach-O components before function tournaments.
- Add optional symbols, dSYMs, and source/commit enrichment.
- Validate with KeePassXC.

Exit condition: the expected KeePassXC patch cluster reaches the final two.

## Phase 7: update tracking and acquisition

- Add Apple security release, Sparkle, GitHub Release, and configurable URL
  adapters.
- Preserve historical versions, signatures, channels, and provenance.
- Check at launch and through an optional daily LaunchAgent.
- Download and inventory automatically; require an explicit job start for deep
  analysis.

Exit condition: a configured public product detects, verifies, archives, and
pairs a new adjacent release.

## Phase 8: discovery and research output

- Add blind security-change hypotheses for memory safety, path handling,
  authorization, parsing, injection, cryptography, and sandbox boundaries.
- Add deep patch explanation, cross-component reopening, bypass hypotheses, and
  approved local regression-test generation.
- Generate reports from per-case user instructions and structured evidence.
- Validate noisy multi-fix behavior with Helm.

Exit condition: guided and blind jobs are auditable, resumable, and explicitly
separate observed evidence from model hypotheses.

## Deferred work

- Windows PE support and non-Apple architectures.
- DMG/PKG acquisition beyond extraction needed for `.app` fixtures.
- IPSW and dyld shared-cache system-binary backend.
- Additional diff engines such as BinDiff, Diaphora, and BSim.
- Managed dependency bundles, Developer ID signing, and notarization.
- Automated proof-of-concept execution.
