# DiffSearchVuln architecture

## Product boundary

DiffSearchVuln is a personal, local macOS application for authorized bug-bounty
research. Its first supported artifacts are Apple Silicon Mach-O files and
`.app` bundles. Direct file-pair import is always available. Automated tracking
will initially cover Apple security releases, Sparkle feeds, GitHub Releases,
and user-defined URLs.

The application supports two analysis modes:

1. **Advisory-guided localization** uses a CVE, advisory URL, or pasted text to
   search a version diff for a described vulnerability.
2. **Blind discovery** reviews unexplained changes across vulnerability-class
   hypotheses. This comes after the guided workflow is validated.

The binary diff is authoritative for what shipped. Source code, commits,
dSYMs, symbols, and reports are optional enrichment.

## System shape

```text
SwiftUI application
  |-- products, releases, comparisons, tournament, findings
  |-- macOS notifications and Keychain-backed source credentials
  |
  `-- local structured IPC
        |
        `-- Python analysis worker
              |-- version vault + SQLite metadata
              |-- artifact/signature inspection
              |-- Ghidra headless adapter
              |-- normalized diff/candidate engine
              |-- Codex app-server client
              `-- report evidence API
```

SwiftUI owns user interaction and presentation. The Python worker owns
long-running jobs, immutable analysis records, external-tool orchestration, and
resumption. IPC messages are versioned JSON objects; the UI never parses raw
Ghidra or Codex output.

Protocol `1.0.0` uses strict JSON Lines over a launched worker's standard input
and output. Requests and responses carry correlation IDs, protocol mismatches
fail explicitly, and oversized evidence is rejected rather than truncated. The
initial methods cover environment checks, local products, candidate paging, and
exact evidence materialization. Long-running jobs will add progress events and
cancellation without changing those request semantics. See
[IPC_PROTOCOL.md](IPC_PROTOCOL.md). The native Swift client already launches and
validates this worker; the SwiftUI presentation target remains pending full
Xcode.

## Artifact lifecycle

1. A release is detected or two artifacts are manually imported.
2. The original download is stored immutably and hashed with SHA-256.
3. The app records source URL, version/build, release channel, architecture,
   download time, file size, Mach-O UUIDs, and code-signing metadata.
4. Universal files are split logically into matching architecture/subtype
   slices before Ghidra import. `arm64` and `arm64e` are never compared with
   `x86_64`, and the exporter rejects a Ghidra language that disagrees with the
   requested slice.
5. `.app` bundles are inventoried for the main executable, frameworks, dylibs,
   helpers, plug-ins, and extensions.
6. Matching components are analyzed out of process by a pinned Ghidra version.
7. Ghidra exports deterministic function dossiers rather than UI-specific data.
8. Raw diff results are cached and reused by separately auditable analysis runs.

Stable, beta, nightly, regional, and distribution-specific releases are
separate channels. Cross-channel comparisons require an explicit override.

## Function dossiers and matching

The initial adapter uses custom Ghidra export scripts plus a deterministic,
streaming matcher. Ghidriff remains a planned alternative adapter behind the
same engine-independent schema. Go binaries receive optional static pclntab
name enrichment when Ghidra's bundled Go analyzer does not support the compiler
version. A dossier can include:

- function address, symbol/name, size, and match confidence;
- full old/new decompilation and normalized instruction or p-code summaries;
- changed basic blocks and control-flow features;
- strings, imports, exports, parameters, and return information;
- one-hop callers and callees;
- added, deleted, low-confidence, data-only, and inlining indicators;
- analyzer warnings and timeouts.

Candidate generation favors recall. Noise can be suppressed but never deleted.
The analysis unit is a candidate cluster: a primary changed function with the
directly relevant changed callers/callees. Multi-function fixes remain valid
results.

## Five-candidate tournament

For each advisory or blind-discovery hypothesis:

1. Deterministic signals pre-rank all candidate clusters.
2. Two tournament passes create different balanced groups of at most five.
3. Every group is analyzed in a fresh Codex thread.
4. Codex assigns absolute security-relevance scores, ranks the group, explains
   its evidence, and advances the top two.
5. Groups with no compelling candidate are labeled `no_strong_candidate`, but
   still advance two for recall.
6. Survivors are regrouped until each pass has at most two finalists.
7. The union of both passes is reviewed by an independent final adjudicator.
8. Eliminated candidates remain recoverable, and user overrides are recorded
   separately from model decisions.

If complete functions exceed usable context, each function is analyzed in
deterministic evidence-linked chunks. The tournament consumes the summaries,
while the complete function remains available for follow-up.

The system may conclude `patch_not_localized`. It must never convert weak
relative winners into a fabricated high-confidence result.

## Codex boundary

Codex runs through a locally authenticated Codex CLI/app-server session. Ghidra
and the original artifacts remain on the Mac, but selected decompiled evidence
is processed by OpenAI. DiffSearchVuln may send approved analysis context
without a per-request confirmation. It sends only the candidate dossier needed
for the active decision.

Each group uses an isolated thread. The recorded interaction includes the model,
prompt/template version, input dossier hashes, structured response, timing, and
thread identifier. Binary text is treated as untrusted data, never as agent
instructions.

## Patch and bypass analysis

After adjudication, Codex analyzes the final clusters to explain:

- the vulnerable behavior and attack preconditions;
- the intended security invariant;
- how the new version enforces that invariant;
- relevant changes across functions or components;
- residual assumptions and plausible bypass hypotheses;
- direct callers of the patched function and whether they preserve the invariant;
- similar implementations elsewhere and whether they carry an equivalent check;
- whole-export scan coverage, omitted evidence, and unresolved review gaps;
- proposed local regression tests.

The sibling search is deterministic and scans the complete patched function
export before Codex analysis. Call-graph relationships and similarity signals
are labeled `OBSERVED`; the conclusion about whether an equivalent invariant is
present remains an analytical classification. Full sibling decompilation is
bounded for prompt safety, and every omitted record is preserved as an
unresolved coverage gap rather than being treated as reviewed. Missing and
uncertain sibling checks are added to the contained dynamic test campaign.

Deep analysis can reopen eliminated functions and query the complete cached diff.
Findings have three states: `candidate`, `likely_patch`, and
`behaviorally_validated`. Only an approved, reproducible old-versus-new test can
reach the final state. Imported artifacts are never executed automatically.

## Storage and audit trail

SQLite stores products, sources, releases, jobs, analysis runs, candidates,
tournament groups, decisions, overrides, and report instructions. Large
artifacts and Ghidra projects live in a content-addressed directory.

Every run records:

- original and derived artifact hashes with parent relationships;
- signature and provenance metadata;
- tool versions and analyzer settings;
- advisory inputs and extracted hypotheses;
- candidate groups, seeds, prompts, scores, responses, and overrides;
- incomplete stages, warnings, and failure causes.

No evidence is silently deleted. Users control per-product retention. Source
credentials live only in macOS Keychain and never enter the database, logs,
reports, or Codex context.

### External storage

The immutable artifact vault and the much larger Ghidra project/cache root are
independently configurable, so either or both can live on an external SSD. The
native application will retain the selected volume through a security-scoped
bookmark and record its stable volume identity. Before an import or analysis it
will verify that the expected volume is mounted and has enough free space plus a
reserve. A missing drive is a paused job, never permission to fall back silently
to the internal disk. Existing content-addressed paths remain valid when a whole
configured root is moved deliberately and its location is updated.

## Process isolation and safety

- Acquisition and Codex network access are separate from static analysis.
- Ghidra runs out of process with isolated temporary directories and resource
  limits; third-party extensions and analyzers are disabled by default. Its
  launcher receives the pinned `JAVA_HOME` explicitly so it never depends on a
  mutable system-wide Java selection.
- Downloaded binaries are never launched during inventory or static analysis.
- Proof-of-concept generation or execution requires a separate approval.
- Behavioral work requires an explicit Findings action. On a designated research
  Mac, targets run through a no-network macOS sandbox with user files denied and
  writes confined to a disposable directory; UTM remains the stronger optional
  isolation mode. Imported targets are never launched automatically.
- Reports distinguish observed evidence, Codex hypotheses, behavioral results,
  and the researcher's conclusions.

## Initial acceptance cases

1. rclone 1.74.3 to 1.74.4: first Mach-O/path-traversal pipeline fixture.
2. KeePassXC 2.7.11-1 to 2.7.12: first complete `.app` component fixture.
3. Helm 4.1.3 to 4.1.4: noisy update with multiple security fixes.

For each guided case, the ground-truth patch cluster must reach the final two,
and final analysis must explain the vulnerable behavior, patched invariant, and
plausible residual bypass conditions.
