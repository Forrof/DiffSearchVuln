# Phase 5 application progress

The first functional native application build was completed on 2026-08-05 with
Xcode 26.6, the macOS 26.5 SDK, Swift 6, and XcodeGen 2.46.0. The project is
generated deterministically from `macos/DiffSearchVulnApp/project.yml` and uses
the local `DiffSearchVulnCore` Swift package.

## Implemented application surfaces

- A native `NavigationSplitView` shell with persistent, separately selectable
  analyses plus Products and Settings destinations.
- A top-level analysis selector that scopes Summary, Function Diff, Tournament,
  and Findings tabs to one release pair, so additional cases do not mix state.
- Per-analysis provenance, including a one-sentence binary/version/source
  summary and the attached semantic-diff and tournament directories.
- Live worker connection state and metadata-schema status.
- Product creation and listing through the versioned worker and SQLite store.
- Paging across all semantic candidates through a compact top selector with
  readable function tails, rank, score, and change kind. Full qualified names
  remain available as help text while the old/new diff occupies the main view.
- On-demand exact evidence materialization with side-by-side old/new
  decompilation and added/deleted-function states. Changed decompilation lines
  now use GitHub-style red removal and green addition rows with line numbers.
- Validated completed-tournament inspection with model, pool/group/call counts,
  final two candidates, finding state, and confidence.
- A native finding reader that explicitly separates where the vulnerability
  was, how the patched binary works now, and possible bypasses to investigate,
  with side-by-side before/after execution-flow graphs. Low-level evidence and
  inference are intentionally omitted from this user-facing tab.
- A per-analysis Exploit Lab with a non-executing path-containment simulator,
  bypass-hypothesis selection, a persistent experiment notebook, and an
  explicit “Ask Codex to Try” action. Each click starts a fresh audited Codex
  app-server thread using the user’s ChatGPT authentication, sends the complete
  final patch-analysis evidence, and allows helper artifacts only inside a
  restricted, network-disabled attempt directory. Imported binaries are not
  automatically executed.
- Independent artifact-vault and analysis-cache location settings suitable for
  later external-SSD selection.
- Typed child-process errors that include safe worker stderr when startup fails.

## Runtime acceptance

The Debug `.app` bundle built successfully for native arm64 and launched outside
Xcode. It connected to worker version 0.3.0, initialized database schema 1, and
showed the local rclone acceptance fixture. Opening Candidates validated and
paged the 54,190-record catalog, automatically selected rank-one
`github.com/rclone/rclone/cmd/archive/extract.destPath`, recognized it as an
added function, and rendered its complete updated decompilation from the local
Ghidra export. The stored tournament then loaded as completed with two finalists,
and the Findings screen rendered the validated `likely_patch` analysis at 99%
confidence with vulnerable-before and patched-now flow graphs.

The Swift package also has a live integration test for this path: it launches
the real Python worker, decodes the first two typed rclone candidates, and
materializes the rank-one evidence. No imported binary is executed.

## Development boundary

The current development target deliberately has App Sandbox disabled because it
launches Homebrew Python and reads arbitrary user-selected analysis directories.
This is not the release security posture. Before packaging, the worker and its
runtime must be bundled or installed through a controlled helper design, file
access must use security-scoped bookmarks, credentials must use Keychain, and
the target must receive explicit sandbox/signing/notarization review.

## Remaining Phase 5 work

- Asynchronous analysis-job APIs with progress events, pause, cancellation, and
  crash-safe resumption.
- Release pairing and component-selection screens.
- Tournament execution/progress, individual group decisions, user overrides,
  and report generation.
- Stable volume identity and free-space/reserve preflight for external storage.
- Notifications, Keychain-backed source credentials, app icon, signing, and
  packaging.

The Phase 5 exit condition is not yet met: the existing rclone results can be
inspected natively, but a complete new comparison cannot yet be initiated and
driven to completion without the CLI.
