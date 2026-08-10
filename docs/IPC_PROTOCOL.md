# Native worker protocol

The first native-app boundary is a long-lived local Python worker started as:

```bash
PYTHONPATH=src /opt/homebrew/bin/python3.12 -m diffsearchvuln worker
```

The worker reads one UTF-8 JSON object per line from standard input and writes
one compact JSON response per line to standard output. Standard output is
reserved for protocol messages. Protocol version `1.0.0` is strict: unknown
request fields, unknown method parameters, and incompatible versions return a
typed error instead of being guessed.

## Request and response

```json
{"protocol_version":"1.0.0","id":"A1","method":"system.hello","params":{}}
```

```json
{"id":"A1","protocol_version":"1.0.0","result":{"capabilities":["candidate_evidence","candidate_paging","contained_host_dynamic_testing","controlled_codex_exploit_attempt","disposable_utm_dynamic_testing","environment_doctor","local_products","tournament_inspection"],"protocol_version":"1.0.0","safety_mode":"static_by_default_explicit_contained_dynamic","worker_version":"0.3.0"}}
```

Errors have an `error` object containing a stable `code`, a human-readable
`message`, and optional structured `data`. Parse failures use a null ID because
the request identity cannot be trusted. The worker continues after malformed
input so one bad UI message does not destroy the session.

Requests are capped at 1 MiB and responses at 64 MiB. An over-limit evidence
response fails with `response_too_large`; it is never silently truncated.

## Initial methods

| Method | Purpose |
| --- | --- |
| `system.hello` | Negotiate protocol, version, capabilities, and safety mode |
| `system.doctor` | Return structured environment checks |
| `store.initialize` | Initialize or migrate one local metadata database |
| `products.list` | List locally configured products |
| `products.create` | Create a local product record |
| `candidates.list` | Page through every preserved semantic candidate |
| `candidate.evidence` | Materialize exact old/new evidence for one candidate |
| `tournament.inspect` | Validate and return a stored tournament and final analysis |
| `exploit.codex_attempt` | Start an explicit, audited Codex exploit-research turn in a network-disabled attempt directory |
| `exploit.latest` | Load the latest persisted Codex exploit attempt for one tournament |

The protocol never executes imported binaries automatically. Evidence-only
Codex attempts may create helpers in their writable attempt directory. An
explicit `host_dynamic` attempt runs the selected pair through macOS
sandbox-exec on a dedicated research Mac: networking is denied, user data is
unreadable, writes are confined to a disposable directory, resources are
bounded, and every target hash and command is audited. `utm_dynamic` remains an
optional guest mode. The Codex workspace-write sandbox limits its own host
writes to the attempt directory. The
full prompt, structured response, thread/turn identity, token
usage, prompt hash, and generated files are preserved locally. Long-running analysis jobs,
progress events, cancellation, storage-volume bookmarks, and tournament
override methods will extend this contract before the SwiftUI workflow is
declared complete.

## Swift client

`macos/DiffSearchVulnCore` is a standalone Swift package that launches the
worker, serializes one request at a time, validates response protocol and
correlation IDs, decodes typed remote errors, and enforces the matching 64 MiB
response ceiling. It currently provides typed calls for the handshake, doctor,
product creation/listing, candidate paging/evidence, and completed tournament
inspection, plus explicit Codex exploit attempts and latest-attempt recovery.

The package can build with the installed command-line macOS SDK. Its integration
test launches the real Python worker, negotiates protocol `1.0.0`, writes a
temporary product through SQLite, reads it back, and verifies clean shutdown.
Its rclone acceptance test also decodes real candidates, exact evidence, and the
validated final tournament analysis.
