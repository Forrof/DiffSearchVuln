# Phase 4 acceptance results

Phase 4 met its core acceptance condition on 2026-08-05 against the rclone
1.74.3-to-1.74.4 path-traversal fixture. This was a bounded ten-candidate pilot
drawn from the deterministic 500-candidate tournament pool. All 54,190 semantic
diff candidates remain preserved and recoverable; the pilot did not claim
full-pool performance or cost acceptance.

## Tournament execution

The runner used the local, ChatGPT-authenticated Codex app-server with
`gpt-5.6-sol`, high reasoning effort, read-only isolation, networking disabled,
and a fresh thread for every judgment. Two differently seeded passes advanced
the top two from groups of at most five, followed by an independent final
adjudication and a separate deep-analysis turn.

| Result | Value |
| --- | ---: |
| Pilot candidates | 10 |
| Judged tournament groups, including final adjudication | 7 |
| Codex calls, including deep analysis | 8 |
| Total input tokens reported by app-server | 446,610 |
| Total output tokens | 8,174 |
| Reasoning output tokens | 3,302 |
| Aggregate turn duration | 248.940 seconds |

Every call preserved its exact prompt, structured request, structured response,
thread ID, turn ID, model, duration, token usage, and prompt hash. Complete old
and new decompilation was supplied for active candidates; duplicate instruction
streams were omitted during tournament rounds and restored for the finalists.

## Finalists and patch localization

Both source-oracle functions reached the final two:

| Final rank | Candidate | Role |
| ---: | --- | --- |
| 1 | `github.com/rclone/rclone/cmd/archive/extract.destPath` | newly added destination validator |
| 2 | `github.com/rclone/rclone/cmd/archive/extract.ArchiveExtract.func1` | modified extraction callback |

The final analysis returned `likely_patch` with confidence `0.99`. It identified
that the old callback removed an optional leading `./` and joined an
archive-controlled name without rejecting parent components. It then described
the new helper's component iteration, exact `..` rejection, error return before
the join/write flow, and the updated caller's early error handling. This agrees
with the public fix commit referenced in [REFERENCES.md](REFERENCES.md).

The response kept observed disassembly/decompilation facts separate from
inference. It also raised non-weaponized review hypotheses including link-based
containment escapes, time-of-check/time-of-use races, absolute or platform-
specific path forms, later normalization, and extraction paths that might not
use the new helper.

## Resume check

Re-running the identical command returned the same content-addressed run in 1.4
seconds with `cached: true`. It revalidated the persisted final analysis and made
no new Codex call. Interrupted runs likewise reuse each already validated group
decision before continuing from the first missing stage.

## Exit decision

The Phase 4 core exit condition is met: the known patch cluster reached the
final two and Codex accurately explained the vulnerable behavior, new invariant,
patch mechanics, and plausible residual review areas. Evidence-linked chunking
for over-limit inputs and user pin/restore controls remain explicit follow-on
work for the native application; over-limit prompts currently fail closed rather
than truncating evidence.
