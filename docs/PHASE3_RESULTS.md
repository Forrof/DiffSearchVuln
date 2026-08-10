# Phase 3 acceptance results

Phase 3 was accepted on 2026-08-05 against the rclone 1.74.3 to 1.74.4
path-traversal fixture. The public source oracle is the rclone fix commit linked
in [REFERENCES.md](REFERENCES.md): it moves destination-path handling into a new
`destPath` validator, rejects `..` components using both slash styles, and calls
the validator from the archive extraction callback.

## Symbol recovery

Ghidra 12.1.2 could not apply its specialized Go RTTI analyzer to the Go 1.26.4
and 1.26.5 inputs. A new static helper now parses the Mach-O `__gopclntab`
section using Go's standard `debug/gosym` package. It recovered 95,816 old and
95,979 new function ranges without executing the target binaries. The Ghidra
index resolved names for 96,084 of 96,124 old functions and 96,251 of 96,291
new functions.

## Matching result

The streaming matcher normalizes relocation-like instruction operands, then
matches unique exact names, normalized instruction hashes, and mnemonic
sequences. Its content-addressed run produced:

| Result | Count |
| --- | ---: |
| Matched function pairs | 96,036 |
| Unchanged pairs | 42,189 |
| Modified pairs | 53,778 |
| Data-only pairs | 69 |
| Added functions | 255 |
| Deleted functions | 88 |
| Low-confidence matches | 39 |
| Preserved candidates | 54,190 |
| Initial tournament pool | 500 |

The unusually large modified set is expected compiler churn from the Go
1.26.4-to-1.26.5 rebuild. All candidates remain recoverable; scoring and the
tournament pool suppress noise without deleting evidence.

## Source-oracle localization

With advisory terms for archive extraction and path traversal:

| Rank | Candidate | Result |
| ---: | --- | --- |
| 1 | `github.com/rclone/rclone/cmd/archive/extract.destPath` | new validator |
| 2 | `github.com/rclone/rclone/cmd/archive/extract.destPath.func1` | slash/backslash predicate |
| 9 | `github.com/rclone/rclone/cmd/archive/extract.ArchiveExtract.func1` | modified extraction callback |
| 195 | `github.com/rclone/rclone/cmd/archive/extract.ArchiveExtract` | enclosing function |

The rank-one cluster directly links the new validator to the modified callback,
`path.Join`, `strings.FieldsFunc`, and error construction. This agrees with the
public source patch and places the full patch cluster comfortably inside the
500-candidate tournament pool.

## Exit decision

The Phase 3 exit condition is met. The semantic layer is deterministic, cached,
auditable, architecture-bound, and keeps source-record offsets so Phase 4 can
materialize complete decompilation only for the five candidates being judged.
