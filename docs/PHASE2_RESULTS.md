# Phase 2 acceptance results

Phase 2 was accepted on 2026-08-05 with the public rclone path-traversal fixture,
versions 1.74.3 and 1.74.4. Acquisition and analysis were static; neither binary
was executed.

## Provenance

| Version | Object | SHA-256 | Size |
| --- | --- | --- | ---: |
| 1.74.3 | original ZIP | `33a435ab17023b686918ce9a3975aceb75fe1796c694f38f1993024be1f063f5` | 30,297,005 |
| 1.74.3 | extracted Mach-O | `9a156afbdd0a6ade42b0b40e7c30240119e2c82914bc8d7059a94dd9242ca2ed` | 81,809,202 |
| 1.74.4 | original ZIP | `c2100e2d4a4b3be04c55cd45380cafe7647e1ad772bb055f52f00876ed701167` | 30,390,226 |
| 1.74.4 | extracted Mach-O | `79dde6096c8d92c31495faac36fc764e3b3d557ee8569ce16c9fb07ce808024e` | 82,044,002 |

The vault stores all four objects by content hash. SQLite links each Mach-O to
its exact ZIP parent. Both executables are thin arm64 Mach-O files with valid
embedded ad-hoc signatures. Their UUIDs are
`B4A2554D-0D7D-3731-CCE0-98A2D94759B1` and
`046BE761-B447-33C6-EA98-CB85E014234F`, respectively.

## Ghidra export

Both inputs were analyzed by Ghidra 12.1.2 using the Apple Silicon language
`AARCH64:LE:64:AppleSilicon`, four analysis CPUs, a 1,800-second analysis
timeout, a 7,200-second process timeout, and a 20-second per-function decompiler
timeout.

| Version | Functions | Decompiled | Failed | Instructions | Export SHA-256 |
| --- | ---: | ---: | ---: | ---: | --- |
| 1.74.3 | 96,124 | 96,117 | 7 | 7,510,029 | `42be1a7f96c9fe06f3558ec126ed340c59952285a21f3862009c879c85a5978d` |
| 1.74.4 | 96,291 | 96,284 | 7 | 7,540,443 | `eb598209ef21cb5eb332fac2eb8d0cf82b5f46485887e1d762a91814b4cc83f4` |

Neither whole-program analysis timed out. The streaming validator checked every
JSONL record for required identity fields, address uniqueness, requested
architecture, and language consistency. Repeating both commands returned the
validated cached results instead of rerunning Ghidra.

## Known analyzer limitation

Ghidra reported rclone's Go 1.26.4 and 1.26.5 toolchains as untested and could
not recover Go RTTI bootstrap information, so its Go symbol and string analyzers
did not contribute their specialized enrichment. Generic disassembly and
decompilation still completed with only seven per-function failures on each
side. Phase 3 must treat missing Go RTTI as an explicit confidence/noise signal
and validate matching against the public source patch oracle.

## Exit decision

The Phase 2 exit condition is met: the two exact release artifacts were
preserved, inspected, decompiled reproducibly, exported deterministically, and
reused from cache without executing hostile input. The next milestone is the
semantic matcher and high-recall candidate-cluster generator.
