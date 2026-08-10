# Research references

## Core tooling

- [Ghidra 12.1.2 getting started](https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.1.2_build/GhidraDocs/GettingStarted.md)
- [Ghidra headless analyzer documentation](https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.1.2_build/Ghidra/RuntimeScripts/Common/support/analyzeHeadlessREADME.md)
- [Ghidriff](https://github.com/clearbluejar/ghidriff)
- [Go debug/gosym package](https://pkg.go.dev/debug/gosym)
- [BinDiff manual](https://www.zynamics.com/bindiff/manual/)
- [Codex authentication](https://learn.chatgpt.com/docs/auth.md)
- [Codex SDK](https://learn.chatgpt.com/docs/codex-sdk.md)
- [Codex app-server](https://learn.chatgpt.com/docs/app-server.md)

## Acceptance fixtures

### rclone 1.74.3 to 1.74.4

- [GHSA-4vr5-p2gc-h23p](https://github.com/rclone/rclone/security/advisories/GHSA-4vr5-p2gc-h23p)
- [Primary fix commit](https://github.com/rclone/rclone/commit/1a746732441e8158f32fab35924b23701e719a8c)
- [Follow-up fix commit](https://github.com/rclone/rclone/commit/d11efe0d58fe6a2d6d90675bb9d8ee5840c51e1d)
- [Old macOS arm64 binary](https://downloads.rclone.org/v1.74.3/rclone-v1.74.3-osx-arm64.zip)
- [New macOS arm64 binary](https://downloads.rclone.org/v1.74.4/rclone-v1.74.4-osx-arm64.zip)

### KeePassXC 2.7.11-1 to 2.7.12

- [Security fix PR #13114](https://github.com/keepassxreboot/keepassxc/pull/13114)
- [KeePassXC 2.7.11 release](https://github.com/keepassxreboot/keepassxc/releases/tag/2.7.11)
- [KeePassXC 2.7.12 release](https://github.com/keepassxreboot/keepassxc/releases/tag/2.7.12)
- [Old arm64 DMG](https://github.com/keepassxreboot/keepassxc/releases/download/2.7.11/KeePassXC-2.7.11-1-arm64.dmg)
- [New arm64 DMG](https://github.com/keepassxreboot/keepassxc/releases/download/2.7.12/KeePassXC-2.7.12-arm64.dmg)

### Helm 4.1.3 to 4.1.4

- [GHSA-vmx8-mqv2-9gmg](https://github.com/helm/helm/security/advisories/GHSA-vmx8-mqv2-9gmg)
- [Fix commit](https://github.com/helm/helm/commit/36c8539e99bc42d7aef9b87d136254662d04f027)
- [Old macOS arm64 binary](https://get.helm.sh/helm-v4.1.3-darwin-arm64.tar.gz)
- [New macOS arm64 binary](https://get.helm.sh/helm-v4.1.4-darwin-arm64.tar.gz)

These fixtures are public, authorized static-analysis targets with source-level
ground truth. Old vulnerable binaries must not be executed outside a disposable
test environment.
