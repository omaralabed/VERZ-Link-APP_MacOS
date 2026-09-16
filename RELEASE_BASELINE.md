# VERZ Link 0.7.0 Build 65 Baseline

This file records the source and artifact boundary for the build-65 macOS and
gateway release. The immutable Git reference is `v0.7.0-build65`.

## Versioned components

- macOS application: `0.7.0 (65)`
- macOS UDP system extension: `0.7.0 (29)`
- Linux TCP relay: built from this tag for `x86_64-unknown-linux-gnu.2.31`
- Linux UDP gateway: built from this tag for `x86_64-unknown-linux-gnu.2.31`

## Artifact SHA-256

| Component | SHA-256 |
| --- | --- |
| macOS `VERZLink` | `424f91f926162869ba9ec5da41d27950d639c1149ce4e8d19d9ee84effd62f92` |
| macOS UDP system extension | `9cc2d7308a22f7b58cd201638d60f3924be4adc08509c638387d5ed24653e53a` |
| bundled macOS `verz-bond` | `f927f123b8bb856b853ca1318cede21fad988051fe6434008eee1b8587d8702f` |
| bundled macOS `verz-app-helper` | `b277c57cd9bc1e6e4bc2c2626a79a0b0ffe3f49d8efc00deb403a43071a61327` |
| Linux `verz-bond` | `9ad84109ea4c4e4fee4c9203d4769dade40bfe8fd7f72d93bf16abf03b004f64` |
| Linux `verz-tunnel-http` | `d2398d7a45c001fabd0c8479d1eae83ba05c529ddee79ac0fb4f328860a650af` |
| Linux `verz-udp-gateway` | `f7d6e2fcf1612e58b65e20b8489c5c704a106435f4095ddfb5aa547cac616623` |

## Required release gates

- Swift tests pass.
- Rust tests pass for `Engine`, `UdpEngine`, and `Helper`.
- Rust formatting and Clippy with warnings denied pass for all three packages.
- Linux TCP and UDP release cross-builds complete.
- The signed macOS Release app passes strict deep signature verification.
- The UDP extension passes the Team ID, App Group, and signing verifier.
- Both directions of the isolated two-WAN TCP cut test complete on one TCP
  connection with exact payload hashes.
- The repository has no pending tracked or untracked release changes.

The isolated cut test protects the automated regression boundary. Physical WAN
handover and throughput acceptance remain separate hardware release checks.

## Rollback boundary

Gateway deployment keeps the immediately previous binaries beside this release
under `/opt/verz-link-lab/releases/0.7.0-build65/`. The macOS installer also
creates a zip of the previously installed application under
`.build/xcode-run-backups/` before replacement.

This baseline is Apple Development signed for the registered development Mac.
Public distribution still requires the normal Developer ID signing and Apple
notarization workflow.
