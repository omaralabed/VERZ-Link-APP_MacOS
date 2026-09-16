# VERZ Link 0.7.0 Build 66 Baseline

This file records the source and artifact boundary for the build-66 macOS and
gateway release. The immutable Git reference is `v0.7.0-build66`. Build 66 is a
macOS UI-only correction over the build-65 networking baseline.

## Versioned components

- macOS application: `0.7.0 (66)`
- macOS UDP system extension: `0.7.0 (29)`
- Linux TCP relay: built from this tag for `x86_64-unknown-linux-gnu.2.31`
- Linux UDP gateway: built from this tag for `x86_64-unknown-linux-gnu.2.31`

## Artifact SHA-256

| Component | SHA-256 |
| --- | --- |
| macOS `VERZLink` | `2cdf613ccfac9e1fe03c13118de1d58baed36682e6f4cdd2241dae6da83fd9ee` |
| macOS UDP system extension | `8ba5ed9b72b7083264e61deab9930313c5e4de5724fee13b6db132465d28d8ef` |
| bundled macOS `verz-bond` | `59f06a1b8ec9bb2e27377093a143adf799d528327c6e3ae99953c43c36671608` |
| bundled macOS `verz-app-helper` | `bbc13d75ba2acc4a44f0f43d405d70cd7c228ae5b66ec973e67133a72940af67` |
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
- The network core is source-identical to build 65, where both directions of
  the isolated two-WAN TCP cut test completed on one TCP connection with exact
  payload hashes.
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
