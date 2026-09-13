# Payload-speed display — build 31

## Reverted in build 32 at the user's request

The dashboard again uses the previous one-second interface-counter reporting:
Download, Upload, Data Transferred and Live Traffic. Secure Continuity reads
the tunnel interface; Direct Smart and Automatic Hybrid read selected adapters.
These are traffic counters, not a maximum internet speed test. The removed ≥
symbol remains absent. The passive engine instrumentation is retained but no
longer drives the dashboard; TCP/UDP transport and failover are unchanged.
The remainder of this document records the superseded build 31 behavior.

Revert verified: 27 Swift tests passed, Xcode Debug build succeeded, and signed
build 32 was installed at `/Applications/VERZ Link.app`. The installed executable
matches the Xcode product. TCP engine and UDP extension CodeDirectory hashes
match the previous installation. The reopened UI shows the original card and
graph labels; the app was left disconnected. No gateway changes were made.
The previous app is recoverable from
`.build/xcode-run-backups/previous-33C8F533-9A19-4C8C-9118-43D52300B06C.zip`.

This is a measurement correction, **not** a throughput or bonding-algorithm fix.
The existing TCP scheduler, wire protocol, path policy, recovery timers, routing
and UDP transport remain unchanged. No gateway service is deployed or restarted.

## What the cards mean

- **Payload download/upload:** VERZ-managed transport payload over a recent
  measurement window (normally about three seconds), in decimal Mbps.
- **Payload counted:** cumulative successfully measured payload in this session.
  This is not a billable ISP-usage counter or a promise that every application
  byte has been measured.
- Neither card is an interface-capacity estimate or a maximum-speed test.
- No greater-than-or-equal symbol is displayed. Missing, stale or currently
  incomplete rate measurements display a dash, not a guessed speed.
- An earlier coverage gap does not permanently blank live rates. It remains
  disclosed beside the cumulative counted total; current gaps affect only the
  recent measurement window.

## Accounting boundaries

### Secure tunnel TCP

An independent bounded observer records inner TCP payload sequence intervals.
Credit requires a cumulative TCP ACK covering bytes actually observed. Upload
uses the remote TCP receiver's ACK; download uses the Mac TCP receiver's ACK.
Retransmitted/overlapping ranges, outer relay copies, ACK-only packets, IP/TCP
headers, SYN and FIN do not add payload credit. Nothing from this observer is
used by the scheduler or affects forwarding decisions.

The observer keeps at most 4,096 flows and 64 outstanding disjoint ranges per
direction per flow. It handles sequence wrap, partial ACKs, tuple reuse and
out-of-order data. Missing connection baselines, malformed/fragmented TCP and
measurement-capacity limits are disclosed as incomplete coverage, not estimated.
Idle state expires after ten minutes. No payload contents are retained or logged.

### Direct TCP and Hybrid

Direct uploads use the existing read-only native TCP acknowledgement snapshot;
downloads count successful reads from the remote TCP socket. A socket close
with unconfirmed upload bytes records a coverage gap instead of assuming
delivery. Per-session totals survive adapter removal and exclude probe sockets.
Hybrid adds physical direct-socket payload to tunnel payload; relayed proxy
sockets are excluded from the direct total to avoid double counting.

### UDP

The transparent UDP provider counts a datagram once after the Rust engine accepts
the send, and download only after a successful local `writeDatagrams` completion.
Copies/repairs/probes on WAN sockets do not increment these payload totals. The
legacy TUN UDP path counts successful original submissions and local TUN writes,
excluding IP/UDP headers; unsupported fragments are disclosed as unmeasured.

**UDP submission is not proof of delivery at the remote application.** TLS,
application framing and encrypted/application-level SRT or QUIC retransmissions
remain transport payload; removing them generically is not possible without
protocol/application-specific knowledge. Traffic outside VERZ is excluded.

## Sampling and UI safeguards

Versioned cumulative telemetry carries a producer ID and producer monotonic
timestamp. Rates use that clock rather than the arrival time of UI callbacks.
The first report establishes a rate baseline but retains its real startup bytes
in the session total. Duplicate/out-of-order reports do not refresh freshness.
Producer restarts preserve known totals without making reset spikes; late reports
from retired producers are ignored. A long report gap re-establishes the baseline.
Missing required producers never fall back to physical interface counters.
The graph uses elapsed session time rather than assuming each callback is one
second. Temporary diagnostics are opt-in and should be restored after validation.

## Validation evidence

- Engine suite: 185 passed; two optional native-SRT tests ignored. Eight new
  observer regressions cover ACK gating, retransmissions, overlap, holes, wrap,
  tuple reuse, invalid ACKs, unsupported input and bounded coverage.
- Swift suite: 27 passed, including 11 rate/total/coverage regressions.
- Existing native direct-socket test also verifies the new cumulative payload
  accounting before/after close without double-counting repeated snapshots.
- Xcode Debug build and development-signature validation completed. The current
  source is in the existing Xcode project; its Run installer uses `/Applications`.
- Live Hybrid test: three 16,777,216-byte uploads and one 188,385,280-byte download
  passed length and SHA-256 verification. Observed tunnel counter deltas were
  50,344,999 bytes up and 188,403,642 bytes down, versus test bodies of 50,331,648
  and 188,385,280 bytes. HTTP framing and concurrent background flows explain why
  session-wide transport totals are not exactly equal to file-body totals.
- The live UI displayed payload traffic without the removed symbol. Its first
  verification exposed a lifetime coverage flag blanking rates permanently;
  this was corrected to recent-window coverage and added to the Swift tests.
- Reinstalled the corrected build and repeated all four transfers: every length
  and SHA-256 check passed again. Tunnel deltas were 50,340,736 bytes up and
  188,395,609 bytes down. One pre-existing coverage gap remained disclosed in
  totals, but did not blank subsequent complete measurement windows. Final UI
  inspection showed numeric rates (0.02 Mbps each at near-idle), 245.3 MB counted
  including concurrent proxy traffic, both adapters healthy, and no removed symbol.
- A live UDP DNS query returned `NOERROR`. This is basic UDP connectivity, not
  an OBS/SRT continuity test. Temporary TCP diagnostic logging was disabled again.

Final installed app executable SHA-256:
`4cead464942017fc2325bef28d0dd45ee662a44488af341d2d7006698afeb751`.
It matches the Xcode product in
`/Users/viewvision/Library/Developer/Xcode/DerivedData/VERZLink-Payload/Build/Products/Debug/VERZ Link.app`.
App remains connected in the user's selected Automatic Hybrid mode. The existing
installer retained a previous-app archive before each replacement; latest:
`.build/xcode-run-backups/previous-C06C923C-C3D9-4F20-A98A-71ED4D676C69.zip`.

Artifacts are in `.build/payload-*` (tests, build, install, live JSON and errors).
This check does not prove full WAN capacity, improved TCP performance, physical
unplug continuity or an OBS/SRT streaming soak. See `TCP_REPAIR_FIX.md` for the
separate, still-unresolved TCP throughput work.
