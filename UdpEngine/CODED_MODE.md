# Coded mode ("Smart")

Status: **deployed on 69.164.213.57 on 2026-10-19** (gateway sha256
`48da115ae29c8302…`, second deployment of the day; the release-baseline
binary is kept as `/opt/verz-link-lab/verz-udp-gateway.backup-20261019T184455Z`,
the first coded build as the later `.backup-…` file). Rollback: copy a backup
over `/opt/verz-link-lab/verz-udp-gateway` and
`systemctl restart verz-udp-gateway.service`. Mac app build 74 carries the
matching client.

## Lessons from the first live attempt (OBS would not stream)

- **Every UDP flow became a coded stream.** The first gateway capped coded
  streams at 32; DNS lookups and browser QUIC connections filled the slots in
  seconds and the OBS stream itself was refused (~400 rejected packets/s).
  Now: DNS never takes the coded lane (client rule, and the gateway treats a
  class-6 port-53 packet as request/response); coded streams are admitted by
  memory (48 MB total, up to 1,024 streams) and expire after 30 s of silence
  regardless of their egress socket (a client continuing later simply starts
  a new one mid-stream).
- **A cover fires once, on the transition to suspect.** If the scheduler then
  still had to use that link (nothing better left), packets placed on it
  afterwards were unprotected; the loopback test caught this as an
  intermittent stall right after a cut. Now anything placed on a link that is
  not trusted is covered as it goes, one repair per original. A link's
  measured loss also fades with time, so a link's own earlier outage does not
  keep it "lossy" long after it recovered.
- **A cover is a burst.** Repairs now leave at most 32 per tick, and a send
  the host refuses is retried next tick instead of counting as a loss.

Verified from this Mac over Wi-Fi (en0) and LAN (en7) with the deployed
gateway (`deployed_gateway_echo`, `VERZ_UDP_TEST_MODE`): Maximum Continuity
100/100 echoes as before; Smart Repair 100/100 echoes, support announced,
200 originals, 121 reports, 10 probes, 0 repairs needed (no loss in that
second), wire bytes about 1.2× the payload against Continuity's 2×.

## What it is

The bonding method proven in `Simulator/` (see `Simulator/README.md`): each
datagram is sent once, repair packets built from recent datagrams replace
copies, the server rebuilds whatever was lost, and it reports back per link
what arrived so the client sees losses one round trip later. The method
itself is the shared crate `Engine/vendor/verz-bonding-core`; the simulator
and the gateway run the same code.

## What changed on the gateway

- `UdpEngine/src/coded.rs` (new): a coded stream per (session, local port):
  packs originals into fixed 1,200-byte blocks, feeds originals and repairs
  to the shared receiver, releases datagrams in order, and builds reports.
- `UdpEngine/src/gateway.rs`: class 6 packets are dispatched to coded
  streams; released datagrams go through the existing `egress`, with the
  same destination checks as today's packets; reports are sent on the link
  they describe; the heartbeat reply now also says `"coded": 1`.
- Limits: 32 coded streams per gateway, about 600 KB each at worst
  (`coded_streams`, `coded_bytes` in the limits JSON). Counters
  `coded_rebuilt`, `coded_abandoned`, `coded_repairs`.

Nothing else changed. Classes 1–5 take exactly the old code paths; an old
client never sees class 6 and ignores the extra heartbeat field.

## What changed in the client engine (`UdpEngine/src/lib.rs`)

- Mode 5, `MODE_CODED`. Until the gateway's heartbeat reply says
  `"coded": 1`, the mode behaves exactly as Continuity (class 4 with copies),
  so an old server is never asked for anything it does not understand.
- One `CodedFlow` per local port: its own sequence space, the coded blocks
  of its last 512 originals (for building repairs), and a `CodedSender` from
  the shared crate that watches the links and orders repairs.
- Originals are placed by the existing Bonded Speed scheduler, offered only
  the best tier of links (healthy, else slow, else suspect, else any with a
  carrier) with each link's predicted delay, and gated by the core's
  admission allowance after a link has congested.
- Every tick: link inputs refreshed, a probe on any link idle for 50 ms, and
  the repairs the core orders, built from the kept blocks.
- Reports (class 6 `ACK`) feed the core, and the Bonded Speed scheduler's
  own capacity model through its ACK/NACK entry points.
- Send stamps are wall-clock anchored (`epoch_wall` + monotonic time), so a
  restarted engine's stamps are newer than the old one's and the gateway
  resets the stream.
- `verz_status` gains `"smart": {supported, flows, stats}`.

Test: `smart_mode_rebuilds_datagrams_lost_on_silently_cut_wans_without_copies`
runs engine and gateway over real loopback sockets through a relay that
silently cuts one link and then the other: 600 datagrams of 1,332 bytes (two
pieces each), all delivered once, losses rebuilt from repairs, and wire bytes
well under what copies would cost.

## What changed in the Mac app

- `ConnectionPreset.smart` ("Smart Repair"), policy `smart-repair`, mode 5
  to the extension (`UDPConnection.mode`). Order in the picker: Bonded, Smart
  Repair, Maximum Continuity, Direct.
- `LinkModel` reads the engine's `"smart"` status: logs once whether the
  server supports it or the preset is running as Maximum Continuity, and
  shows "Smart Repair: Active · N repairs sent" in the Protection card.
- Settings migration keeps `smart-repair` for the secure mode; Direct keeps
  its own `smart` policy as before.

## Wire format (class 6, inside the usual authenticated packet)

| Packet | Flags | Fields | Payload |
|---|---|---|---|
| Original | none (`MORE` = `RESEND` bit on every piece of a split datagram but the last) | `sequence` = coded sequence; `timestamp_us` = the client's per-link send stamp, unique per link, echoed back; `link`; destination fields as today | the datagram, or a piece of it, at most 1,190 bytes |
| Repair | `FEC` | `sequence` = first covered; `timestamp_us`; `link` | 10-byte `RepairHeader` (first, count, seed) + one 1,200-byte coded block |
| Probe | `FEC` + `MORE` | `timestamp_us`; `link` | empty: only a send stamp to echo, so an idle link's rhythm stays observable |
| Report (server → client) | `ACK` | `sequence` = decoded-through or `u32::MAX`; `link` = the link it describes; `local_port` | `Report`: decoded-through, missing sequences, echo of that link's newest send stamp, and per link (id, newest send stamp, packets received, originals received) |

A coded block is `[len u16][more u8][protocol u8][destination 4][port u16]`
then the bytes, zero padded to 1,200: a rebuilt original is complete on its own.

Clocks: the server never compares client send stamps with its own clock
directly; it learns the smallest difference seen (offset plus fastest one-way
delay) and measures deadlines from there (`Clock` in the receiver).

Datagrams longer than 1,190 bytes are split into pieces at the client and
reassembled on release. Real-time media stays under that; the path exists so
nothing breaks if an application sends more.

## Deploying

Build: `cd UdpEngine && cargo zigbuild --release --target x86_64-unknown-linux-gnu --bin verz-udp-gateway`
(the server is Ubuntu, glibc 2.39, x86-64). Deploy first to a server created
through the hub, never straight to 69.164.213.57; its gateway must stay on
the release-baseline binary until the new mode has passed the lab test with
real cables. Rollback is the previous binary in place and a service restart,
as documented in `UDP_PROXY_PORT.md`.
