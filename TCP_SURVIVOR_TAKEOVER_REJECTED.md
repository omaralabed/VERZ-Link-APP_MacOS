# Rejected TCP survivor-window bypass — build 45

Build 45 temporarily allowed outstanding TCP work from an unavailable WAN to
bypass a surviving path's occupied congestion window. The physical Mac test on
2026-09-12 rejected this design. It is not present in the current source or
installed runtime.

## Physical evidence

Report:
`.build/tcp-failover-reports/20260912-135904-1969ff/REPORT.txt`

- Download maximum application-delivery gap: 2,425.7 ms.
- Download gaps over the 100 ms reporting budget: 31.
- Upload maximum application-delivery gap: 250.8 ms.
- Upload gaps over the budget: 35.
- The connection survived, but that is not a seamless-failover pass.
- Live gateway telemetry recorded 367 congestion-window bypass repairs,
  1,124 queue drops, a full 1,024-packet TUN intake queue, and a 3,145-packet
  TCP reorder peak.

The evidence shows that moving a failed path's outstanding work into a full
survivor created an uncontrolled burst. A path's physical capacity and safe
congestion window cannot be transferred from another interface.

## Rollback identity

- Installed Mac app restored to signed build 44. Embedded engine SHA-256:
  `95427253c73c5af4546619183b1451e22ec1e263aa91bc8e68fc49903b3061a1`.
- TCP gateway restored to SHA-256:
  `47cd0fa7fd0cb038c07fa854195980f00eab19644f49bef15b618a856a7d3de2`.
- UDP gateway was not replaced or restarted. PID 41955, SHA-256:
  `1112cef6101e533c79bb944cfd5cb2623b835313f3d245db98e4d1ee41f29507`.
- Failed installed build 45 is archived at
  `.build/failed-build45-runtime-20260912-1405/VERZ-Link-build45.zip`.
- Server candidate and prior binary are retained at
  `/opt/verz-link-lab/tcp-survivor.qV4NwQ/`.

## Required direction

Do not reintroduce cross-path congestion-window transfer or unbounded repair
credit. The next design must maintain a separately learned, validated capacity
model per interface; select only the survivor after failure; pace recovery and
new traffic within that survivor's own current capacity; and prevent a
returning interface from carrying data until it is stable. It must be proven
under sustained load and physical unplug/replug before deployment.
