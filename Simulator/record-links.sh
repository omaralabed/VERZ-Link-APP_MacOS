#!/bin/sh
# Record this Mac's real links against the lab relay, for the simulator.
#
#   Simulator/record-links.sh [minutes] [mbps per link]
#
# While it runs, make the links fail the way they do in real life: pull the
# LAN cable, walk out of Wi-Fi range, switch the Wi-Fi off and on. Replay:
#
#   cd Simulator && cargo run --release -- --record recordings/<stamp>-en0.csv --record recordings/<stamp>-en7.csv
set -e
MINUTES=${1:-10}
MBPS=${2:-3}
IFACES=${IFACES:-"en0 en7"}
RELAY=${RELAY:-69.164.213.57:39000}
SECRET=${SECRET:-"$HOME/Desktop/VERZ/link-lab/lab-secret"}
cd "$(dirname "$0")/.."
cargo build --release --quiet --manifest-path Engine/Cargo.toml --bin verz-link-record
mkdir -p Simulator/recordings
STAMP=$(date +%Y%m%d-%H%M)
echo "Recording $IFACES for $MINUTES min at $MBPS Mbit/s each; Ctrl-C stops early."
for IF in $IFACES; do
  Engine/target/release/verz-link-record --relay "$RELAY" --interface "$IF" --secret-file "$SECRET" \
    --seconds $((MINUTES * 60)) --mbps "$MBPS" --out "Simulator/recordings/$STAMP-$IF.csv" \
    > "Simulator/recordings/$STAMP-$IF.summary.json" &
done
trap 'kill 0 2>/dev/null' INT TERM
wait
echo
for IF in $IFACES; do
  echo "== $IF"; cat "Simulator/recordings/$STAMP-$IF.summary.json"
done
echo
echo "Replay with:"
printf "  cd Simulator && cargo run --release --"
for IF in $IFACES; do printf " --record recordings/%s-%s.csv" "$STAMP" "$IF"; done
echo
