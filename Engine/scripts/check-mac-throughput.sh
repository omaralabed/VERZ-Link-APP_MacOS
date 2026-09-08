#!/bin/bash
# Real TCP through the running app, not a synthetic packet-rate benchmark.
set -euo pipefail
umask 077
ENDPOINT=http://10.78.0.1:8080
TUN=$(/sbin/route -n get 10.78.0.1 | awk '/interface:/ {print $2}')
case "$TUN" in utun*) ;; *) echo 'Connect the VERZ app before this test.' >&2; exit 1;; esac
TEST_DIR=$(mktemp -d /tmp/verz-mac-throughput.XXXXXX)
echo "Tunnel: $TUN; test files: $TEST_DIR"
EXPECTED=$(curl --fail --silent --show-error --max-time 15 "$ENDPOINT/bulk-sha256")
curl --fail --silent --show-error --max-time 60 "$ENDPOINT/bulk" \
    --output "$TEST_DIR/download.bin" \
    --write-out 'Download: %{speed_download} bytes/sec; %{size_download} bytes; %{time_total}s\n'
ACTUAL=$(shasum -a 256 "$TEST_DIR/download.bin" | awk '{print $1}')
test "$EXPECTED" = "$ACTUAL"
echo 'PASS: download SHA-256 verified'
UPLOAD_HASH=$(head -c 16777216 /dev/zero | shasum -a 256 | awk '{print $1}')
for RUN in 1 2 3; do
    head -c 16777216 /dev/zero | curl --fail --silent --show-error --max-time 30 \
        -H 'Content-Type: application/octet-stream' --data-binary @- "$ENDPOINT/upload" \
        --output "$TEST_DIR/upload-$RUN.sha256" \
        --write-out 'Upload: %{speed_upload} bytes/sec; %{size_upload} bytes; %{time_total}s\n'
    test "$(tr -d '\r\n' < "$TEST_DIR/upload-$RUN.sha256")" = "$UPLOAD_HASH"
done
echo 'PASS: all upload SHA-256 results verified'
echo 'These are private-relay TCP measurements, not Speedtest results.'
