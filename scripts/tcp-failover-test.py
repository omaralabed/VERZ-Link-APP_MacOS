#!/usr/bin/env python3
"""Paced, bidirectional, single-socket TCP delivery-gap probe. No dependencies.

Runs only synthetic data over VERZ's private tunnel. It never changes adapters,
routes, the app, firewall rules or production services. Remote listener expires.
"""
import argparse
import datetime
import hmac
import json
import math
import os
from pathlib import Path
import queue
import re
import secrets
import select
import shlex
import socket
import subprocess
import sys
import threading
import time

INTERVAL = 0.020
BASELINE = 15.0
PAYLOAD = "VERZ-TCP-PROBE-" * 73  # 1022 synthetic bytes, about 0.5 Mbps/direction.
PRIVATE_IP = "10.78.0.1"
SSH_HOST = "root@69.164.213.57"
MAX_LINE = 8192


def encode(value):
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as file:
        json.dump(value, file, indent=2)
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


class Receiver:
    def __init__(self, start, threshold):
        self.start = start
        self.threshold = threshold
        self.records = []
        self.previous = None
        self.previous_sent = None
        self.count = 0
        self.peer_end_count = None

    def receive(self, frame, now):
        if self.peer_end_count is not None:
            raise ValueError("Data after peer's end marker")
        if frame.get("seq") != self.count or frame.get("payload") != PAYLOAD:
            raise ValueError("Sequence or synthetic payload verification failed")
        sent = frame["sent_ns"] / 1e9
        if self.previous_sent is not None and sent < self.previous_sent:
            raise ValueError("Sender clock moved backwards")
        gap = (now - self.previous) * 1000 if self.previous is not None else None
        sender_gap = (sent - self.previous_sent) * 1000 if self.previous_sent is not None else None
        self.records.append({"seq": self.count, "elapsed_s": now - self.start,
                             "gap_ms": gap, "sender_interval_ms": sender_gap})
        self.count += 1
        self.previous = now
        self.previous_sent = sent
        return gap

    def finish(self, frame):
        if self.peer_end_count is not None or frame.get("count") != self.count:
            raise ValueError("End marker / received frame count mismatch")
        self.peer_end_count = frame["count"]

    def summary(self, now):
        gaps = [r for r in self.records if r["gap_ms"] is not None]
        baseline = [r["gap_ms"] for r in gaps if r["elapsed_s"] <= BASELINE]
        after = [r for r in gaps if r["elapsed_s"] > BASELINE]
        unfinished = ((now - self.previous) * 1000
                      if self.previous is not None and self.peer_end_count is None else 0)
        return {"frames_received": self.count, "payload_bytes": self.count * len(PAYLOAD),
                "peer_end_count": self.peer_end_count,
                "baseline_samples": len(baseline), "baseline_p99_ms": percentile(baseline, .99),
                "baseline_max_ms": max(baseline, default=0),
                "after_baseline_max_ms": max([r["gap_ms"] for r in after] + [unfinished]),
                "after_baseline_gaps_over_budget": [r for r in after if r["gap_ms"] > self.threshold],
                "unfinished_gap_lower_bound_ms": unfinished,
                "all_max_ms": max([r["gap_ms"] for r in gaps] + [unfinished]),
                "records": self.records}


def read_handshake(sock):
    raw = bytearray()
    while not raw.endswith(b"\n"):
        part = sock.recv(1)
        if not part or len(raw) >= MAX_LINE:
            raise ValueError("Incomplete or oversized handshake")
        raw.extend(part)
    return json.loads(raw)


def exchange(sock, seconds, threshold, notify=None, on_start=None):
    """No reader throttling, no reconnect and no application retransmission.

    Both sides generate a fresh frame every 20 ms; missed send ticks are not
    replayed. Nonblocking reads timestamp recv() completion, including batches.
    TCP backpressure never stops this loop from draining incoming data.
    """
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setblocking(False)
    start = time.monotonic()
    receiver = Receiver(start, threshold)
    local = sock.getsockname()
    peer = sock.getpeername()
    if on_start:
        on_start(start)
    outgoing = b""
    incoming = bytearray()
    count = 0
    end_queued = False
    next_send = start
    error = None
    completed = False
    announced_pause = False
    max_loop_gap = 0.0
    last_loop = start
    peer_max = 0.0
    receiver_max = 0.0
    try:
        while True:
            now = time.monotonic()
            max_loop_gap = max(max_loop_gap, (now - last_loop) * 1000)
            last_loop = now
            elapsed = now - start
            if elapsed > seconds + 45:
                raise TimeoutError("45-second drain/recovery deadline exceeded")
            if not outgoing and not end_queued and now >= next_send:
                if elapsed >= seconds:
                    outgoing = encode({"kind": "end", "count": count})
                    end_queued = True
                else:
                    outgoing = encode({"kind": "data", "seq": count,
                                       "sent_ns": time.monotonic_ns(), "payload": PAYLOAD,
                                       "rx_max_ms": receiver_max, "rx_count": receiver.count})
                    count += 1
                    next_send = now + INTERVAL
            if not outgoing and end_queued and receiver.peer_end_count is not None:
                completed = True
                break
            if receiver.previous is not None and receiver.peer_end_count is None:
                silence = (now - receiver.previous) * 1000
                if silence > threshold and not announced_pause:
                    announced_pause = True
                    if notify:
                        notify("pause", elapsed, silence)
            if notify:
                notify("tick", elapsed, None)
            wait = .020 if end_queued or outgoing else max(.001, min(.020, next_send - now))
            readable, writable, _ = select.select([sock], [sock] if outgoing else [], [], wait)
            if writable:
                try:
                    sent = sock.send(outgoing)
                    if sent == 0:
                        raise ConnectionError("Socket stopped accepting data")
                    outgoing = outgoing[sent:]
                except BlockingIOError:
                    pass
            if readable:
                try:
                    chunk = sock.recv(65536)
                except BlockingIOError:
                    continue
                received_at = time.monotonic()
                if not chunk:
                    if end_queued and not outgoing and receiver.peer_end_count is not None:
                        completed = True
                        break
                    raise ConnectionError("TCP closed before both verified end markers")
                incoming.extend(chunk)
                while b"\n" in incoming:
                    raw, _, tail = incoming.partition(b"\n")
                    incoming = bytearray(tail)
                    if len(raw) > MAX_LINE:
                        raise ValueError("Oversized frame")
                    frame = json.loads(raw)
                    if frame.get("kind") == "data":
                        gap = receiver.receive(frame, received_at)
                        receiver_max = max(receiver_max, gap or 0)
                        if gap is not None and gap > threshold and notify:
                            notify("gap", received_at - start, gap)
                        announced_pause = False
                        remote_max = float(frame.get("rx_max_ms", 0))
                        if remote_max > max(peer_max, threshold) and notify:
                            notify("peer_gap", received_at - start, remote_max)
                        peer_max = max(peer_max, remote_max)
                    elif frame.get("kind") == "end":
                        receiver.finish(frame)
                    else:
                        raise ValueError("Unknown frame kind")
                if len(incoming) > MAX_LINE:
                    raise ValueError("Oversized unfinished frame")
    except (OSError, ValueError, KeyError, TypeError, KeyboardInterrupt) as exc:
        error = "Cancelled" if isinstance(exc, KeyboardInterrupt) else str(exc)
    finally:
        end = time.monotonic()
        sock.close()
    return {"complete": completed, "error": error, "duration_s": end - start,
            "planned_seconds": seconds, "connections": 1, "application_retries": 0,
            "local_socket": local, "peer_socket": peer, "frames_generated": count,
            "maximum_event_loop_gap_ms": max_loop_gap, "budget_ms": threshold,
            "receiver": receiver.summary(end)}


def serve(args):
    if args.bind not in (PRIVATE_IP, "127.0.0.1"):
        raise ValueError("Listener must bind to the private VERZ IP or loopback")
    os.umask(0o077)
    directory = Path(args.directory)
    config = json.loads((directory / "config.json").read_text())
    seconds = float(config["seconds"])
    threshold = float(config["budget_ms"])
    if not 1 <= seconds <= 300 or not 20 <= threshold <= 5000:
        raise ValueError("Out-of-range probe duration or budget")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((args.bind, 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    source = str(config.get("client_ip", ""))
    try:
        socket.inet_aton(source)
    except OSError as error:
        raise ValueError("Invalid client tunnel IPv4") from error
    if not source.startswith("10.78."):
        raise ValueError("Client must use the VERZ private tunnel range")
    comment = "verz-tcp-probe-" + str(config["token"])[:12]
    rule = ["-d", args.bind + "/32", "-s", source + "/32", "-p", "tcp",
            "--dport", str(port), "-m", "comment", "--comment", comment, "-j", "ACCEPT"]
    iptables = "/usr/sbin/iptables"
    subprocess.run([iptables, "-I", "INPUT", "1"] + rule, check=True)
    firewall_installed = True
    save(directory / "ready.json", {"port": port, "pid": os.getpid(),
                                    "client_ip": source, "firewall_comment": comment})
    deadline = time.monotonic() + 180
    try:
        while time.monotonic() < deadline:
            listener.settimeout(max(.1, deadline - time.monotonic()))
            sock, _ = listener.accept()
            sock.settimeout(5)
            try:
                hello = read_handshake(sock)
                if not hmac.compare_digest(str(hello.get("token", "")), config["token"]):
                    sock.close()
                    continue
                sock.sendall(encode({"ready": True, "seconds": seconds, "budget_ms": threshold}))
            except (OSError, ValueError):
                sock.close()
                continue
            listener.close()  # Exactly one authenticated test; no reconnect accepted.
            report = exchange(sock, seconds, threshold)
            save(directory / "server-report.json", report)
            return
    finally:
        listener.close()
        if firewall_installed:
            subprocess.run([iptables, "-D", "INPUT"] + rule, check=False)


def interface_snapshot(text):
    output = {}
    for block in re.split(r"\n(?=\S)", text):
        match = re.match(r"((?:en|bridge)\d+):.*?<([^>]+)>", block)
        if not match:
            continue
        flags = match.group(2).split(",")
        output[match.group(1)] = ("UP" in flags and "status: active" in block
                                  and re.search(r"\n\s+inet (?!169\.254\.)", block) is not None)
    return output


def watch_interfaces(start, stop, events):
    old = None
    while not stop.is_set():
        try:
            text = subprocess.check_output(["/sbin/ifconfig", "-a"], text=True, timeout=2)
            current = interface_snapshot(text)
            if old is not None:
                for name in sorted(set(old) | set(current)):
                    if old.get(name, False) != current.get(name, False):
                        events.put({"elapsed_s": time.monotonic() - start, "interface": name,
                                    "ready": current.get(name, False)})
            old = current
        except (OSError, subprocess.SubprocessError):
            pass
        stop.wait(.25)


def ssh(command, timeout=20):
    return subprocess.check_output(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                                    SSH_HOST, command], text=True, timeout=timeout).strip()


def number(value):
    return "unavailable" if value is None else "%.1f ms" % value


def report_text(download, upload, events, seconds):
    lines = ["VERZ TCP FAILOVER REPORT", "", "One TCP socket, synthetic data, no reconnect/retry.",
             "Sender-paced every 20 ms; neither receiver is rate-limited.",
             "Download measured at Mac; upload measured at gateway.", ""]
    for name, report in (("DOWNLOAD", download), ("UPLOAD", upload)):
        if report is None:
            lines += [name + ": INCONCLUSIVE — gateway report could not be retrieved.", ""]
            continue
        rx = report["receiver"]
        enough = rx["baseline_samples"] >= 100 and seconds > BASELINE + 5
        if not report["complete"]:
            verdict = "FAILED / INCOMPLETE: " + str(report["error"])
        elif not enough:
            verdict = "INCONCLUSIVE: insufficient baseline or test duration"
        elif rx["after_baseline_max_ms"] > report["budget_ms"]:
            verdict = "PAUSE EXCEEDS %.0f ms BUDGET" % report["budget_ms"]
        elif rx["baseline_max_ms"] > report["budget_ms"]:
            verdict = "BASELINE ALREADY EXCEEDS BUDGET; repeat under stable conditions"
        elif not events:
            verdict = "NO INTERFACE CHANGE OBSERVED — not a physical failover validation"
        else:
            verdict = "WITHIN %.0f ms DELIVERY-GAP BUDGET IN THIS RUN" % report["budget_ms"]
        lines += [name + ": " + verdict,
                  "  Same TCP connection completed: " + ("YES" if report["complete"] else "NO"),
                  "  Verified payload bytes received: %d" % rx["payload_bytes"],
                  "  Baseline p99 / maximum: %s / %s" % (number(rx["baseline_p99_ms"]), number(rx["baseline_max_ms"])),
                  "  Largest gap after baseline: " + number(rx["after_baseline_max_ms"]),
                  "  Gaps over budget after baseline: %d" % len(rx["after_baseline_gaps_over_budget"]),
                  "  Receiver event-loop scheduling maximum: " + number(report["maximum_event_loop_gap_ms"])]
        if rx["unfinished_gap_lower_bound_ms"]:
            lines += ["  Unrecovered silence lasted at least " + number(rx["unfinished_gap_lower_bound_ms"])]
        worst = sorted(rx["after_baseline_gaps_over_budget"], key=lambda r: r["gap_ms"], reverse=True)[:10]
        for gap in worst:
            lines += ["  t=%.3fs: delivery gap %.1f ms; sender frame interval %.1f ms" %
                      (gap["elapsed_s"], gap["gap_ms"], gap["sender_interval_ms"])]
        lines.append("")
    lines += ["INTERFACE EVENTS (Mac polling, approximately 250 ms resolution):"]
    lines += ["  t=%.3fs %s %s" % (e["elapsed_s"], e["interface"], "READY" if e["ready"] else "DOWN") for e in events]
    if not events:
        lines.append("  None detected.")
    lines += ["", "Interpretation:",
              "These are application-delivery gaps, not exact cable-detection/route-switch latency.",
              "The 100 ms default is a chosen acceptance budget, not a guarantee of zero interruption.",
              "OS scheduling, sender stalls and baseline jitter can contribute; raw timestamps are saved.",
              "A completed connection alone is NOT a seamless-failover pass.",
              "This low-rate probe tests the encrypted TCP path, not maximum throughput or Direct Smart.",
              "Do not infer full-load behavior or other TCP connections from this single run."]
    return "\n".join(lines) + "\n"


def client(args):
    os.umask(0o077)
    if not 1 <= args.seconds <= 300 or not 20 <= args.budget_ms <= 5000:
        raise ValueError("Use 1–300 seconds and a 20–5000 ms gap budget")
    route = subprocess.check_output(["/sbin/route", "-n", "get", PRIVATE_IP], text=True, timeout=5)
    interface_match = re.search(r"interface:\s+(utun\d+)", route)
    if interface_match is None:
        raise RuntimeError("Connect VERZ in Secure Continuity with both interfaces enabled, then run again.")
    source_match = re.search(r"source:\s+(10\.78\.\d+\.\d+)", route)
    if source_match is None:
        tunnel = subprocess.check_output(["/sbin/ifconfig", interface_match.group(1)], text=True, timeout=5)
        source_match = re.search(r"\binet\s+(10\.78\.\d+\.\d+)\s+-->", tunnel)
    if source_match is None:
        raise RuntimeError("VERZ private tunnel address is unavailable. Disconnect and reconnect Secure Continuity.")
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    directory = Path(__file__).resolve().parent.parent / ".build" / "tcp-failover-reports" / stamp
    directory.mkdir(parents=True, exist_ok=False)
    print("Preparing a temporary private gateway probe. No service restart.", flush=True)
    remote = ssh("mktemp -d /tmp/verz-tcp-failover.XXXXXXXX")
    if re.fullmatch(r"/tmp/verz-tcp-failover\.[A-Za-z0-9]+", remote) is None:
        raise ValueError("Unexpected remote temporary directory")
    config = {"token": secrets.token_hex(32), "seconds": args.seconds,
              "budget_ms": args.budget_ms, "client_ip": source_match.group(1)}
    save(directory / "config.json", config)
    subprocess.run(["scp", "-q", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                    str(Path(__file__).resolve()), SSH_HOST + ":" + remote + "/probe.py"], check=True, timeout=20)
    subprocess.run(["scp", "-q", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                    str(directory / "config.json"), SSH_HOST + ":" + remote + "/config.json"], check=True, timeout=20)
    q = shlex.quote(remote)
    ssh("nohup python3 " + q + "/probe.py --server --directory " + q +
        " </dev/null >" + q + "/probe.log 2>&1 &")
    ready = None
    for _ in range(10):
        try:
            ready = json.loads(ssh("test ! -f " + q + "/ready.json || cat " + q + "/ready.json"))
            break
        except (ValueError, subprocess.SubprocessError):
            time.sleep(.3)
    if ready is None:
        raise RuntimeError("Probe did not start. Logs: " + remote + "/probe.log")
    save(directory / "session.json", {"remote_directory": remote, "port": ready["port"],
                                      "seconds": args.seconds, "budget_ms": args.budget_ms})
    sock = socket.create_connection((PRIVATE_IP, int(ready["port"])), timeout=10)
    sock.sendall(encode({"token": config["token"]}))
    if read_handshake(sock).get("ready") is not True:
        sock.close()
        raise RuntimeError("Gateway handshake rejected")
    print("\nTEST STARTED — %d seconds, one TCP connection, upload + download." % args.seconds, flush=True)
    print("Keep both paths unchanged for the first 15 seconds. Watch the prompts.", flush=True)
    print("100 ms is the reporting budget. Ctrl+C stops and saves partial evidence.\n", flush=True)
    event_queue = queue.Queue()
    events = []
    stop = threading.Event()
    watcher = None
    progress_at = -5
    prompts = {15: "BASELINE FINISHED. Get ready to unplug LAN.",
               20: "UNPLUG LAN NOW. Keep Wi-Fi ON.",
               35: "PLUG LAN BACK IN. Wait until it is ready.",
               60: "If LAN is ready, DISABLE WI-FI NOW. Keep LAN plugged in.",
               75: "ENABLE WI-FI AGAIN. Leave both paths on until the test ends."}

    def start_watch(start):
        nonlocal watcher
        watcher = threading.Thread(target=watch_interfaces, args=(start, stop, event_queue), daemon=True)
        watcher.start()

    def notify(kind, elapsed, value):
        nonlocal progress_at
        if kind == "pause":
            print("[%.1fs] DOWNLOAD delivery has paused for > %.0f ms" % (elapsed, value), flush=True)
        elif kind == "gap":
            print("[%.1fs] DOWNLOAD resumed — gap %.1f ms" % (elapsed, value), flush=True)
        elif kind == "peer_gap":
            print("[%.1fs] UPLOAD gateway reports maximum gap %.1f ms (report may arrive late)" % (elapsed, value), flush=True)
        if kind == "tick":
            while not event_queue.empty():
                event = event_queue.get_nowait()
                events.append(event)
                print("[%.1fs] INTERFACE %s %s" % (event["elapsed_s"], event["interface"],
                                                    "READY" if event["ready"] else "DOWN"), flush=True)
            for when in list(prompts):
                if elapsed >= when:
                    print("\n>>> " + prompts.pop(when) + "\n", flush=True)
            if elapsed - progress_at >= 5:
                progress_at = elapsed
                print("[%.0fs / %ds] %s" % (elapsed, args.seconds, "Baseline" if elapsed < BASELINE else "Measuring delivery"), flush=True)

    download = exchange(sock, args.seconds, args.budget_ms, notify, start_watch)
    stop.set()
    if watcher:
        watcher.join(timeout=3)
    while not event_queue.empty():
        events.append(event_queue.get_nowait())
    save(directory / "download.json", download)
    save(directory / "interface-events.json", events)
    upload = None
    print("\nRetrieving gateway's receiver report (this is not a test-data reconnect)...", flush=True)
    for _ in range(3):
        try:
            upload = json.loads(ssh("cat " + q + "/server-report.json"))
            break
        except (ValueError, subprocess.SubprocessError):
            time.sleep(1)
    if upload is not None:
        save(directory / "upload.json", upload)
    text = report_text(download, upload, events, args.seconds)
    (directory / "REPORT.txt").write_text(text)
    print("\n" + text)
    print("REPORT SAVED: " + str(directory / "REPORT.txt"))
    print("Remote evidence: " + remote + "/server-report.json")
    print("The temporary listener exits automatically; no production services were changed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--budget-ms", type=float, default=100)
    parser.add_argument("--server", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--directory", help=argparse.SUPPRESS)
    parser.add_argument("--bind", default=PRIVATE_IP, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        serve(args) if args.server else client(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print("TEST NOT COMPLETED: " + (str(error) or "Cancelled"), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
