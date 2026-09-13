"""Local-only probe regression tests; no production network or interface changes."""
import importlib.util
from pathlib import Path
import select
import socket
import threading
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("probe", Path(__file__).with_name("tcp-failover-test.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def frame(seq, sent):
    return {"seq": seq, "sent_ns": int(sent * 1e9), "payload": probe.PAYLOAD}


def tcp_pair():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        client = socket.create_connection(listener.getsockname())
        server, _ = listener.accept()
    return client, server


class ReceiverTests(unittest.TestCase):
    def test_receiver_gap_not_sender_progress(self):
        meter = probe.Receiver(0, 100)
        meter.receive(frame(0, 1), 1)
        meter.receive(frame(1, 1.02), 1.02)
        meter.receive(frame(2, 1.04), 1.52)
        self.assertAlmostEqual(meter.records[-1]["gap_ms"], 500)
        self.assertAlmostEqual(meter.records[-1]["sender_interval_ms"], 20)

    def test_sequence_corruption_and_truncation_not_success(self):
        meter = probe.Receiver(0, 100)
        with self.assertRaises(ValueError):
            meter.receive(frame(1, 1), 1)
        bad = frame(0, 1)
        bad["payload"] = "corrupt"
        with self.assertRaises(ValueError):
            meter.receive(bad, 1)
        meter.receive(frame(0, 1), 1)
        with self.assertRaises(ValueError):
            meter.finish({"count": 2})

    def test_baseline_and_post_baseline_separate(self):
        meter = probe.Receiver(0, 100)
        meter.receive(frame(0, 1), 1)
        meter.receive(frame(1, 1.02), 1.02)
        meter.receive(frame(2, 16), 16)
        meter.receive(frame(3, 16.02), 16.5)
        meter.finish({"count": 4})
        summary = meter.summary(17)
        self.assertAlmostEqual(summary["baseline_max_ms"], 20)
        self.assertEqual(len(summary["after_baseline_gaps_over_budget"]), 2)
        self.assertEqual(summary["unfinished_gap_lower_bound_ms"], 0)

    def test_unrecovered_silence_included(self):
        meter = probe.Receiver(0, 100)
        meter.receive(frame(0, 1), 1)
        self.assertEqual(meter.summary(6)["unfinished_gap_lower_bound_ms"], 5000)

    def test_batch_timestamp_does_not_erase_previous_gap(self):
        meter = probe.Receiver(0, 100)
        meter.receive(frame(0, 1), 1)
        meter.receive(frame(1, 1.02), 1.5)
        meter.receive(frame(2, 1.04), 1.5)
        meter.finish({"count": 3})
        self.assertEqual(meter.summary(2)["all_max_ms"], 500)

    def test_backward_sender_clock_rejected(self):
        meter = probe.Receiver(0, 100)
        meter.receive(frame(0, 2), 2)
        with self.assertRaises(ValueError):
            meter.receive(frame(1, 1), 2.1)

    def test_dynamic_interface_parser(self):
        text = "en7: flags=1<UP,RUNNING> mtu 1500\n\tinet 192.168.1.3 netmask 0\n\tstatus: active\n"
        text += "en42: flags=1<UP> mtu 1500\n\tinet 169.254.1.3 netmask 0\n\tstatus: active\n"
        text += "en0: flags=1<UP> mtu 1500\n\tinet 192.168.1.2 netmask 0\n\tstatus: inactive\n"
        self.assertEqual(probe.interface_snapshot(text), {"en7": True, "en42": False, "en0": False})

    def test_firewall_rule_is_private_and_source_scoped(self):
        token = "abcdef0123456789"
        rule = ["-d", probe.PRIVATE_IP + "/32", "-s", "10.78.0.2/32", "-p", "tcp",
                "--dport", "41234", "-m", "comment", "--comment",
                "verz-tcp-probe-" + token[:12], "-j", "ACCEPT"]
        self.assertEqual(rule[:4], ["-d", "10.78.0.1/32", "-s", "10.78.0.2/32"])
        self.assertNotIn("0.0.0.0/0", rule)

    def test_point_to_point_tunnel_source_pattern(self):
        tunnel = "utun4: flags=8051<UP,POINTOPOINT> mtu 1280\n\tinet 10.78.0.2 --> 10.78.0.1 netmask 0xffffffff\n"
        match = probe.re.search(r"\binet\s+(10\.78\.\d+\.\d+)\s+-->", tunnel)
        self.assertEqual(match.group(1), "10.78.0.2")


class TransportTests(unittest.TestCase):
    def test_native_tcp_both_directions_integrity(self):
        client, server = tcp_pair()
        output = {}
        thread = threading.Thread(target=lambda: output.update(server=probe.exchange(server, 1, 100)))
        thread.start()
        local = probe.exchange(client, 1, 100)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        remote = output["server"]
        self.assertTrue(local["complete"], local["error"])
        self.assertTrue(remote["complete"], remote["error"])
        self.assertEqual(local["frames_generated"], remote["receiver"]["frames_received"])
        self.assertEqual(remote["frames_generated"], local["receiver"]["frames_received"])
        self.assertEqual(local["connections"], 1)
        self.assertEqual(local["application_retries"], 0)

    def test_deliberate_delivery_pause_is_reported_despite_completion(self):
        client, middle_left = tcp_pair()
        middle_right, server = tcp_pair()
        output = {}
        stop = threading.Event()

        def forward():
            started = time.monotonic()
            buffered = bytearray()
            try:
                while not stop.is_set():
                    elapsed = time.monotonic() - started
                    paused = .25 <= elapsed < .75
                    readable, _, _ = select.select([middle_left, middle_right], [], [], .005)
                    for source in readable:
                        data = source.recv(65536)
                        if not data:
                            return
                        if source is middle_left:
                            middle_right.sendall(data)
                        else:
                            buffered.extend(data)
                    if not paused and buffered:
                        middle_left.sendall(buffered)
                        buffered.clear()
            finally:
                middle_left.close()
                middle_right.close()

        relay = threading.Thread(target=forward)
        remote_thread = threading.Thread(target=lambda: output.update(server=probe.exchange(server, 1.5, 100)))
        relay.start()
        remote_thread.start()
        with patch.object(probe, "BASELINE", .1):
            local = probe.exchange(client, 1.5, 100)
        stop.set()
        relay.join(3)
        remote_thread.join(3)
        self.assertTrue(local["complete"], local["error"])
        self.assertGreater(local["receiver"]["after_baseline_max_ms"], 400)
        self.assertLess(local["receiver"]["after_baseline_max_ms"], 1000)
        gaps = local["receiver"]["after_baseline_gaps_over_budget"]
        self.assertTrue(gaps)
        self.assertLess(gaps[0]["sender_interval_ms"], 100)

    def test_broken_connection_is_not_success(self):
        client, server = tcp_pair()
        server.close()
        result = probe.exchange(client, 1, 100)
        self.assertFalse(result["complete"])
        self.assertIsNotNone(result["error"])

    def test_report_does_not_call_no_flap_a_pass(self):
        rx = {"baseline_samples": 200, "baseline_max_ms": 22, "baseline_p99_ms": 21,
              "after_baseline_max_ms": 23, "after_baseline_gaps_over_budget": [],
              "unfinished_gap_lower_bound_ms": 0, "payload_bytes": 123}
        result = {"complete": True, "error": None, "receiver": rx, "budget_ms": 100,
                  "maximum_event_loop_gap_ms": 21}
        text = probe.report_text(result, result, [], 120)
        self.assertIn("NO INTERFACE CHANGE OBSERVED", text)
        self.assertNotIn("WITHIN 100 ms", text)
        rx["after_baseline_max_ms"] = 500
        text = probe.report_text(result, result, [{"elapsed_s": 20, "interface": "en7", "ready": False}], 120)
        self.assertIn("PAUSE EXCEEDS 100 ms BUDGET", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
