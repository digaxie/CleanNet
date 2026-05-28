import subprocess
import unittest

from cleannet.network_monitor import NetworkMonitor, exception_entry_for_flow


class _Runner:
    def __init__(self, *, no_header_supported=True):
        self.calls = []
        self.no_header_supported = no_header_supported

    def __call__(self, args, _timeout):
        self.calls.append(args)
        if args == ["ss", "-tunpH"]:
            if not self.no_header_supported:
                return subprocess.CompletedProcess(args, 1, stdout="", stderr="invalid option -- H")
            return subprocess.CompletedProcess(args, 0, stdout=self._ss_body(), stderr="")
        if args == ["ss", "-tunp"]:
            return subprocess.CompletedProcess(
                args,
                0,
                stdout=(
                    "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
                    + self._ss_body()
                ),
                stderr="",
            )
        if args[:3] == ["ps", "-p", "1234"]:
            return subprocess.CompletedProcess(args, 0, stdout="firefox\n", stderr="")
        if args[:3] == ["ps", "-p", "4321"]:
            return subprocess.CompletedProcess(args, 0, stdout="python\n", stderr="")
        raise AssertionError(args)

    def _ss_body(self):
        return (
            'tcp ESTAB 0 0 192.168.1.5:50123 93.184.216.34:https users:(("firefox",pid=1234,fd=56))\n'
            'tcp ESTAB 0 0 127.0.0.1:50124 127.0.0.1:8888 users:(("python",pid=4321,fd=9))\n'
            'udp UNCONN 0 0 0.0.0.0:5353 *:* users:(("avahi-daemon",pid=999,fd=12))\n'
            'tcp ESTAB 0 0 [2001:db8::1]:5555 [2606:2800:220:1:248:1893:25c8:1946]:443 users:(("curl",pid=777,fd=4))\n'
        )


class NetworkMonitorTests(unittest.TestCase):
    def test_linux_snapshot_parses_ss_and_process_names(self):
        monitor = NetworkMonitor(system="Linux", runner=_Runner(), which=lambda name: f"/usr/bin/{name}", cache_ttl=0)

        snapshot = monitor.snapshot(proxy_bypass=[], always_bypass=["127.*"])

        self.assertTrue(snapshot["supported"])
        self.assertEqual(snapshot["summary"]["flow_count"], 4)
        external = next(flow for flow in snapshot["flows"] if flow["remote_address"] == "93.184.216.34")
        self.assertEqual(external["process_name"], "firefox")
        self.assertEqual(external["remote_port"], 443)
        self.assertEqual(external["exception_entry"], "93.184.216.34")
        self.assertFalse(external["is_exception"])
        local = next(flow for flow in snapshot["flows"] if flow["remote_address"] == "127.0.0.1")
        self.assertTrue(local["is_exception"])
        ipv6 = next(flow for flow in snapshot["flows"] if flow["pid"] == 777)
        self.assertEqual(ipv6["remote_address"], "2606:2800:220:1:248:1893:25c8:1946")

    def test_ss_without_no_header_flag_falls_back_and_skips_header(self):
        runner = _Runner(no_header_supported=False)
        monitor = NetworkMonitor(system="Linux", runner=runner, which=lambda name: f"/usr/bin/{name}", cache_ttl=0)

        snapshot = monitor.snapshot()

        self.assertTrue(snapshot["supported"])
        self.assertEqual(snapshot["summary"]["flow_count"], 4)
        self.assertIn(["ss", "-tunpH"], runner.calls)
        self.assertIn(["ss", "-tunp"], runner.calls)

    def test_snapshot_marks_new_proxy_bypass_without_duplicate_parse(self):
        runner = _Runner()
        monitor = NetworkMonitor(system="Linux", runner=runner, which=lambda name: f"/usr/bin/{name}", cache_ttl=60)

        first = monitor.snapshot(proxy_bypass=[], always_bypass=[])
        second = monitor.snapshot(proxy_bypass=["93.184.216.34"], always_bypass=[])

        self.assertFalse(next(flow for flow in first["flows"] if flow["remote_address"] == "93.184.216.34")["is_exception"])
        self.assertTrue(next(flow for flow in second["flows"] if flow["remote_address"] == "93.184.216.34")["is_exception"])
        self.assertEqual(sum(1 for call in runner.calls if call[0] == "ss"), 1)

    def test_missing_ss_returns_unsupported_snapshot(self):
        monitor = NetworkMonitor(system="Linux", which=lambda _name: None)

        snapshot = monitor.snapshot()

        self.assertFalse(snapshot["supported"])
        self.assertEqual(snapshot["flows"], [])
        self.assertEqual(snapshot["summary"]["flow_count"], 0)
        self.assertIn("ss command", snapshot["error"])

    def test_non_linux_returns_unsupported_snapshot(self):
        monitor = NetworkMonitor(system="Darwin", which=lambda name: f"/usr/bin/{name}")

        snapshot = monitor.snapshot()

        self.assertFalse(snapshot["supported"])
        self.assertEqual(snapshot["flows"], [])
        self.assertEqual(snapshot["summary"]["flow_count"], 0)

    def test_exception_entry_skips_local_and_empty_remote(self):
        self.assertEqual(exception_entry_for_flow({"remote_address": "127.0.0.1", "remote_port": 80}), "")
        self.assertEqual(exception_entry_for_flow({"remote_address": "*", "remote_port": None}), "")
        self.assertEqual(exception_entry_for_flow({"remote_address": "93.184.216.34", "remote_port": 443}), "93.184.216.34")


if __name__ == "__main__":
    unittest.main()
