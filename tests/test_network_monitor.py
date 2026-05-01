import subprocess
import unittest

from cleannet.network_monitor import NetworkMonitor, exception_entry_for_flow


class _Runner:
    def __init__(self):
        self.calls = []

    def __call__(self, args, _timeout):
        self.calls.append(args)
        if args[0] == "netstat":
            return subprocess.CompletedProcess(
                args,
                0,
                stdout=(
                    "  Proto  Local Address          Foreign Address        State           PID\n"
                    "  TCP    192.168.1.5:50123      93.184.216.34:443      ESTABLISHED     1234\n"
                    "  TCP    127.0.0.1:50124        127.0.0.1:8888         ESTABLISHED     4321\n"
                    "  UDP    0.0.0.0:5353           *:*                                    1234\n"
                ),
                stderr="",
            )
        if args[0] == "tasklist":
            return subprocess.CompletedProcess(
                args,
                0,
                stdout='"game.exe","1234","Console","1","10,000 K"\n"python.exe","4321","Console","1","20,000 K"\n',
                stderr="",
            )
        raise AssertionError(args)


class NetworkMonitorTests(unittest.TestCase):
    def test_windows_snapshot_parses_netstat_and_process_names(self):
        monitor = NetworkMonitor(system="Windows", runner=_Runner(), cache_ttl=0)

        snapshot = monitor.snapshot(proxy_bypass=[], always_bypass=["127.*"])

        self.assertTrue(snapshot["supported"])
        self.assertEqual(snapshot["summary"]["flow_count"], 3)
        external = next(flow for flow in snapshot["flows"] if flow["remote_address"] == "93.184.216.34")
        self.assertEqual(external["process_name"], "game.exe")
        self.assertEqual(external["exception_entry"], "93.184.216.34")
        self.assertFalse(external["is_exception"])
        local = next(flow for flow in snapshot["flows"] if flow["remote_address"] == "127.0.0.1")
        self.assertTrue(local["is_exception"])

    def test_snapshot_marks_new_proxy_bypass_without_duplicate_parse(self):
        runner = _Runner()
        monitor = NetworkMonitor(system="Windows", runner=runner, cache_ttl=60)

        first = monitor.snapshot(proxy_bypass=[], always_bypass=[])
        second = monitor.snapshot(proxy_bypass=["93.184.216.34"], always_bypass=[])

        self.assertFalse(next(flow for flow in first["flows"] if flow["remote_address"] == "93.184.216.34")["is_exception"])
        self.assertTrue(next(flow for flow in second["flows"] if flow["remote_address"] == "93.184.216.34")["is_exception"])
        self.assertEqual(sum(1 for call in runner.calls if call[0] == "netstat"), 1)

    def test_unsupported_platform_returns_empty_snapshot(self):
        monitor = NetworkMonitor(system="Linux")

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
