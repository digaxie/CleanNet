import json
import logging
import os
import tempfile
import unittest
from unittest.mock import patch

import cleannet.windows_integration as wi
from cleannet.uninstall_cleanup import run_cleanup

QUIET = logging.getLogger("test.cleanup")
QUIET.addHandler(logging.NullHandler())
QUIET.propagate = False


def _blob(counter: int, flags: int, server: bytes = b"127.0.0.1:8080") -> bytes:
    return (
        bytes([0x46, 0, 0, 0])
        + counter.to_bytes(4, "little")
        + flags.to_bytes(4, "little")
        + len(server).to_bytes(4, "little")
        + server
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
    )


class FakeWinreg:
    """In-memory HKCU with the two keys CleanNet touches."""

    HKEY_CURRENT_USER = "HKCU"
    KEY_READ = 1
    KEY_ALL_ACCESS = 2
    REG_SZ = 1
    REG_BINARY = 3
    REG_DWORD = 4

    def __init__(self):
        self.keys = {
            wi.INTERNET_SETTINGS_KEY: {},
            wi.CONNECTIONS_KEY: {},
            wi.AUTOSTART_REG_KEY: {},
        }

    def OpenKey(self, _root, path, *_args):
        return path

    def CloseKey(self, _key):
        pass

    def QueryValueEx(self, key, name):
        try:
            return self.keys[key][name]
        except KeyError:
            raise FileNotFoundError(name)

    def SetValueEx(self, key, name, _reserved, value_type, value):
        self.keys[key][name] = (value, value_type)

    def DeleteValue(self, key, name):
        try:
            del self.keys[key][name]
        except KeyError:
            raise FileNotFoundError(name)

    def value(self, key, name):
        return self.keys[key][name][0]


def _flags(blob) -> int:
    return wi._unpack_dword(bytes(blob), 8)


def _counter(blob) -> int:
    return wi._unpack_dword(bytes(blob), 4)


class ProxyRestoreTests(unittest.TestCase):
    def setUp(self):
        self.reg = FakeWinreg()
        patches = [
            patch.object(wi, "winreg", self.reg),
            patch.object(wi, "_refresh_proxy_settings"),
            patch.object(wi.time, "sleep"),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def _set_cleannet_proxy_on(self, counter: int = 50):
        self.reg.SetValueEx(wi.INTERNET_SETTINGS_KEY, "ProxyEnable", 0, 4, 1)
        self.reg.SetValueEx(wi.INTERNET_SETTINGS_KEY, "ProxyServer", 0, 1, "127.0.0.1:8080")
        for name in ("DefaultConnectionSettings", "SavedLegacySettings"):
            self.reg.SetValueEx(wi.CONNECTIONS_KEY, name, 0, 3, _blob(counter, 0x0B))

    def _backup_state(self, enable: int, server: str, blob: bytes) -> dict:
        return {
            "ProxyEnable": {"exists": True, "value": enable, "type": 4},
            "ProxyServer": {"exists": True, "value": server, "type": 1},
            "ProxyOverride": {"exists": False, "value": None, "type": None},
            "ConnectionSettings": {
                name: {"exists": True, "value": list(blob), "type": 3}
                for name in ("DefaultConnectionSettings", "SavedLegacySettings")
            },
        }

    def test_restore_writes_newer_counter_and_flag_matching_proxy_enable(self):
        self._set_cleannet_proxy_on(counter=50)
        # Older backup whose blob still carries the proxy flag while ProxyEnable was 0.
        state = self._backup_state(0, "127.0.0.1:8080", _blob(7, 0x0B))

        self.assertTrue(wi._restore_proxy_state(state, "127.0.0.1", 8080))

        self.assertEqual(self.reg.value(wi.INTERNET_SETTINGS_KEY, "ProxyEnable"), 0)
        for name in ("DefaultConnectionSettings", "SavedLegacySettings"):
            blob = self.reg.value(wi.CONNECTIONS_KEY, name)
            self.assertEqual(_flags(blob) & wi.CONNECTION_PROXY_FLAG, 0)
            self.assertEqual(_flags(blob) & 0x09, 0x09)
            self.assertGreater(_counter(blob), 50)

    def test_restore_keeps_a_users_own_proxy_on(self):
        self._set_cleannet_proxy_on(counter=10)
        state = self._backup_state(1, "corp-proxy:3128", _blob(4, 0x03, b"corp-proxy:3128"))

        self.assertTrue(wi._restore_proxy_state(state, "127.0.0.1", 8080))

        self.assertEqual(self.reg.value(wi.INTERNET_SETTINGS_KEY, "ProxyEnable"), 1)
        self.assertEqual(self.reg.value(wi.INTERNET_SETTINGS_KEY, "ProxyServer"), "corp-proxy:3128")
        blob = self.reg.value(wi.CONNECTIONS_KEY, "DefaultConnectionSettings")
        self.assertTrue(_flags(blob) & wi.CONNECTION_PROXY_FLAG)
        self.assertIn(b"corp-proxy:3128", bytes(blob))

    def test_backup_that_points_at_cleannet_is_restored_as_off(self):
        self._set_cleannet_proxy_on()
        state = self._backup_state(1, "127.0.0.1:8080", _blob(3, 0x0B))

        wi._restore_proxy_state(state, "127.0.0.1", 8080)

        self.assertEqual(self.reg.value(wi.INTERNET_SETTINGS_KEY, "ProxyEnable"), 0)
        blob = self.reg.value(wi.CONNECTIONS_KEY, "SavedLegacySettings")
        self.assertEqual(_flags(blob) & wi.CONNECTION_PROXY_FLAG, 0)

    def test_confirm_reapplies_when_windows_writes_the_old_value_back(self):
        self._set_cleannet_proxy_on()
        self.reg.SetValueEx(wi.INTERNET_SETTINGS_KEY, "ProxyEnable", 0, 4, 0)
        refreshes = []

        def wininet_rewrites_once():
            refreshes.append(True)

        reads = iter([True, False])
        with (
            patch.object(wi, "_refresh_proxy_settings", wininet_rewrites_once),
            patch.object(wi, "_read_proxy_enable", lambda: next(reads)),
        ):
            self.assertTrue(wi._confirm_proxy_enable(False))
        self.assertEqual(len(refreshes), 1)
        self.assertEqual(_flags(self.reg.value(wi.CONNECTIONS_KEY, "DefaultConnectionSettings")) & 2, 0)

    def test_recover_without_backup_switches_off_a_dead_cleannet_proxy(self):
        self._set_cleannet_proxy_on()
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(wi.recover_orphaned_proxy("127.0.0.1", 8080, tmp))

        self.assertEqual(self.reg.value(wi.INTERNET_SETTINGS_KEY, "ProxyEnable"), 0)
        blob = self.reg.value(wi.CONNECTIONS_KEY, "DefaultConnectionSettings")
        self.assertEqual(_flags(blob) & wi.CONNECTION_PROXY_FLAG, 0)

    def test_cleanup_restores_backup_removes_autostart_and_keeps_data(self):
        self._set_cleannet_proxy_on(counter=20)
        self.reg.SetValueEx(wi.AUTOSTART_REG_KEY, "CleanNetDPIBypass", 0, 1, '"C:\\x\\CleanNet.exe"')
        with tempfile.TemporaryDirectory() as tmp:
            backup = {"version": 1, "state": self._backup_state(0, "", _blob(2, 0x09, b""))}
            with open(os.path.join(tmp, wi.PROXY_BACKUP_FILE), "w", encoding="utf-8") as f:
                json.dump(backup, f)
            with open(os.path.join(tmp, "config.json"), "w", encoding="utf-8") as f:
                json.dump({"proxy_port": 8080, "sites": {"a": {}}}, f)

            with patch.dict(os.environ, {"CLEANNET_DATA_DIR": tmp}):
                self.assertEqual(run_cleanup(os.path.join(tmp, "bypass_silent.pyw"), logger=QUIET), 0)

            self.assertFalse(os.path.exists(os.path.join(tmp, wi.PROXY_BACKUP_FILE)))
            self.assertTrue(os.path.exists(os.path.join(tmp, "config.json")))
        self.assertEqual(self.reg.value(wi.INTERNET_SETTINGS_KEY, "ProxyEnable"), 0)
        self.assertNotIn("CleanNetDPIBypass", self.reg.keys[wi.AUTOSTART_REG_KEY])

    def test_restore_proxy_only_keeps_autostart(self):
        self._set_cleannet_proxy_on()
        self.reg.SetValueEx(wi.AUTOSTART_REG_KEY, "CleanNetDPIBypass", 0, 1, '"C:\\x\\CleanNet.exe"')
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"CLEANNET_DATA_DIR": tmp}):
                run_cleanup(os.path.join(tmp, "bypass_silent.pyw"), remove_autostart=False, logger=QUIET)

        self.assertEqual(self.reg.value(wi.INTERNET_SETTINGS_KEY, "ProxyEnable"), 0)
        self.assertIn("CleanNetDPIBypass", self.reg.keys[wi.AUTOSTART_REG_KEY])


if __name__ == "__main__":
    unittest.main()
