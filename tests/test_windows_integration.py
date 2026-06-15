import unittest
from unittest.mock import patch

import cleannet.windows_integration as wi
from cleannet.windows_integration import (
    CONNECTION_PROXY_FLAG,
    SessionEndWatcher,
    _build_connection_settings_blob,
    _unpack_dword,
    build_bypass_list,
    ensure_system_proxy_enabled,
    is_app_proxy_server,
    set_system_proxy,
)


class WindowsIntegrationTests(unittest.TestCase):
    def test_build_bypass_list_deduplicates_preserving_order(self):
        result = build_bypass_list(["localhost", "127.*"], ["127.*", "*.example.com"])

        self.assertEqual(result, "localhost;127.*;*.example.com")

    def test_is_app_proxy_server(self):
        self.assertTrue(is_app_proxy_server("127.0.0.1:8080", "127.0.0.1", 8080))
        self.assertFalse(is_app_proxy_server("127.0.0.1:8888", "127.0.0.1", 8080))
        self.assertFalse(is_app_proxy_server(None, "127.0.0.1", 8080))

    def test_ensure_system_proxy_enabled_repairs_only_when_needed(self):
        class _Key:
            pass

        writes = []
        closed = []
        key = _Key()

        class _Winreg:
            HKEY_CURRENT_USER = object()
            KEY_ALL_ACCESS = 1
            REG_DWORD = 4
            REG_SZ = 1

            def OpenKey(self, *_args):
                return key

            def SetValueEx(self, _key, name, _reserved, value_type, value):
                writes.append((name, value_type, value))

            def CloseKey(self, item):
                closed.append(item)

        with (
            patch("cleannet.windows_integration.winreg", _Winreg()),
            patch("cleannet.windows_integration.read_proxy_state", return_value={
                "ProxyEnable": {"value": 0},
                "ProxyServer": {"value": "127.0.0.1:8080"},
                "ProxyOverride": {"value": ""},
            }),
            patch("cleannet.windows_integration._refresh_proxy_settings") as refresh,
        ):
            self.assertTrue(ensure_system_proxy_enabled(
                "127.0.0.1",
                8080,
                ["localhost"],
                ["*.example.com"],
            ))

        expected_writes = [
            ("ProxyEnable", 4, 1),
            ("ProxyServer", 1, "127.0.0.1:8080"),
            ("ProxyOverride", 1, "localhost;*.example.com"),
        ]
        self.assertEqual(writes, expected_writes + expected_writes)
        self.assertEqual(closed, [key, key, key, key])
        refresh.assert_called_once()

    def test_connection_settings_blob_sets_manual_proxy_flag_and_strings(self):
        existing = (
            bytes([0x46, 0, 0, 0])
            + (7).to_bytes(4, "little")
            + (0x09).to_bytes(4, "little")
            + (3).to_bytes(4, "little")
            + b"old"
            + (4).to_bytes(4, "little")
            + b"skip"
            + (0).to_bytes(4, "little")
        )

        blob = _build_connection_settings_blob(
            existing,
            True,
            "127.0.0.1:8080",
            "localhost;127.*",
        )

        self.assertEqual(_unpack_dword(blob, 4), 8)
        self.assertTrue(_unpack_dword(blob, 8) & CONNECTION_PROXY_FLAG)
        proxy_len = _unpack_dword(blob, 12)
        self.assertEqual(blob[16 : 16 + proxy_len], b"127.0.0.1:8080")
        bypass_len_offset = 16 + proxy_len
        bypass_len = _unpack_dword(blob, bypass_len_offset)
        bypass_start = bypass_len_offset + 4
        self.assertEqual(blob[bypass_start : bypass_start + bypass_len], b"localhost;127.*")

    def test_connection_settings_blob_clears_only_manual_proxy_flag(self):
        existing = (
            bytes([0x46, 0, 0, 0])
            + (7).to_bytes(4, "little")
            + (0x0B).to_bytes(4, "little")
            + (14).to_bytes(4, "little")
            + b"127.0.0.1:8080"
            + (0).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
        )

        blob = _build_connection_settings_blob(existing, False, "127.0.0.1:8080", "")

        self.assertFalse(_unpack_dword(blob, 8) & CONNECTION_PROXY_FLAG)
        self.assertEqual(_unpack_dword(blob, 8) & 0x09, 0x09)

    def test_set_system_proxy_disable_without_backup_is_noop_for_non_app_proxy(self):
        class _Winreg:
            HKEY_CURRENT_USER = object()
            KEY_ALL_ACCESS = 1
            REG_DWORD = 4

            def OpenKey(self, *_args):
                raise AssertionError("OpenKey should not be called for non-app proxy")

        with (
            patch("cleannet.windows_integration.winreg", _Winreg()),
            patch("cleannet.windows_integration.os.path.exists", return_value=False),
            patch("cleannet.windows_integration.read_proxy_state", return_value={
                "ProxyEnable": {"value": 1},
                "ProxyServer": {"value": "127.0.0.1:9999"},
                "ProxyOverride": {"value": ""},
            }),
            patch("cleannet.windows_integration._refresh_proxy_settings") as refresh,
        ):
            self.assertTrue(set_system_proxy(
                False,
                "127.0.0.1",
                8080,
                ["localhost"],
                [],
                "appdir",
            ))

        refresh.assert_not_called()


class SessionEndWatcherTests(unittest.TestCase):
    def test_fire_runs_callback_exactly_once(self):
        calls = {"n": 0}
        watcher = SessionEndWatcher(lambda: calls.__setitem__("n", calls["n"] + 1))

        watcher._fire()
        watcher._fire()

        self.assertEqual(calls["n"], 1)

    def test_fire_swallows_callback_errors(self):
        class _Logger:
            def __init__(self):
                self.errors = []

            def error(self, message):
                self.errors.append(message)

        def boom():
            raise RuntimeError("nope")

        logger = _Logger()
        watcher = SessionEndWatcher(boom, logger=logger)

        watcher._fire()  # must not raise

        self.assertTrue(logger.errors)

    def test_start_and_stop_are_safe_without_ctypes(self):
        watcher = SessionEndWatcher(lambda: None)
        with patch.object(wi, "ctypes", None):
            self.assertFalse(watcher.start())
            watcher.stop()  # must not raise


if __name__ == "__main__":
    unittest.main()
