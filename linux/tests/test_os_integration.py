import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cleannet import os_integration
from cleannet.os_integration import ProxyBackend


class OsIntegrationTests(unittest.TestCase):
    def test_detect_proxy_backend_prefers_kde_when_desktop_and_tools_exist(self):
        def which(name):
            if name in {"kwriteconfig6", "kreadconfig6", "gsettings"}:
                return f"/usr/bin/{name}"
            return None

        with patch.dict(os.environ, {"XDG_CURRENT_DESKTOP": "KDE"}, clear=True), patch("cleannet.os_integration.shutil.which", side_effect=which):
            backend = os_integration.detect_proxy_backend()

        self.assertEqual(backend.name, "kde")
        self.assertTrue(backend.supported)

    def test_detect_proxy_backend_uses_gnome_only_when_schema_exists(self):
        def which(name):
            return f"/usr/bin/{name}" if name == "gsettings" else None

        def run(args, _timeout=3.0):
            self.assertEqual(args, ["gsettings", "list-schemas"])
            return subprocess.CompletedProcess(args, 0, stdout="org.gnome.system.proxy\n", stderr="")

        with patch.dict(os.environ, {"XDG_CURRENT_DESKTOP": "XFCE"}, clear=True), patch("cleannet.os_integration.shutil.which", side_effect=which), patch("cleannet.os_integration._run", side_effect=run):
            backend = os_integration.detect_proxy_backend()

        self.assertEqual(backend.name, "gnome")
        self.assertTrue(backend.supported)

    def test_detect_proxy_backend_falls_back_to_env_file_without_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp, "XDG_CURRENT_DESKTOP": "XFCE"}, clear=True), patch("cleannet.os_integration.shutil.which", return_value=None):
                backend = os_integration.detect_proxy_backend()

            self.assertEqual(backend.name, "env-file")
            self.assertFalse(backend.supported)
            self.assertEqual(backend.manual_env_file, os.path.join(tmp, "cleannet", "proxy.env"))

    def test_env_fallback_writes_and_restores_proxy_file(self):
        with tempfile.TemporaryDirectory() as data_tmp, tempfile.TemporaryDirectory() as config_tmp:
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": config_tmp}, clear=True), patch("cleannet.os_integration.shutil.which", return_value=None):
                self.assertTrue(os_integration.set_system_proxy(True, "127.0.0.1", 8080, ["localhost"], ["*.example.com"], data_tmp))

                env_path = os.path.join(config_tmp, "cleannet", "proxy.env")
                backup_path = os.path.join(data_tmp, "linux_proxy_state.json")
                self.assertTrue(os.path.exists(env_path))
                self.assertTrue(os.path.exists(backup_path))
                with open(env_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.assertIn("export HTTP_PROXY=http://127.0.0.1:8080", content)
                self.assertIn("export NO_PROXY='localhost,*.example.com'", content)

                summary = os_integration.get_proxy_summary(data_tmp, "127.0.0.1", 8080)
                self.assertEqual(summary["backend"], "env-file")
                self.assertTrue(summary["owned_by_cleannet"])
                self.assertFalse(summary["supported"])

                self.assertTrue(os_integration.set_system_proxy(False, "127.0.0.1", 8080, [], [], data_tmp))
                self.assertFalse(os.path.exists(env_path))
                self.assertFalse(os.path.exists(backup_path))

    def test_set_system_proxy_returns_false_when_backend_write_fails(self):
        with tempfile.TemporaryDirectory() as data_tmp:
            with (
                patch("cleannet.os_integration.detect_proxy_backend", return_value=ProxyBackend("gnome", True)),
                patch("cleannet.os_integration._read_backend_state", return_value={"mode": "none"}),
                patch("cleannet.os_integration._enable_backend_proxy", side_effect=RuntimeError("boom")),
            ):
                self.assertFalse(os_integration.set_system_proxy(True, "127.0.0.1", 8080, [], [], data_tmp))


if __name__ == "__main__":
    unittest.main()
