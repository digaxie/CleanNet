import unittest
from unittest.mock import patch

from cleannet.tray import (
    TrayManager,
    TrayRuntimeContext,
    build_full_shutdown_prompt,
    build_status_title,
)


class _Logger:
    def __init__(self):
        self.messages = []

    def info(self, message):
        self.messages.append(("info", message))

    def error(self, message):
        self.messages.append(("error", message))


class _Loop:
    def __init__(self):
        self.calls = []

    def call_soon_threadsafe(self, callback):
        self.calls.append(callback)
        callback()


class _Event:
    def __init__(self):
        self.set_count = 0

    def set(self):
        self.set_count += 1


class _Icon:
    def __init__(self):
        self.stopped = False

    def stop(self):
        self.stopped = True


async def _resolve_bypass_ips():
    return None


class TrayTests(unittest.TestCase):
    def _manager(self):
        state = {"running": True, "saved": 0, "proxy": [], "released": 0}
        loop = _Loop()
        event = _Event()
        logger = _Logger()
        manager = TrayManager(
            TrayRuntimeContext(
                version="9.9.9",
                logger=logger,
                local_host="127.0.0.1",
                web_port=8888,
                log_file="missing.log",
                app_file="app.pyw",
                python_executable="pythonw.exe",
                get_status=lambda: "running",
                get_ping_ms=lambda: 42,
                get_loop=lambda: loop,
                get_shutdown_event=lambda: event,
                set_running=lambda value: state.__setitem__("running", value),
                force_save=lambda: state.__setitem__("saved", state["saved"] + 1),
                set_proxy_enabled=lambda value: state["proxy"].append(value),
                release_instance_lock=lambda: state.__setitem__("released", state["released"] + 1),
                resolve_bypass_ips=_resolve_bypass_ips,
            )
        )
        return manager, state, loop, event, logger

    def test_status_title_and_prompt_text(self):
        self.assertEqual(build_status_title("running", 42), "CleanNet - Active | 42ms")
        self.assertEqual(build_status_title("stopped", -1), "CleanNet - Stopped")
        self.assertIn("Tam Kapatma", build_full_shutdown_prompt("tr")[0])
        self.assertIn("Vollstaendiges", build_full_shutdown_prompt("de")[0])
        self.assertIn("Full Shutdown", build_full_shutdown_prompt("en")[0])

    def test_exit_saves_state_clears_proxy_and_signals_shutdown(self):
        manager, state, loop, event, logger = self._manager()
        icon = _Icon()

        manager.exit(icon)

        self.assertFalse(state["running"])
        self.assertEqual(state["saved"], 1)
        self.assertEqual(state["proxy"], [False])
        self.assertEqual(len(loop.calls), 1)
        self.assertEqual(event.set_count, 1)
        self.assertTrue(icon.stopped)
        self.assertIn(("info", "User exit"), logger.messages)

    def test_restart_releases_lock_and_spawns_delayed_process(self):
        manager, state, _loop, event, _logger = self._manager()
        icon = _Icon()

        with patch("cleannet.tray.subprocess.Popen") as popen:
            manager.restart(icon)

        self.assertFalse(state["running"])
        self.assertEqual(state["released"], 1)
        self.assertEqual(event.set_count, 1)
        self.assertTrue(icon.stopped)
        popen.assert_called_once()
        self.assertIn("app.pyw", popen.call_args.args[0][2])


if __name__ == "__main__":
    unittest.main()
