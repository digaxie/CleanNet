import unittest

from cleannet.app import CleanNetApp, CleanNetAppContext


class _Logger:
    def __init__(self):
        self.messages = []

    def info(self, message):
        self.messages.append(("info", message))

    def warning(self, message):
        self.messages.append(("warning", message))

    def error(self, message):
        self.messages.append(("error", message))


class _Server:
    def __init__(self):
        self.closed = False
        self.waited = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        self.waited = True


class _Event:
    def __init__(self):
        self.waited = False
        self.set_called = False

    async def wait(self):
        self.waited = True

    def set(self):
        self.set_called = True


class _ProxyEngine:
    async def handle_proxy_client(self, _reader, _writer):
        return None


class _DashboardServer:
    async def handle_http(self, _reader, _writer):
        return None


class _BackgroundTasks:
    async def health_check_loop(self):
        return None

    async def proxy_ownership_loop(self):
        return None

    async def strategy_retest_loop(self):
        return None


class _TrainingManager:
    async def self_training_loop(self):
        return None


class _Lock:
    def __init__(self, acquired=True):
        self.acquired = acquired
        self.released = 0

    def acquire(self):
        return self.acquired

    def release(self):
        self.released += 1


class _Thread:
    def __init__(self, target=None, args=(), daemon=False):
        self.target = target
        self.args = args
        self.daemon = daemon

    def start(self):
        self.target(*self.args)


class _Loop:
    def call_soon_threadsafe(self, func):
        func()


class _TrayIcon:
    def __init__(self):
        self.ran = False

    def run(self):
        self.ran = True


class _TrayManager:
    def __init__(self, icon):
        self.icon = icon

    def setup(self):
        return self.icon


class _ExitCalled(Exception):
    def __init__(self, code):
        self.code = code


class _SessionWatcher:
    def __init__(self, on_session_end, logger):
        self.on_session_end = on_session_end
        self.logger = logger
        self.started = 0
        self.stopped = 0

    def start(self):
        self.started += 1

    def stop(self):
        self.stopped += 1


class CleanNetAppTests(unittest.IsolatedAsyncioTestCase):
    def _context(self, **overrides):
        state = {
            "proxy": [],
            "saved": 0,
            "stats": 0,
            "recover": 0,
            "tasks": 0,
            "urls": [],
        }
        logger = _Logger()

        def create_task(coro):
            state["tasks"] += 1
            coro.close()
            return None

        def exit_func(code):
            raise _ExitCalled(code)

        def ensure_proxy_enabled():
            state["ensured"] = state.get("ensured", 0) + 1

        values = dict(
            logger=logger,
            version="9.9.9",
            get_site_names=lambda: ["example"],
            local_host="127.0.0.1",
            local_port=8080,
            web_port=8888,
            proxy_engine=_ProxyEngine(),
            dashboard_server=_DashboardServer(),
            background_tasks=_BackgroundTasks(),
            training_manager=_TrainingManager(),
            tray_available=False,
            tray_manager=None,
            set_proxy_enabled=lambda enabled: state["proxy"].append(enabled),
            ensure_proxy_enabled=ensure_proxy_enabled,
            force_save=lambda: state.__setitem__("saved", state["saved"] + 1),
            save_stats=lambda: state.__setitem__("stats", state["stats"] + 1),
            recover_proxy=lambda: state.__setitem__("recover", state["recover"] + 1),
            open_url=lambda url: state["urls"].append(url),
            create_task=create_task,
            event_factory=_Event,
            exit_func=exit_func,
            logger_state=logger,
            state=state,
        )
        values.update(overrides)
        logger_state = values.pop("logger_state")
        state_ref = values.pop("state")
        return CleanNetAppContext(**values), logger_state, state_ref

    async def test_async_main_starts_servers_tasks_and_closes_servers(self):
        servers = []

        async def start_server(_handler, host, port):
            servers.append((host, port, _Server()))
            return servers[-1][2]

        ctx, logger, state = self._context(start_server=start_server)
        app = CleanNetApp(ctx)

        await app.async_main()

        self.assertTrue(app.running)
        self.assertEqual(app.status, "running")
        self.assertTrue(app.port_ready.is_set())
        self.assertEqual([(host, port) for host, port, _server in servers], [
            ("127.0.0.1", 8080),
            ("127.0.0.1", 8888),
        ])
        self.assertEqual(state["tasks"], 4)
        self.assertTrue(all(server.closed and server.waited for _host, _port, server in servers))
        self.assertIn(("info", "Proxy listening: 127.0.0.1:8080"), logger.messages)

    async def test_async_main_port_busy_sets_ready_without_running(self):
        async def start_server(_handler, _host, _port):
            raise OSError("busy")

        ctx, logger, _state = self._context(start_server=start_server)
        app = CleanNetApp(ctx)

        await app.async_main()

        self.assertFalse(app.running)
        self.assertTrue(app.port_ready.is_set())
        self.assertIn(("warning", "Port 8080 already in use"), logger.messages)

    def test_cleanup_handlers_save_restore_and_release_lock(self):
        ctx, _logger, state = self._context()
        app = CleanNetApp(ctx)
        app.instance_lock = _Lock()

        app.atexit_handler()

        self.assertEqual(state["saved"], 1)
        self.assertEqual(state["stats"], 1)
        self.assertEqual(state["recover"], 0)
        self.assertIsNone(app.instance_lock)

        app.instance_lock = _Lock()
        with self.assertRaises(_ExitCalled) as cm:
            app.cleanup_handler()

        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(state["proxy"], [])
        self.assertEqual(state["saved"], 2)
        self.assertEqual(state["stats"], 2)
        self.assertIsNone(app.instance_lock)

    def test_cleanup_handlers_restore_only_after_proxy_ownership(self):
        ctx, _logger, state = self._context()
        app = CleanNetApp(ctx)
        app.instance_lock = _Lock()
        app.proxy_owned = True

        app.atexit_handler()

        self.assertEqual(state["recover"], 1)
        self.assertFalse(app.proxy_owned)
        self.assertIsNone(app.instance_lock)

        app.instance_lock = _Lock()
        app.proxy_owned = True
        with self.assertRaises(_ExitCalled) as cm:
            app.cleanup_handler()

        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(state["proxy"], [False])
        self.assertFalse(app.proxy_owned)
        self.assertIsNone(app.instance_lock)

    def test_start_port_busy_does_not_toggle_proxy(self):
        event = _Event()

        ctx, _logger, state = self._context(
            event_factory=lambda: event,
            instance_factory=lambda _name: _Lock(),
            thread_factory=_Thread,
            new_event_loop=lambda: _Loop(),
        )
        app = CleanNetApp(ctx)

        def fake_run_async_loop(_loop):
            app.shutdown_event = event
            app.running = False
            app.status = "stopped"
            app.port_ready.set()

        app.run_async_loop = fake_run_async_loop

        with self.assertRaises(_ExitCalled) as cm:
            app.start()

        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(state["proxy"], [])
        self.assertEqual(state["recover"], 0)
        self.assertIsNone(app.instance_lock)

    def test_start_keeps_process_alive_when_tray_loop_returns_unexpectedly(self):
        event = _Event()
        icon = _TrayIcon()
        sleep_calls = {"count": 0}
        app_ref = {}

        def sleep(_seconds):
            sleep_calls["count"] += 1
            app_ref["app"].running = False

        ctx, logger, state = self._context(
            tray_available=True,
            tray_manager=_TrayManager(icon),
            event_factory=lambda: event,
            instance_factory=lambda _name: _Lock(),
            thread_factory=_Thread,
            new_event_loop=lambda: _Loop(),
            sleep=sleep,
        )
        app = CleanNetApp(ctx)
        app_ref["app"] = app

        def fake_run_async_loop(_loop):
            app.shutdown_event = event
            app.running = True
            app.status = "running"
            app.port_ready.set()

        app.run_async_loop = fake_run_async_loop

        app.start()

        self.assertTrue(icon.ran)
        self.assertEqual(sleep_calls["count"], 1)
        self.assertEqual(state["proxy"], [True, False])
        self.assertEqual(state["recover"], 1)
        self.assertEqual(state["ensured"], 1)
        self.assertEqual(app.status, "stopped")
        self.assertTrue(event.set_called)
        self.assertIn(("warning", "Tray loop ended unexpectedly; continuing without tray"), logger.messages)

    def test_start_waits_for_first_run_onboarding_before_proxy_enable(self):
        event = _Event()
        sleep_calls = {"count": 0}
        app_ref = {}

        def sleep(_seconds):
            sleep_calls["count"] += 1
            app_ref["app"].running = False

        ctx, logger, state = self._context(
            is_onboarding_complete=lambda: False,
            event_factory=lambda: event,
            instance_factory=lambda _name: _Lock(),
            thread_factory=_Thread,
            new_event_loop=lambda: _Loop(),
            sleep=sleep,
        )
        app = CleanNetApp(ctx)
        app_ref["app"] = app

        def fake_run_async_loop(_loop):
            app.shutdown_event = event
            app.running = True
            app.status = "running"
            app.port_ready.set()

        app.run_async_loop = fake_run_async_loop

        app.start()

        self.assertEqual(state["proxy"], [])
        self.assertEqual(state["recover"], 1)
        self.assertEqual(state["urls"], ["http://127.0.0.1:8888/?setup=1"])
        self.assertIn(("info", "First-run setup pending; system proxy is not enabled yet"), logger.messages)

    def test_enable_system_proxy_after_onboarding_sets_ownership_once(self):
        ctx, _logger, state = self._context()
        app = CleanNetApp(ctx)

        self.assertTrue(app.enable_system_proxy())
        self.assertTrue(app.enable_system_proxy())

        self.assertEqual(state["proxy"], [True])
        self.assertEqual(state["recover"], 1)
        self.assertTrue(app.proxy_owned)

    def test_on_session_end_restores_proxy_without_exiting(self):
        ctx, _logger, state = self._context()
        app = CleanNetApp(ctx)
        app.proxy_owned = True

        app.on_session_end()  # must not raise / must not call exit_func

        self.assertEqual(state["proxy"], [False])
        self.assertEqual(state["saved"], 1)
        self.assertEqual(state["stats"], 1)
        self.assertFalse(app.proxy_owned)

    def test_on_session_end_does_not_touch_proxy_when_not_owned(self):
        ctx, _logger, state = self._context()
        app = CleanNetApp(ctx)

        app.on_session_end()

        self.assertEqual(state["proxy"], [])
        self.assertEqual(state["saved"], 1)
        self.assertEqual(state["stats"], 1)

    def test_start_starts_and_stops_session_watcher(self):
        event = _Event()
        icon = _TrayIcon()
        app_ref = {}
        created = {}

        def sleep(_seconds):
            app_ref["app"].running = False

        def watcher_factory(on_session_end, logger):
            created["watcher"] = _SessionWatcher(on_session_end, logger)
            return created["watcher"]

        ctx, _logger, _state = self._context(
            tray_available=True,
            tray_manager=_TrayManager(icon),
            event_factory=lambda: event,
            instance_factory=lambda _name: _Lock(),
            thread_factory=_Thread,
            new_event_loop=lambda: _Loop(),
            sleep=sleep,
            session_watcher_factory=watcher_factory,
        )
        app = CleanNetApp(ctx)
        app_ref["app"] = app

        def fake_run_async_loop(_loop):
            app.shutdown_event = event
            app.running = True
            app.status = "running"
            app.port_ready.set()

        app.run_async_loop = fake_run_async_loop

        app.start()

        watcher = created["watcher"]
        self.assertEqual(watcher.started, 1)
        self.assertEqual(watcher.stopped, 1)
        self.assertEqual(watcher.on_session_end, app.on_session_end)
        self.assertIsNone(app.session_watcher)


if __name__ == "__main__":
    unittest.main()
