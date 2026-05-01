import unittest

from cleannet.background_tasks import BackgroundTaskContext, BackgroundTaskManager


class _Logger:
    def __init__(self):
        self.messages = []

    def info(self, message):
        self.messages.append(("info", message))


class _Writer:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _StrategyCache:
    def __init__(self):
        self.saved = 0
        self.rows = []

    def _save_if_needed(self):
        self.saved += 1

    def iter_site_data(self):
        return self.rows


async def _sleep(_seconds):
    pass


class BackgroundTaskTests(unittest.IsolatedAsyncioTestCase):
    def _context(self, **overrides):
        state = {
            "ping": -1,
            "running": False,
            "saved": 0,
            "notifications": [],
            "resolved": 0,
            "tasks": [],
            "time": 1000.0,
        }
        config = {
            "sites": {
                "example": {
                    "enabled": True,
                    "domains": ["example.com"],
                    "dns_resolve": ["example.com"],
                }
            }
        }
        cache = overrides.pop("strategy_cache", _StrategyCache())

        async def resolve_bypass_ips():
            state["resolved"] += 1
            return True

        def create_task(coro):
            state["tasks"].append(coro)
            coro.close()
            return coro

        base = {
            "logger": _Logger(),
            "get_config": lambda: config,
            "get_running": lambda: state["running"],
            "set_ping_ms": lambda value: state.__setitem__("ping", value),
            "ping_history": [],
            "test_results": {},
            "get_bypass_ips": lambda: ["1.1.1.1"],
            "get_bypass_domains": lambda: ["example.com"],
            "local_host": "127.0.0.1",
            "local_port": 8080,
            "health_check_interval": 1,
            "ip_update_interval": 1,
            "ping_target_host": "1.1.1.1",
            "strategy_retest_interval": 10,
            "resolve_bypass_ips": resolve_bypass_ips,
            "notify": lambda title, message: state["notifications"].append((title, message)),
            "strategy_cache": cache,
            "save_stats": lambda: state.__setitem__("saved", state["saved"] + 1),
            "ensure_proxy_enabled": lambda: state.__setitem__("ensured", state.get("ensured", 0) + 1),
            "parse_iso": lambda value: float(value) if value else None,
            "now_iso": lambda: "now",
            "sleep": _sleep,
            "perf_counter": lambda: state["time"],
            "time_func": lambda: state["time"],
            "create_task": create_task,
        }
        base.update(overrides)
        return BackgroundTaskContext(**base), state, cache

    async def test_measure_ping_success_updates_history(self):
        async def open_connection(host, port):
            self.assertEqual((host, port), ("1.1.1.1", 443))
            return object(), _Writer()

        ctx, state, _cache = self._context(open_connection=open_connection)
        manager = BackgroundTaskManager(ctx)

        ping = await manager.measure_ping()

        self.assertEqual(ping, 0)
        self.assertEqual(state["ping"], 0)
        self.assertEqual(ctx.ping_history, [0])

    async def test_measure_ping_failure_sets_minus_one(self):
        async def open_connection(_host, _port):
            raise OSError("nope")

        ctx, state, _cache = self._context(open_connection=open_connection)
        manager = BackgroundTaskManager(ctx)

        ping = await manager.measure_ping()

        self.assertEqual(ping, -1)
        self.assertEqual(state["ping"], -1)

    async def test_test_site_connection_uses_injected_tester(self):
        tested = []

        def site_tester(host, port, domain):
            tested.append((host, port, domain))

        ctx, _state, _cache = self._context(site_tester=site_tester)
        manager = BackgroundTaskManager(ctx)

        result = await manager.test_site_connection("example")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(tested, [("127.0.0.1", 8080, "example.com")])
        self.assertIn("example", ctx.test_results)

    async def test_test_site_connection_missing_site_returns_fail(self):
        ctx, _state, _cache = self._context()
        manager = BackgroundTaskManager(ctx)

        result = await manager.test_site_connection("missing")

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["error"], "Site not found")

    async def test_strategy_retest_loop_expires_old_failures_once(self):
        cache = _StrategyCache()
        cache.rows = [
            (
                "example",
                {
                    "best_strategy": None,
                    "failures": {
                        "direct": {"last_fail": "900"},
                        "host_split": {"last_fail": "995"},
                    },
                },
            )
        ]
        state = {"calls": 0}

        def get_running():
            state["calls"] += 1
            if state["calls"] <= 2:
                return True
            return False

        ctx, _state, _cache = self._context(strategy_cache=cache, get_running=get_running)
        manager = BackgroundTaskManager(ctx)

        await manager.strategy_retest_loop()

        failures = cache.rows[0][1]["failures"]
        self.assertNotIn("direct", failures)
        self.assertIn("host_split", failures)
        self.assertEqual(cache.saved, 1)

    async def test_proxy_ownership_loop_repairs_while_running(self):
        state = {"calls": 0}

        def get_running():
            state["calls"] += 1
            return state["calls"] <= 2

        repairs = {"count": 0}
        ctx, _state, _cache = self._context(
            get_running=get_running,
            ensure_proxy_enabled=lambda: repairs.__setitem__("count", repairs["count"] + 1),
        )
        manager = BackgroundTaskManager(ctx)

        await manager.proxy_ownership_loop()

        self.assertEqual(repairs["count"], 2)


if __name__ == "__main__":
    unittest.main()
