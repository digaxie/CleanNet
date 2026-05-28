import unittest

from cleannet.training import TrainingManager, TrainingRuntimeContext, build_client_hello


class _Logger:
    def __getattr__(self, _name):
        return lambda *args, **kwargs: None


class _Reader:
    def __init__(self, payload: bytes):
        self.payload = payload

    async def read(self, _limit):
        payload = self.payload
        self.payload = b""
        return payload


class _Writer:
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True


class _AiEngine:
    def __init__(self):
        self.records = []
        self.restored = []
        self.cleared = []
        self.saved = 0

    def snapshot_site(self, site_name):
        return {"site": site_name, "before": True}

    def clear_site(self, site_name):
        self.cleared.append(site_name)

    def record(self, site_name, strategy, success, elapsed_ms):
        self.records.append((site_name, strategy, success, elapsed_ms))

    def restore_site(self, site_name, data):
        self.restored.append((site_name, data))

    def _do_save(self):
        self.saved += 1

    def _compute_global_reputation(self):
        pass

    def _get_site_ai(self, _site_name):
        return {"total_observations": 0, "recent": []}


class _StrategyCache:
    def __init__(self):
        self.successes = []
        self.failures = []
        self.cleared = []
        self.saved = 0

    def record_success(self, site_name, strategy, elapsed_ms):
        self.successes.append((site_name, strategy, elapsed_ms))

    def record_failure(self, site_name, strategy):
        self.failures.append((site_name, strategy))

    def clear_site(self, site_name):
        self.cleared.append(site_name)

    def _do_save(self):
        self.saved += 1


async def _strategy(writer, data):
    writer.write(data)
    await writer.drain()


async def _sleep(_seconds):
    pass


class TrainingTests(unittest.IsolatedAsyncioTestCase):
    def _context(self, **overrides):
        ai_engine = overrides.pop("ai_engine", _AiEngine())
        strategy_cache = overrides.pop("strategy_cache", _StrategyCache())
        training_state = overrides.pop(
            "training_state",
            {"active": False, "progress": {}, "results": {}, "previous_strategies": {}, "completed": False},
        )
        config = overrides.pop(
            "config",
            {
                "sites": {
                    "enabled": {"enabled": True, "dns_resolve": ["enabled.test"]},
                    "disabled": {"enabled": False, "dns_resolve": ["disabled.test"]},
                }
            },
        )
        base = {
            "logger": _Logger(),
            "get_config": lambda: config,
            "get_running": lambda: False,
            "get_ai_train_intensity": lambda: "light",
            "get_background_training_enabled": lambda: False,
            "training_state": training_state,
            "self_train_state": {
                "running": False,
                "last_run": 0,
                "total_probes": 0,
                "last_site": "",
                "last_strategy": "",
                "last_result": "",
                "cycle_count": 0,
            },
            "ai_engine": ai_engine,
            "strategy_cache": strategy_cache,
            "strategy_funcs": {"direct": _strategy, "host_split": _strategy},
            "strategy_order": ["direct", "host_split"],
            "ai_train_profiles": {"light": {"interval": 1, "probes": 1}},
            "ai_min_samples": 5,
            "get_bypass_ip": lambda domain: "1.1.1.1" if domain else None,
            "resolve_domain_doh": lambda _domain: ["1.1.1.1"],
            "hash_host": lambda host: f"<{host}>",
            "open_connection": lambda host, port: None,
            "sleep": _sleep,
        }
        base.update(overrides)
        return TrainingRuntimeContext(**base), ai_engine, strategy_cache

    def test_build_client_hello_contains_sni(self):
        hello = build_client_hello("example.com")

        self.assertEqual(hello[0], 0x16)
        self.assertIn(b"example.com", hello)
        self.assertEqual(hello[5], 0x01)

    async def test_probe_strategy_uses_connection_and_strategy(self):
        calls = []

        async def open_connection(host, port):
            calls.append((host, port))
            return _Reader(b"\x16\x03\x03"), _Writer()

        ctx, _ai, _cache = self._context(open_connection=open_connection)
        manager = TrainingManager(ctx)

        success, elapsed_ms = await manager.probe_strategy("1.1.1.1", "example.com", "direct")

        self.assertTrue(success)
        self.assertGreaterEqual(elapsed_ms, 0)
        self.assertEqual(calls, [("1.1.1.1", 443)])

    async def test_train_all_sites_only_runs_enabled_sites(self):
        ctx, _ai, _cache = self._context()
        manager = TrainingManager(ctx)
        trained = []

        async def fake_train_site(site_name):
            trained.append(site_name)

        manager.train_site = fake_train_site

        await manager.train_all_sites()

        self.assertEqual(trained, ["enabled"])
        self.assertFalse(ctx.training_state["active"])
        self.assertTrue(ctx.training_state["completed"])

    async def test_self_training_loop_stays_idle_when_background_training_disabled(self):
        state = {"running_checks": 0, "sleeps": []}

        def get_running():
            state["running_checks"] += 1
            return state["running_checks"] <= 1

        async def sleep(seconds):
            state["sleeps"].append(seconds)

        ctx, ai, cache = self._context(get_running=get_running, sleep=sleep)
        manager = TrainingManager(ctx)

        await manager.self_training_loop()

        self.assertEqual(state["sleeps"], [60])
        self.assertFalse(ctx.self_train_state["running"])
        self.assertEqual(ai.records, [])
        self.assertEqual(cache.successes, [])

    async def test_apply_and_revert_training(self):
        training_state = {
            "active": False,
            "progress": {},
            "results": {
                "example": {
                    "best_strategy": "direct",
                    "all_results": [
                        {"strategy": "direct", "success": True, "ms": 15},
                        {"strategy": "host_split", "success": False, "ms": 0},
                    ],
                }
            },
            "previous_strategies": {},
            "completed": True,
        }
        ctx, ai, cache = self._context(training_state=training_state)
        manager = TrainingManager(ctx)

        self.assertTrue(manager.apply_training("example"))
        self.assertEqual(len(ai.records), 6)
        self.assertEqual(len(cache.successes), 5)
        self.assertEqual(cache.failures, [("example", "host_split")])

        self.assertTrue(manager.revert_training("example"))
        self.assertEqual(ai.restored, [("example", {"site": "example", "before": True})])
        self.assertNotIn("example", training_state["previous_strategies"])


if __name__ == "__main__":
    unittest.main()
