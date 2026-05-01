import os
import tempfile
import unittest
from unittest.mock import patch

from cleannet.dashboard import DashboardRuntimeContext, DashboardServer, load_dashboard_html


class _Logger:
    def __getattr__(self, _name):
        return lambda *args, **kwargs: None


class _LogHandler:
    def get_entries_after(self, _after_id):
        return []


class _StrategyCache:
    def get_site_strategy_info(self, _site_name):
        return {"strategy": "auto", "time_ms": None}

    def reset_all(self):
        pass


class _AiEngine:
    def __init__(self):
        self.train_intensity = "light"

    def get_global_stats(self):
        return {"total_observations": 0}

    def get_site_insights(self, _site_name):
        return {}

    def set_train_intensity(self, value):
        if value not in {"light", "heavy"}:
            return False
        self.train_intensity = value
        return True

    def reset(self):
        pass


class _Reader:
    def __init__(self, request: bytes, body: bytes = b""):
        self._lines = request.splitlines(keepends=True)
        self._body = body

    async def readline(self):
        if not self._lines:
            return b""
        return self._lines.pop(0)

    async def read(self, _limit):
        body = self._body
        self._body = b""
        return body


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


async def _noop_async(*_args, **_kwargs):
    return None


class DashboardTests(unittest.TestCase):
    def test_loader_injects_version(self):
        load_dashboard_html.cache_clear()
        with tempfile.TemporaryDirectory() as tmp:
            assets = os.path.join(tmp, "assets")
            os.mkdir(assets)
            with open(os.path.join(assets, "dashboard.html"), "w", encoding="utf-8") as f:
                f.write("<span>__CLEANNET_VERSION__</span>")

            self.assertEqual(load_dashboard_html(tmp, "9.9.9"), "<span>9.9.9</span>")


class DashboardServerTests(unittest.IsolatedAsyncioTestCase):
    def _server(self):
        state = {"intensity": "light"}
        config = {
            "sites": {
                "example": {
                    "enabled": True,
                    "domains": ["example.com"],
                    "dns_resolve": ["example.com"],
                    "ips": [],
                }
            },
            "proxy_bypass": [],
            "privacy": {"hide_dns": False, "hide_sni": False},
            "performance": {
                "low_latency_mode": True,
                "background_training": False,
                "health_check_interval": 120,
                "ip_update_interval": 1800,
                "ping_target_host": "1.1.1.1",
            },
        }
        ctx = DashboardRuntimeContext(
            version="9.9.9",
            dashboard_html="<html>9.9.9</html>",
            logger=_Logger(),
            get_config=lambda: config,
            save_config=lambda: None,
            reload_config=lambda: True,
            resolve_bypass_ips=_noop_async,
            resolve_domain_doh=lambda _domain: [],
            strategy_cache=_StrategyCache(),
            ai_engine=_AiEngine(),
            get_ai_train_intensity=lambda: state["intensity"],
            set_ai_train_intensity=lambda value: state.__setitem__("intensity", value),
            ai_train_profiles={"light": {"label": "Light"}, "heavy": {"label": "Heavy"}},
            training_state={"active": False, "completed": False, "progress": {}, "results": {}, "previous_strategies": {}},
            self_train_state={"running": False, "last_run": 0, "total_probes": 0, "last_site": "", "last_result": "", "cycle_count": 0},
            train_all_sites=_noop_async,
            apply_training=lambda _site: None,
            revert_training=lambda _site: None,
            always_bypass=["localhost"],
            bypass_presets={},
            get_autostart=lambda: False,
            set_autostart=lambda _value: None,
            get_privacy_settings=lambda: {"hide_dns": False, "hide_sni": False},
            get_performance_settings=lambda: config["performance"],
            get_network_flows=lambda: {
                "supported": True,
                "flows": [
                    {
                        "process_name": "game.exe",
                        "pid": 123,
                        "protocol": "TCP",
                        "local_address": "127.0.0.1",
                        "local_port": 5555,
                        "remote_address": "203.0.113.10",
                        "remote_port": 443,
                        "state": "ESTABLISHED",
                        "exception_entry": "203.0.113.10",
                        "is_exception": "203.0.113.10" in config["proxy_bypass"],
                    }
                ],
                "summary": {"supported": True, "flow_count": 1, "addable_count": 1, "exception_count": 0, "top_processes": []},
                "error": "",
            },
            test_site_connection=_noop_async,
            get_running=lambda: False,
            get_status=lambda: "running",
            get_ping_ms=lambda: 12,
            get_start_time=lambda: None,
            get_bypass_ips=lambda: ["1.1.1.1"],
            get_active_connections=lambda: [],
            dashboard_log_handler=_LogHandler(),
            stats={"connections": 1, "fragments": 2, "ip_updates": 3, "last_ip_refresh": 0, "strategy_tries": 4, "strategy_fallbacks": 5},
            site_stats={"example": {"connections": 1, "successes": 1, "failures": 0, "total_ms": 42}},
            strategy_history=[],
            test_results={},
            site_privacy_state={},
            script_dir=".",
            local_host="127.0.0.1",
            local_port=8080,
            strategy_names=["direct", "host_split"],
        )
        return DashboardServer(ctx), state

    async def test_stats_endpoint_serves_json(self):
        server, _state = self._server()
        writer = _Writer()

        with patch("cleannet.dashboard.get_proxy_summary", return_value={"owned_by_cleannet": True}):
            await server.handle_http(_Reader(b"GET /api/stats HTTP/1.1\r\nHost: x\r\n\r\n"), writer)

        raw = bytes(writer.data)
        self.assertIn(b"200 OK", raw)
        self.assertIn(b'"status": "running"', raw)
        self.assertIn(b'"example"', raw)
        self.assertTrue(writer.closed)

    async def test_ai_train_intensity_post_updates_context(self):
        server, state = self._server()
        writer = _Writer()

        await server.handle_http(
            _Reader(
                b"POST /api/ai-train-intensity HTTP/1.1\r\nHost: x\r\n\r\n",
                b'{"intensity":"heavy"}',
            ),
            writer,
        )

        self.assertIn(b"200 OK", bytes(writer.data))
        self.assertEqual(state["intensity"], "heavy")

    async def test_performance_settings_endpoint_updates_config(self):
        server, _state = self._server()
        writer = _Writer()

        await server.handle_http(
            _Reader(
                b"POST /api/performance-settings HTTP/1.1\r\nHost: x\r\n\r\n",
                b'{"background_training":true,"health_check_interval":300,"ip_update_interval":900,"ping_target_host":"8.8.8.8"}',
            ),
            writer,
        )

        self.assertIn(b"200 OK", bytes(writer.data))
        self.assertTrue(server.ctx.get_config()["performance"]["background_training"])
        self.assertEqual(server.ctx.get_config()["performance"]["health_check_interval"], 300)
        self.assertEqual(server.ctx.get_config()["performance"]["ip_update_interval"], 900)
        self.assertEqual(server.ctx.get_config()["performance"]["ping_target_host"], "8.8.8.8")

    async def test_network_exception_endpoint_adds_single_and_process_entries(self):
        server, _state = self._server()

        writer = _Writer()
        await server.handle_http(
            _Reader(
                b"POST /api/network-exception HTTP/1.1\r\nHost: x\r\n\r\n",
                b'{"entry":"203.0.113.10","source":"network-flow"}',
            ),
            writer,
        )
        self.assertIn(b"200 OK", bytes(writer.data))
        self.assertEqual(server.ctx.get_config()["proxy_bypass"], ["203.0.113.10"])

        writer = _Writer()
        await server.handle_http(
            _Reader(
                b"POST /api/network-exception HTTP/1.1\r\nHost: x\r\n\r\n",
                b'{"pid":123,"mode":"current-process-endpoints"}',
            ),
            writer,
        )
        self.assertIn(b"200 OK", bytes(writer.data))
        self.assertEqual(server.ctx.get_config()["proxy_bypass"], ["203.0.113.10"])

    async def test_site_strategy_endpoint_validates_site_and_strategy(self):
        server, _state = self._server()

        writer = _Writer()
        await server.handle_http(
            _Reader(
                b"POST /api/site-strategy HTTP/1.1\r\nHost: x\r\n\r\n",
                b'{"site":"example","strategy":"host_split"}',
            ),
            writer,
        )
        self.assertIn(b"200 OK", bytes(writer.data))
        self.assertEqual(server.ctx.get_config()["sites"]["example"]["strategy"], "host_split")

        writer = _Writer()
        await server.handle_http(
            _Reader(
                b"POST /api/site-strategy HTTP/1.1\r\nHost: x\r\n\r\n",
                b'{"site":"example","strategy":"auto"}',
            ),
            writer,
        )
        self.assertIn(b"200 OK", bytes(writer.data))
        self.assertNotIn("strategy", server.ctx.get_config()["sites"]["example"])

        writer = _Writer()
        await server.handle_http(
            _Reader(
                b"POST /api/site-strategy HTTP/1.1\r\nHost: x\r\n\r\n",
                b'{"site":"example","strategy":"bad"}',
            ),
            writer,
        )
        self.assertIn(b"400 Bad Request", bytes(writer.data))


if __name__ == "__main__":
    unittest.main()
