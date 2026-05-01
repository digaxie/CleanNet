import unittest

from cleannet.proxy_engine import ProxyEngine, ProxyRuntimeContext
from cleannet.runtime import ConnectionTracker


class _Logger:
    def debug(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


class _Writer:
    def __init__(self):
        self.closed = False
        self.data = []

    def write(self, data):
        self.data.append(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True


class _Reader:
    def __init__(self, data=b""):
        self.data = data
        self.used = False

    async def read(self, _size):
        if self.used:
            return b""
        self.used = True
        return self.data


async def _direct_strategy(writer, data):
    writer.write(data)
    await writer.drain()


class _StrategyCache:
    pass


class _AiEngine:
    pass


class ProxyEngineTests(unittest.IsolatedAsyncioTestCase):
    def _context(self, *, open_connection=None, resolve_private=None):
        tracker = ConnectionTracker()

        async def default_open_connection(host, port):
            return _Reader(), _Writer()

        async def default_resolve_private(host):
            return [host]

        return ProxyRuntimeContext(
            logger=_Logger(),
            stats={"connections": 0, "strategy_tries": 0, "strategy_fallbacks": 0},
            site_stats={},
            strategy_history=[],
            domain_ips={},
            blocked_domains={},
            site_semaphores={},
            connection_tracker=tracker,
            strategy_cache=_StrategyCache(),
            ai_engine=_AiEngine(),
            strategy_funcs={"direct": _direct_strategy},
            direct_strategy=_direct_strategy,
            get_privacy_settings=lambda: {"hide_dns": False, "hide_sni": False},
            resolve_domain_privately=resolve_private or default_resolve_private,
            resolve_domain_doh=lambda host: [],
            is_ip_literal=lambda value: value.replace(".", "").isdigit(),
            hash_host=lambda host: f"<{host}>",
            find_site_for_host=lambda host: None,
            is_main_domain=lambda host, site: False,
            get_bypass_ip=lambda host: None,
            get_domain_ips=lambda host: [],
            get_site_ips=lambda host: [],
            record_privacy_event=lambda *args, **kwargs: None,
            doh_bootstrap_map={},
            global_sni_strategy="direct",
            strategy_success_timeout=0.1,
            blocked_domain_ttl=300,
            site_max_concurrent=24,
            open_connection=open_connection or default_open_connection,
        )

    async def test_try_connect_uses_alt_ip_after_first_failure(self):
        calls = []

        async def open_connection(host, port):
            calls.append((host, port))
            if host == "example.com":
                raise OSError("nope")
            return _Reader(), _Writer()

        engine = ProxyEngine(self._context(open_connection=open_connection))

        reader, writer = await engine.try_connect("example.com", 443, alt_ips=["203.0.113.10"])

        self.assertIsNotNone(reader)
        self.assertIsNotNone(writer)
        self.assertEqual(calls, [("example.com", 443), ("203.0.113.10", 443)])

    async def test_try_connect_blocks_when_privacy_dns_has_no_result(self):
        calls = []

        async def open_connection(host, port):
            calls.append((host, port))
            return _Reader(), _Writer()

        async def resolve_private(_host):
            return []

        engine = ProxyEngine(self._context(open_connection=open_connection, resolve_private=resolve_private))
        privacy_context = {}

        reader, writer = await engine.try_connect(
            "example.com",
            443,
            use_privacy_dns=True,
            privacy_context=privacy_context,
        )

        self.assertIsNone(reader)
        self.assertIsNone(writer)
        self.assertEqual(calls, [])
        self.assertEqual(privacy_context["dns_status"], "blocked")

    async def test_http_forward_releases_connection_on_upstream_failure(self):
        async def open_connection(_host, _port):
            raise OSError("upstream down")

        context = self._context(open_connection=open_connection)
        engine = ProxyEngine(context)

        await engine.handle_http_forward(
            b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n",
            _Reader(),
            _Writer(),
        )

        self.assertEqual(context.connection_tracker.count(), 0)

    async def test_invalid_connect_smoke_path_closes_writer(self):
        context = self._context()
        engine = ProxyEngine(context)
        writer = _Writer()

        await engine.handle_proxy_client(_Reader(b"CONNECT example.com HTTP/1.1\r\n\r\n"), writer)

        self.assertEqual(context.connection_tracker.count(), 0)
        self.assertTrue(writer.closed)


if __name__ == "__main__":
    unittest.main()

