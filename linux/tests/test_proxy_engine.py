import asyncio
import unittest
from unittest import mock

from cleannet.proxy_engine import (
    HAPPY_EYEBALLS_DELAY,
    ProxyEngine,
    ProxyRuntimeContext,
    open_connection_dual_stack,
)
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
    def _context(self, *, open_connection=None, resolve_private=None, privacy=None):
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
            get_privacy_settings=lambda: privacy or {"hide_dns": False, "hide_sni": False},
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

    async def test_passthrough_uses_plain_tunnel_without_privacy_dns_or_sni_shield(self):
        calls = []
        private_resolutions = []
        privacy_events = []

        async def open_connection(host, port):
            calls.append((host, port))
            return _Reader(), _Writer()

        async def resolve_private(host):
            private_resolutions.append(host)
            return ["203.0.113.10"]

        context = self._context(
            open_connection=open_connection,
            resolve_private=resolve_private,
            privacy={"hide_dns": True, "hide_sni": True},
        )
        context.record_privacy_event = lambda *args, **kwargs: privacy_events.append((args, kwargs))
        engine = ProxyEngine(context)

        async def fail_if_called(*_args, **_kwargs):
            raise AssertionError("SNI shield should not run for passthrough domains")

        engine.forward_with_sni_shield = fail_if_called
        writer = _Writer()

        await engine.handle_proxy_client(_Reader(b"CONNECT api.openai.com:443 HTTP/1.1\r\n\r\n"), writer)

        self.assertEqual(calls, [("api.openai.com", 443)])
        self.assertEqual(private_resolutions, [])
        self.assertIn(b"HTTP/1.1 200 Connection Established\r\n\r\n", writer.data)
        self.assertEqual(privacy_events[0][1]["sni_status"], "direct")
        self.assertEqual(privacy_events[0][1]["sni_detail"], "passthrough tunnel")

    async def test_http_forward_never_uses_privacy_dns_or_blocks(self):
        # Regression: plain HTTP forward must connect via system DNS and never DoH-block,
        # even with privacy mode on. Apps whose HTTP client ignores the proxy bypass list
        # (e.g. launchers reaching localhost) were blackholed when DoH failed.
        calls = []
        private_resolutions = []

        async def open_connection(host, port):
            calls.append((host, port))
            return _Reader(), _Writer()

        async def resolve_private(host):
            private_resolutions.append(host)
            return []  # DoH "fails" - would block if privacy DNS were applied here

        context = self._context(
            open_connection=open_connection,
            resolve_private=resolve_private,
            privacy={"hide_dns": True, "hide_sni": True},
        )
        engine = ProxyEngine(context)

        await engine.handle_http_forward(
            b"GET http://localhost:35783/api/v1/installation/operations HTTP/1.1\r\nHost: localhost:35783\r\n\r\n",
            _Reader(),
            _Writer(),
        )

        self.assertEqual(calls, [("localhost", 35783)])  # connected directly
        self.assertEqual(private_resolutions, [])  # DoH never consulted -> never blocked

    async def test_default_connector_enables_happy_eyeballs(self):
        # Regression: on machines that advertise IPv6 but cannot route it, hostname
        # connects hung on the AAAA address until try_connect's 10s timeout fired
        # before IPv4 was ever tried (YouTube/Kick "connection failed" while
        # IPv4-only hosts worked). The default connector must stagger v6/v4.
        captured = {}

        async def fake_open_connection(host, port, **kwargs):
            captured["args"] = (host, port)
            captured["kwargs"] = kwargs
            return _Reader(), _Writer()

        with mock.patch("asyncio.open_connection", fake_open_connection):
            await open_connection_dual_stack("example.com", 443)

        self.assertEqual(captured["args"], ("example.com", 443))
        self.assertEqual(captured["kwargs"], {"happy_eyeballs_delay": HAPPY_EYEBALLS_DELAY})
        self.assertIs(
            ProxyRuntimeContext.__dataclass_fields__["open_connection"].default,
            open_connection_dual_stack,
        )


class _ChunkReader:
    """Reader that returns pre-split chunks, simulating TCP segmentation."""

    def __init__(self, *chunks):
        self.chunks = list(chunks)

    async def read(self, _size):
        return self.chunks.pop(0) if self.chunks else b""


def _client_hello(body_len):
    body = b"\x01" + b"x" * (body_len - 1)
    return b"\x16\x03\x01" + body_len.to_bytes(2, "big") + body


class ProxyEngineReadTests(unittest.IsolatedAsyncioTestCase):
    async def test_read_full_client_hello_waits_for_split_record(self):
        # Regression: strategies only received the first TCP read of a split ClientHello,
        # then rebuilt TLS records from the partial bytes and corrupted the handshake.
        hello = _client_hello(600)
        reader = _ChunkReader(hello[200:400], hello[400:])

        record, extra = await ProxyEngine.read_full_client_hello(reader, hello[:200])

        self.assertEqual(record, hello)
        self.assertEqual(extra, b"")

    async def test_read_full_client_hello_separates_trailing_bytes(self):
        hello = _client_hello(64)
        trailing = b"\x17\x03\x03\x00\x01z"

        record, extra = await ProxyEngine.read_full_client_hello(_ChunkReader(), hello + trailing)

        self.assertEqual(record, hello)
        self.assertEqual(extra, trailing)

    async def test_read_full_client_hello_passes_non_tls_through(self):
        record, extra = await ProxyEngine.read_full_client_hello(_ChunkReader(b"more"), b"GET / HTTP/1.1")

        self.assertEqual(record, b"GET / HTTP/1.1")
        self.assertEqual(extra, b"")

    async def test_read_request_head_collects_split_headers(self):
        reader = _ChunkReader(b"Cookie: " + b"a" * 5000 + b"\r\n", b"\r\n")

        head = await ProxyEngine.read_request_head(reader, b"GET http://example.com/ HTTP/1.1\r\n")

        self.assertTrue(head.endswith(b"\r\n\r\n"))
        self.assertIn(b"a" * 5000, head)

    async def test_get_request_mentioning_connect_is_not_treated_as_tunnel(self):
        calls = []

        async def open_connection(host, port):
            calls.append((host, port))
            return _Reader(), _Writer()

        context = ProxyEngineTests._context(None, open_connection=open_connection)
        engine = ProxyEngine(context)

        await engine.handle_proxy_client(
            _Reader(b"GET http://example.com/CONNECT HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            _Writer(),
        )

        self.assertEqual(calls, [("example.com", 80)])



class _RecordingCache:
    def __init__(self):
        self.failures = []

    def record_failure(self, site, strategy):
        self.failures.append((site, strategy))


class _RecordingAi:
    def __init__(self):
        self.records = []

    def record(self, site, strategy, success, ms):
        self.records.append((site, strategy, success, ms))


class ClientRejectionTests(unittest.IsolatedAsyncioTestCase):
    def test_small_alert_then_close_is_rejection(self):
        stats = {"client_bytes": 30, "server_bytes": 4000, "client_closed_first": True, "duration": 0.2}

        self.assertTrue(ProxyEngine.looks_rejected_by_client(stats))

    def test_healthy_or_cancelled_connections_are_not_rejections(self):
        base = {"client_bytes": 30, "server_bytes": 4000, "client_closed_first": True, "duration": 0.2}
        cases = {
            "finished sent": {**base, "client_bytes": 64},
            "server closed first": {**base, "client_closed_first": False},
            "cancelled race, nothing sent": {**base, "client_bytes": 0},
            "long-lived": {**base, "duration": 30.0},
        }
        for name, stats in cases.items():
            with self.subTest(case=name):
                self.assertFalse(ProxyEngine.looks_rejected_by_client(stats))
        self.assertFalse(ProxyEngine.looks_rejected_by_client(None))

    def test_record_client_rejection_turns_success_into_failure(self):
        context = ProxyEngineTests._context(None)
        context.strategy_cache = _RecordingCache()
        context.ai_engine = _RecordingAi()
        context.site_stats["discord"] = {"connections": 1, "successes": 1, "failures": 0, "total_ms": 50}
        verifications = []
        context.record_verification = lambda site, status, **kw: verifications.append((site, status, kw["source"]))

        ProxyEngine(context).record_client_rejection("discord", "tls_record_frag", "discord.com")

        self.assertEqual(context.strategy_cache.failures, [("discord", "tls_record_frag")])
        self.assertEqual(context.ai_engine.records, [("discord", "tls_record_frag", False, 0)])
        self.assertEqual(context.site_stats["discord"]["successes"], 0)
        self.assertEqual(context.site_stats["discord"]["failures"], 1)
        self.assertEqual(context.site_stats["discord"]["rejections"], 1)
        self.assertEqual(context.stats["client_rejections"], 1)
        self.assertEqual(verifications, [("discord", "rejected", "live")])
        self.assertTrue(context.strategy_history[-1]["rejected"])

    async def test_tunnel_reports_byte_counts_and_who_closed(self):
        client_reader = _ChunkReader(b"\x15\x03\x03\x00\x02\x02\x2a")

        class _SlowReader:
            async def read(self, _size):
                await asyncio.sleep(5)
                return b""

        stats = await ProxyEngine(ProxyEngineTests._context(None)).tunnel_plain(
            client_reader, _Writer(), _SlowReader(), _Writer()
        )

        self.assertEqual(stats["client_bytes"], 7)
        self.assertTrue(stats["client_closed_first"])
        self.assertTrue(ProxyEngine.looks_rejected_by_client(stats))


if __name__ == "__main__":
    unittest.main()
