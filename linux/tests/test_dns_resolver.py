import unittest

from cleannet.dns_resolver import (
    DnsResolver,
    DnsResolverContext,
    decode_chunked,
    is_ip_literal,
    read_http_response,
)


class _Logger:
    def __init__(self):
        self.messages = []

    def debug(self, message):
        self.messages.append(("debug", message))

    def info(self, message):
        self.messages.append(("info", message))

    def warning(self, message):
        self.messages.append(("warning", message))


class _Socket:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def recv(self, _size):
        if not self.chunks:
            return b""
        return self.chunks.pop(0)


class DnsResolverTests(unittest.IsolatedAsyncioTestCase):
    def _resolver(self, **overrides):
        logger = _Logger()
        state = {"bypass_ips": [], "time": 1000.0}
        domain_ips = overrides.pop("domain_ips", {})
        site_ips = overrides.pop("site_ips", {})
        privacy_cache = overrides.pop("privacy_cache", {})
        site_dns = overrides.pop("site_dns", {"example": ["example.com", "cdn.example.com"]})
        stats = overrides.pop("stats", {"ip_updates": 0})
        ctx = DnsResolverContext(
            logger=logger,
            domain_ips=domain_ips,
            site_ips=site_ips,
            privacy_cache=privacy_cache,
            stats=stats,
            get_site_dns=lambda: site_dns,
            set_bypass_ips=lambda ips: state.__setitem__("bypass_ips", list(ips)),
            hash_host=lambda host: f"<{host}>",
            privacy_cache_ttl=900,
            time_func=lambda: state["time"],
        )
        resolver = DnsResolver(ctx, providers=[], fallback_opener=object())
        return resolver, state, logger

    def test_decode_chunked_and_content_length_response(self):
        self.assertEqual(decode_chunked(b"4\r\ntest\r\n0\r\n\r\n"), b"test")

        body = read_http_response(_Socket([
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe",
            b"llo",
        ]))

        self.assertEqual(body, b"hello")

    def test_is_ip_literal(self):
        self.assertTrue(is_ip_literal("1.1.1.1"))
        self.assertTrue(is_ip_literal("2606:4700:4700::1111"))
        self.assertFalse(is_ip_literal("example.com"))

    async def test_private_resolution_uses_known_domain_ips_and_cache(self):
        resolver, _state, _logger = self._resolver(domain_ips={"example.com": ["1.1.1.1"]})

        first = await resolver.resolve_domain_privately("example.com")
        resolver.ctx.domain_ips.clear()
        second = await resolver.resolve_domain_privately("example.com")

        self.assertEqual(first, ["1.1.1.1"])
        self.assertEqual(second, ["1.1.1.1"])
        self.assertEqual(resolver.ctx.privacy_cache["example.com"]["ips"], ["1.1.1.1"])

    async def test_private_resolution_warns_when_doh_fails(self):
        resolver, _state, logger = self._resolver()
        resolver.resolve_domain_doh = lambda _domain: []

        ips = await resolver.resolve_domain_privately("missing.test")

        self.assertEqual(ips, [])
        self.assertEqual(logger.messages[-1][0], "warning")

    async def test_resolve_bypass_ips_updates_domain_site_and_stats(self):
        resolver, state, _logger = self._resolver()
        answers = {
            "example.com": ["1.1.1.1"],
            "cdn.example.com": ["2.2.2.2"],
        }
        resolver.resolve_domain_doh = lambda domain: answers.get(domain, [])

        ok = await resolver.resolve_bypass_ips()

        self.assertTrue(ok)
        self.assertEqual(set(state["bypass_ips"]), {"1.1.1.1", "2.2.2.2"})
        self.assertEqual(set(resolver.ctx.site_ips["example"]), {"1.1.1.1", "2.2.2.2"})
        self.assertEqual(resolver.ctx.stats["ip_updates"], 1)


if __name__ == "__main__":
    unittest.main()
