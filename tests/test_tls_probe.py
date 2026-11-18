import asyncio
import os
import ssl
import unittest

from cleannet.strategies import StrategyRuntimeContext, build_strategy_funcs
from cleannet.tls_probe import (
    STATUS_FAILED,
    STATUS_INTERCEPTED,
    STATUS_UNVERIFIED,
    STATUS_VERIFIED,
    classify_tls_error,
    verified_probe,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
CERT = os.path.join(FIXTURES, "probe_cert.pem")
KEY = os.path.join(FIXTURES, "probe_key.pem")


async def _no_sleep(_seconds):
    pass


class VerifiedProbeTests(unittest.IsolatedAsyncioTestCase):
    """Real TLS handshakes against a local server with a self-signed probe.test cert."""

    async def asyncSetUp(self):
        server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_ctx.load_cert_chain(CERT, KEY)

        async def handle(reader, writer):
            try:
                await reader.read(1)
            except Exception:
                pass
            writer.close()

        self.server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_ctx)
        self.port = self.server.sockets[0].getsockname()[1]
        self.trusting = ssl.create_default_context(cafile=CERT)
        self.funcs = build_strategy_funcs(StrategyRuntimeContext(record_fragments=lambda _c: None, sleep=_no_sleep))

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()

    async def _probe(self, strategy="direct", host="probe.test", context=None, port=None):
        return await verified_probe(
            asyncio.open_connection,
            self.funcs[strategy],
            host,
            "127.0.0.1",
            port or self.port,
            timeout=5,
            context=context or self.trusting,
        )

    async def test_trusted_certificate_is_verified(self):
        result = await self._probe()

        self.assertEqual(result.status, STATUS_VERIFIED)
        self.assertTrue(result.success)
        self.assertTrue(result.tls_version.startswith("TLS"))

    async def test_framing_strategy_still_verifies(self):
        for name in ("tls_record_frag", "sni_multi_record", "tls_record_tcp_split"):
            with self.subTest(strategy=name):
                self.assertEqual((await self._probe(name)).status, STATUS_VERIFIED)

    async def test_certificate_for_other_host_is_interception(self):
        # DPI block pages present a valid certificate for their own name.
        result = await self._probe(host="discord.test")

        self.assertEqual(result.status, STATUS_INTERCEPTED)
        self.assertFalse(result.success)

    async def test_untrusted_chain_falls_back_to_unverified_handshake(self):
        result = await self._probe(context=ssl.create_default_context())

        self.assertEqual(result.status, STATUS_UNVERIFIED)
        self.assertTrue(result.success)

    async def test_content_changing_strategy_fails(self):
        # The old probe counted this as success because a ServerHello came back.
        result = await self._probe("dot_shuffle")

        self.assertEqual(result.status, STATUS_FAILED)

    async def test_server_that_closes_fails(self):
        async def close_at_once(reader, writer):
            writer.close()

        plain = await asyncio.start_server(close_at_once, "127.0.0.1", 0)
        try:
            result = await self._probe(port=plain.sockets[0].getsockname()[1])
        finally:
            plain.close()
            await plain.wait_closed()

        self.assertEqual(result.status, STATUS_FAILED)

    async def test_connect_failure_fails(self):
        async def refuse(_host, _port):
            raise ConnectionRefusedError("refused")

        result = await verified_probe(refuse, self.funcs["direct"], "probe.test", "127.0.0.1", 1, context=self.trusting)

        self.assertEqual(result.status, STATUS_FAILED)


class ClassifyTlsErrorTests(unittest.TestCase):
    def test_hostname_mismatch_is_interception(self):
        exc = ssl.SSLCertVerificationError()
        exc.verify_code = 62

        self.assertEqual(classify_tls_error(exc), STATUS_INTERCEPTED)

    def test_other_errors_are_failures(self):
        exc = ssl.SSLCertVerificationError()
        exc.verify_code = 20

        self.assertEqual(classify_tls_error(exc), STATUS_FAILED)
        self.assertEqual(classify_tls_error(ConnectionResetError()), STATUS_FAILED)


if __name__ == "__main__":
    unittest.main()
