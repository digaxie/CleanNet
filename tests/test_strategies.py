import unittest

from cleannet.strategies import (
    StrategyRuntimeContext,
    _find_extensions_length_offset,
    _find_sni_offset,
    build_strategy_funcs,
)
from cleannet.strategy_catalog import STRATEGY_ORDER
from cleannet.training import build_client_hello


class _Transport:
    def get_extra_info(self, _name):
        return None


class _Writer:
    def __init__(self):
        self.chunks = []
        self.transport = _Transport()

    def write(self, data):
        self.chunks.append(data)

    async def drain(self):
        pass


async def _sleep(_seconds):
    pass


class StrategyTests(unittest.IsolatedAsyncioTestCase):
    def _strategy_funcs(self):
        fragments = {"count": 0}
        funcs = build_strategy_funcs(
            StrategyRuntimeContext(
                record_fragments=lambda count: fragments.__setitem__("count", fragments["count"] + count),
                sleep=_sleep,
            )
        )
        return funcs, fragments

    def test_strategy_map_matches_catalog(self):
        funcs, _fragments = self._strategy_funcs()

        self.assertEqual(list(funcs.keys()), STRATEGY_ORDER)

    async def test_direct_writes_input_without_fragment_count(self):
        funcs, fragments = self._strategy_funcs()
        writer = _Writer()
        data = b"plain"

        await funcs["direct"](writer, data)

        self.assertEqual(writer.chunks, [data])
        self.assertEqual(fragments["count"], 0)

    async def test_host_split_fragments_tls_client_hello(self):
        funcs, fragments = self._strategy_funcs()
        writer = _Writer()
        hello = build_client_hello("example.com")

        await funcs["host_split"](writer, hello)

        self.assertGreaterEqual(len(writer.chunks), 2)
        self.assertEqual(b"".join(writer.chunks), hello)
        self.assertEqual(fragments["count"], 1)

    async def test_tls_record_frag_rewrites_as_tls_records(self):
        funcs, fragments = self._strategy_funcs()
        writer = _Writer()
        hello = build_client_hello("example.com")

        await funcs["tls_record_frag"](writer, hello)

        self.assertEqual(len(writer.chunks), 2)
        self.assertEqual(writer.chunks[0][0], 0x16)
        self.assertEqual(writer.chunks[1][0], 0x16)
        self.assertEqual(fragments["count"], 1)


def _handshake_bytes(stream):
    """Reassemble handshake (0x16) record payloads from a TLS byte stream."""
    out = b""
    pos = 0
    while pos + 5 <= len(stream):
        ctype = stream[pos]
        length = int.from_bytes(stream[pos + 3:pos + 5], "big")
        body = stream[pos + 5:pos + 5 + length]
        if ctype == 0x16:
            out += body
        pos += 5 + length
    return out


# Strategies that re-frame the ClientHello into several TLS records; the server must
# be able to reassemble exactly the original handshake message.
RECORD_PRESERVING = [
    "tls_record_frag",
    "desync",
    "sni_shuffle",
    "fake_tls_inject",
    "triple_split",
    "oob_inline",
    "tls_multi_record",
    "tls_mixed_delay",
    "sni_split_byte",
    "tls_zero_frag",
    "tls_version_mix",
    "tls_random_pad_frag",
    "tcp_window_frag",
]

# Strategies that only split the byte stream across TCP writes.
STREAM_PRESERVING = [
    "direct",
    "host_split",
    "fragment_light",
    "fragment_burst",
    "fragment_heavy",
    "slow_drip",
    "header_fragment",
]


class StrategyIntegrityTests(unittest.IsolatedAsyncioTestCase):
    def _funcs(self):
        return build_strategy_funcs(StrategyRuntimeContext(record_fragments=lambda _c: None, sleep=_sleep))

    async def test_record_strategies_preserve_handshake(self):
        hello = build_client_hello("discord.com")
        funcs = self._funcs()
        for name in RECORD_PRESERVING:
            with self.subTest(strategy=name):
                writer = _Writer()
                await funcs[name](writer, hello)
                self.assertEqual(_handshake_bytes(b"".join(writer.chunks)), hello[5:])

    async def test_stream_strategies_preserve_bytes(self):
        hello = build_client_hello("discord.com")
        funcs = self._funcs()
        for name in STREAM_PRESERVING:
            with self.subTest(strategy=name):
                writer = _Writer()
                await funcs[name](writer, hello)
                self.assertEqual(b"".join(writer.chunks), hello)

    async def test_sni_padding_produces_consistent_client_hello(self):
        # Regression: the padding extension was inserted without updating the
        # extensions-length field, so every padded ClientHello was malformed.
        hello = build_client_hello("discord.com")
        writer = _Writer()

        await self._funcs()["sni_padding"](writer, hello)
        out = b"".join(writer.chunks)

        self.assertEqual(len(out), len(hello) + 260)
        self.assertEqual(int.from_bytes(out[3:5], "big"), len(out) - 5)
        self.assertEqual(int.from_bytes(out[6:9], "big"), len(out) - 9)
        ext_len_off = _find_extensions_length_offset(out)
        self.assertEqual(ext_len_off + 2 + int.from_bytes(out[ext_len_off:ext_len_off + 2], "big"), len(out))
        sni_off = _find_sni_offset(out)
        self.assertEqual(out[sni_off:sni_off + 2], b"\x00\x00")
        self.assertIn(b"discord.com", out)


if __name__ == "__main__":
    unittest.main()
