import unittest

from cleannet.strategies import StrategyRuntimeContext, build_strategy_funcs
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


if __name__ == "__main__":
    unittest.main()
