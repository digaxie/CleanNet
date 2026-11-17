"""Strategy names, groups, and background training profiles."""

from __future__ import annotations


STRATEGY_ORDER = [
    "direct",
    "host_split",
    "fragment_light",
    "tls_record_frag",
    "fragment_burst",
    "desync",
    "fragment_heavy",
    "sni_shuffle",
    "fake_tls_inject",
    "triple_split",
    "sni_padding",
    "reverse_frag",
    "slow_drip",
    "oob_inline",
    "dot_shuffle",
    "tls_multi_record",
    "tls_mixed_delay",
    "sni_split_byte",
    "header_fragment",
    "tls_zero_frag",
    "tls_frag_overlap",
    "tls_version_mix",
    "tls_random_pad_frag",
    "tls_interleaved_ccs",
    "tcp_window_frag",
    "sni_multi_record",
    "sni_tcp_drip",
    "tls_record_tcp_split",
    "tls_record_long_delay",
]

# Strategies kept only so existing configs that lock a site to them keep working.
# They are never tried automatically, by the AI, the strategy cache or training:
# * sni_padding, dot_shuffle change ClientHello *content*. The server answers with a
#   ServerHello (so they were scored as successes), but its TLS transcript no longer
#   matches the browser's and the real connection fails right after.
# * reverse_frag, tls_frag_overlap, tls_interleaved_ccs produce a handshake stream the
#   server can never accept (reordered, duplicated or alert-interrupted records).
RETIRED_STRATEGIES = frozenset({
    "sni_padding",
    "dot_shuffle",
    "reverse_frag",
    "tls_frag_overlap",
    "tls_interleaved_ccs",
})

# Order used for automatic selection, AI scoring and training probes.
AUTO_STRATEGY_ORDER = [name for name in STRATEGY_ORDER if name not in RETIRED_STRATEGIES]

AI_TRAIN_PROFILES = {
    "light": {"interval": 1800, "probes": 3, "label": "Light"},
    "medium": {"interval": 600, "probes": 5, "label": "Medium"},
    "heavy": {"interval": 120, "probes": 8, "label": "Heavy"},
    "nonstop": {"interval": 15, "probes": 10, "label": "Nonstop 24/7"},
}

STRATEGY_GROUPS = {
    "fragmentation": ["fragment_light", "fragment_burst", "fragment_heavy", "header_fragment", "sni_tcp_drip"],
    "tls_record": [
        "tls_record_frag",
        "tls_multi_record",
        "tls_mixed_delay",
        "tls_zero_frag",
        "tls_version_mix",
        "tls_random_pad_frag",
        "tls_record_tcp_split",
        "tls_record_long_delay",
    ],
    "sni_based": ["sni_shuffle", "sni_split_byte", "sni_multi_record", "host_split"],
    "injection": ["fake_tls_inject", "desync", "oob_inline"],
    "split": ["triple_split", "slow_drip"],
    "transport": ["tcp_window_frag"],
    "direct": ["direct"],
    # Own group so AI sibling-score sharing never boosts them from working strategies.
    "retired": sorted(RETIRED_STRATEGIES),
}


def build_strategy_to_group(groups: dict[str, list[str]] | None = None) -> dict[str, str]:
    result: dict[str, str] = {}
    for group, strategies in (groups or STRATEGY_GROUPS).items():
        for strategy in strategies:
            result[strategy] = group
    return result


STRATEGY_TO_GROUP = build_strategy_to_group()


def normalize_train_intensity(value: str | None, fallback: str = "light") -> str:
    if value in AI_TRAIN_PROFILES:
        return value
    if not fallback:
        return ""
    return fallback if fallback in AI_TRAIN_PROFILES else "light"
