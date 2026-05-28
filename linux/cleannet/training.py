"""Strategy training and self-training orchestration."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import random
import time
from typing import Any, Awaitable, Callable


Reader = Any
Writer = Any


@dataclass
class TrainingRuntimeContext:
    logger: Any
    get_config: Callable[[], dict[str, Any]]
    get_running: Callable[[], bool]
    get_ai_train_intensity: Callable[[], str]
    get_background_training_enabled: Callable[[], bool]
    training_state: dict[str, Any]
    self_train_state: dict[str, Any]
    ai_engine: Any
    strategy_cache: Any
    strategy_funcs: dict[str, Callable[[Writer, bytes], Awaitable[None]]]
    strategy_order: list[str]
    ai_train_profiles: dict[str, dict[str, Any]]
    ai_min_samples: int
    get_bypass_ip: Callable[[str], str | None]
    resolve_domain_doh: Callable[[str], list[str]]
    hash_host: Callable[[str], str]
    open_connection: Callable[..., Awaitable[tuple[Reader, Writer]]] = asyncio.open_connection
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep


def close_writer(writer: Writer | None) -> None:
    try:
        if writer:
            writer.close()
    except Exception:
        pass


def build_client_hello(hostname: str) -> bytes:
    """Build a minimal TLS 1.2 ClientHello with SNI for training probes."""
    host_bytes = hostname.encode("ascii")
    sni_ext = (
        b"\x00\x00"
        + (len(host_bytes) + 5).to_bytes(2, "big")
        + (len(host_bytes) + 3).to_bytes(2, "big")
        + b"\x00"
        + len(host_bytes).to_bytes(2, "big")
        + host_bytes
    )
    sv_ext = b"\x00\x2b\x00\x03\x02\x03\x03"
    extensions = sni_ext + sv_ext
    ciphers = (
        b"\x13\x01\x13\x02\x13\x03"
        b"\xc0\x2c\xc0\x2b\xc0\x30\xc0\x2f"
        b"\x00\x9e\x00\x9f\x00\x67\x00\x6b"
        b"\x00\xff"
    )
    client_random = (
        random.randbytes(32)
        if hasattr(random, "randbytes")
        else bytes(random.getrandbits(8) for _ in range(32))
    )
    body = (
        b"\x03\x03"
        + client_random
        + b"\x00"
        + len(ciphers).to_bytes(2, "big")
        + ciphers
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class TrainingManager:
    def __init__(self, context: TrainingRuntimeContext):
        self.ctx = context

    async def probe_strategy(self, test_ip: str, test_domain: str, strat_name: str) -> tuple[bool, float]:
        """Single strategy probe: connect, send ClientHello through strategy, check TLS response."""
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                self.ctx.open_connection(test_ip, 443),
                timeout=8,
            )
            hello = build_client_hello(test_domain)
            start_t = time.perf_counter()
            await self.ctx.strategy_funcs[strat_name](writer, hello)
            server_reply = await asyncio.wait_for(reader.read(8192), timeout=8)
            elapsed_ms = round((time.perf_counter() - start_t) * 1000, 1)
            success = bool(server_reply and len(server_reply) >= 2 and server_reply[0] == 0x16)
            return success, elapsed_ms if success else 0
        except Exception:
            return False, 0
        finally:
            close_writer(writer)

    async def self_training_loop(self) -> None:
        """Background task: periodically probe underexplored strategies for all sites."""
        while self.ctx.get_running():
            try:
                if not self.ctx.get_background_training_enabled():
                    self.ctx.self_train_state["running"] = False
                    await self.ctx.sleep(60)
                    continue
                intensity = self.ctx.get_ai_train_intensity()
                profile = self.ctx.ai_train_profiles.get(intensity, self.ctx.ai_train_profiles["light"])
                await self.ctx.sleep(profile["interval"])
                if self.ctx.training_state.get("active"):
                    continue

                max_probes = profile["probes"]
                self.ctx.ai_engine._compute_global_reputation()
                self.ctx.self_train_state["running"] = True
                self.ctx.self_train_state["cycle_count"] += 1
                self.ctx.self_train_state["last_run"] = time.time()
                self.ctx.logger.info(
                    f"[SELF-TRAIN] Cycle #{self.ctx.self_train_state['cycle_count']} "
                    f"({intensity} mode, {max_probes} probes, every {profile['interval']}s)"
                )

                for site_name, site_cfg in self.ctx.get_config().get("sites", {}).items():
                    if not site_cfg.get("enabled", True) or not self.ctx.get_running():
                        continue
                    ai = self.ctx.ai_engine._get_site_ai(site_name)
                    min_obs = self.ctx.ai_min_samples if intensity in ("light", "medium") else 1
                    if ai["total_observations"] < min_obs:
                        continue

                    obs_counts: dict[str, int] = {}
                    for obs in ai.get("recent", []):
                        obs_counts[obs[0]] = obs_counts.get(obs[0], 0) + 1

                    explore_threshold = 3 if intensity == "light" else (5 if intensity == "medium" else 10)
                    underexplored = [s for s in self.ctx.strategy_order if obs_counts.get(s, 0) < explore_threshold]
                    if not underexplored:
                        if intensity == "nonstop":
                            underexplored = list(self.ctx.strategy_order)
                        else:
                            continue

                    to_test = random.sample(underexplored, min(max_probes, len(underexplored)))
                    domains = site_cfg.get("dns_resolve", site_cfg.get("domains", []))
                    test_domain = domains[0] if domains else f"{site_name}.com"
                    test_ip = self.ctx.get_bypass_ip(test_domain)
                    if not test_ip or test_ip == test_domain.lower():
                        continue

                    self.ctx.self_train_state["last_site"] = site_name
                    self.ctx.logger.info(f"[SELF-TRAIN] {site_name}: probing {[s[:12] for s in to_test]}")
                    for strat_name in to_test:
                        if not self.ctx.get_running():
                            break
                        self.ctx.self_train_state["last_strategy"] = strat_name
                        success, elapsed_ms = await self.probe_strategy(test_ip, test_domain, strat_name)
                        self.ctx.ai_engine.record(site_name, strat_name, success, elapsed_ms)
                        self.ctx.self_train_state["total_probes"] += 1
                        if success:
                            self.ctx.strategy_cache.record_success(site_name, strat_name, elapsed_ms)
                            self.ctx.self_train_state["last_result"] = f"{strat_name} OK ({elapsed_ms}ms)"
                            self.ctx.logger.info(f"[SELF-TRAIN] {site_name}: {strat_name} OK ({elapsed_ms}ms)")
                        else:
                            self.ctx.strategy_cache.record_failure(site_name, strat_name)
                            self.ctx.self_train_state["last_result"] = f"{strat_name} FAIL"
                            self.ctx.logger.info(f"[SELF-TRAIN] {site_name}: {strat_name} FAIL")
                        await self.ctx.sleep(0.5 if intensity == "nonstop" else 1.0)
                self.ctx.self_train_state["running"] = False
            except Exception as e:
                self.ctx.self_train_state["running"] = False
                self.ctx.logger.info(f"[SELF-TRAIN] Error: {e}")

    async def train_site(self, site_name: str) -> None:
        """Test all strategies for a single site via real TLS handshake."""
        site_cfg = self.ctx.get_config().get("sites", {}).get(site_name)
        if not site_cfg:
            return
        domains = site_cfg.get("dns_resolve", site_cfg.get("domains", []))
        test_domain = domains[0] if domains else f"{site_name}.com"

        test_ip = self.ctx.get_bypass_ip(test_domain)
        if not test_ip or test_ip == test_domain.lower():
            loop = asyncio.get_event_loop()
            try:
                ips = await loop.run_in_executor(None, self.ctx.resolve_domain_doh, test_domain)
                if ips:
                    test_ip = ips[0]
                else:
                    self.ctx.logger.warning(
                        f"[TRAIN] {site_name}: no IPs found for {self.ctx.hash_host(test_domain)}"
                    )
                    return
            except Exception:
                return

        strat_list = list(self.ctx.strategy_funcs.keys())
        total = len(strat_list)
        results = []
        self.ctx.training_state["progress"][site_name] = {
            "current_strat": "",
            "tested": 0,
            "total": total,
            "pct": 0,
        }

        for idx, strat_name in enumerate(strat_list):
            if not self.ctx.training_state["active"]:
                break

            self.ctx.training_state["progress"][site_name]["current_strat"] = strat_name
            self.ctx.training_state["progress"][site_name]["tested"] = idx
            self.ctx.training_state["progress"][site_name]["pct"] = int((idx / total) * 100)

            success, elapsed_ms = await self.probe_strategy(test_ip, test_domain, strat_name)
            results.append({
                "strategy": strat_name,
                "success": success,
                "ms": elapsed_ms if success else 0,
            })

            if success:
                self.ctx.logger.info(f"[TRAIN] {site_name}: {strat_name} OK ({elapsed_ms}ms)")
            else:
                self.ctx.logger.debug(f"[TRAIN] {site_name}: {strat_name} FAIL")

            await self.ctx.sleep(0.5)

        self.ctx.training_state["progress"][site_name] = {
            "current_strat": "done",
            "tested": total,
            "total": total,
            "pct": 100,
        }

        successful = [r for r in results if r["success"]]
        if successful:
            best = min(successful, key=lambda r: r["ms"])
            self.ctx.training_state["results"][site_name] = {
                "best_strategy": best["strategy"],
                "best_ms": best["ms"],
                "success_count": len(successful),
                "total_tested": total,
                "all_results": results,
            }
            self.ctx.logger.info(
                f"[TRAIN] {site_name}: best = {best['strategy']} ({best['ms']}ms), "
                f"{len(successful)}/{total} strategies worked"
            )
        else:
            self.ctx.training_state["results"][site_name] = {
                "best_strategy": None,
                "best_ms": 0,
                "success_count": 0,
                "total_tested": total,
                "all_results": results,
            }
            self.ctx.logger.warning(f"[TRAIN] {site_name}: no strategies succeeded")

    async def train_all_sites(self) -> None:
        """Run strategy training for all enabled sites."""
        self.ctx.training_state["active"] = True
        self.ctx.training_state["completed"] = False
        self.ctx.training_state["progress"] = {}
        self.ctx.training_state["results"] = {}
        self.ctx.logger.info("[TRAIN] Strategy training started for all sites")

        enabled_sites = [
            name for name, cfg in self.ctx.get_config().get("sites", {}).items()
            if cfg.get("enabled", True)
        ]
        for site_name in enabled_sites:
            if not self.ctx.training_state["active"]:
                break
            await self.train_site(site_name)

        self.ctx.training_state["active"] = False
        self.ctx.training_state["completed"] = True
        self.ctx.logger.info(
            f"[TRAIN] Training complete. Results for {len(self.ctx.training_state['results'])} sites."
        )

    def apply_training(self, site_name: str) -> bool:
        """Feed training results into the AI engine so it learns the best strategy."""
        result = self.ctx.training_state["results"].get(site_name)
        if not result or not result.get("all_results"):
            return False

        ai_data = self.ctx.ai_engine.snapshot_site(site_name)
        self.ctx.training_state["previous_strategies"][site_name] = ai_data
        self.ctx.ai_engine.clear_site(site_name)
        self.ctx.strategy_cache.clear_site(site_name)

        for item in result["all_results"]:
            if item["success"]:
                for _ in range(5):
                    self.ctx.ai_engine.record(site_name, item["strategy"], True, item["ms"])
                    self.ctx.strategy_cache.record_success(site_name, item["strategy"], item["ms"])
            else:
                self.ctx.ai_engine.record(site_name, item["strategy"], False, 0)
                self.ctx.strategy_cache.record_failure(site_name, item["strategy"])

        self.ctx.ai_engine._do_save()
        self.ctx.strategy_cache._do_save()
        best = result.get("best_strategy", "?")
        self.ctx.logger.info(
            f"[TRAIN] Fed {len(result['all_results'])} training results into AI for {site_name}. "
            f"AI should now prefer '{best}'"
        )
        return True

    def revert_training(self, site_name: str) -> bool:
        """Revert AI data to pre-training state."""
        old_ai_data = self.ctx.training_state["previous_strategies"].get(site_name)
        if old_ai_data is None and site_name not in self.ctx.training_state["previous_strategies"]:
            return False

        self.ctx.ai_engine.restore_site(site_name, old_ai_data)
        self.ctx.ai_engine._do_save()
        self.ctx.strategy_cache.clear_site(site_name)
        self.ctx.strategy_cache._do_save()
        del self.ctx.training_state["previous_strategies"][site_name]
        self.ctx.logger.info(f"[TRAIN] Reverted AI data for {site_name} to pre-training state")
        return True
