"""Strategy cache and adaptive AI strategy engine."""

from __future__ import annotations

from datetime import datetime
import copy
import json
import logging
import os
import random as _rng
import shutil
import time
from typing import Any, Callable, Iterable

from .config import atomic_write_json
from .strategy_catalog import (
    AUTO_STRATEGY_ORDER,
    RETIRED_STRATEGIES,
    STRATEGY_ORDER,
    normalize_train_intensity,
)


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def parse_iso(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except Exception:
        return None


class StrategyCache:
    """Per-site strategy bookkeeping: locks, failure cooldowns and success history.

    Ranking itself comes from :class:`AdaptiveStrategyEngine`; this class only applies
    the site's locked strategy and the short cooldown after repeated failures.
    """

    COOLDOWN_AFTER_CONSECUTIVE_FAILURES = 2

    def __init__(
        self,
        cache_file: str,
        *,
        logger=None,
        config_provider: Callable[[], dict[str, Any]] | None = None,
        strategy_names: Iterable[str] | None = None,
        ai_engine_provider: Callable[[], Any] | None = None,
        save_interval: int = 60,
        failure_cooldown: int = 3600,
    ):
        self.cache_file = cache_file
        self.logger = logger or logging.getLogger(__name__)
        self.config_provider = config_provider or (lambda: {})
        self.strategy_names = set(strategy_names or STRATEGY_ORDER)
        self.ai_engine_provider = ai_engine_provider or (lambda: None)
        self.save_interval = save_interval
        self.failure_cooldown = failure_cooldown
        self._data = {"version": 1, "sites": {}}
        self._dirty = False
        self._last_save = 0.0
        self._load()

    def _load(self) -> None:
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if not isinstance(loaded, dict) or not isinstance(loaded.get("sites", {}), dict):
                raise ValueError("unexpected strategy cache format")
            loaded.setdefault("sites", {})
            self._data = loaded
            self.logger.info(f"Strategy cache loaded: {len(self._data.get('sites', {}))} sites")
        except FileNotFoundError:
            pass
        except Exception as e:
            self.logger.warning(f"Strategy cache read error: {e}")

    def _save_if_needed(self) -> None:
        if self._dirty and (time.time() - self._last_save) > self.save_interval:
            self._do_save()

    def _do_save(self) -> None:
        try:
            atomic_write_json(self.cache_file, self._data, indent=2, ensure_ascii=False)
            self._dirty = False
            self._last_save = time.time()
        except Exception as e:
            self.logger.error(f"Strategy cache write error: {e}")

    def force_save(self) -> None:
        if self._dirty:
            self._do_save()

    def _get_site_data(self, site_name: str) -> dict[str, Any]:
        sites = self._data.setdefault("sites", {})
        if site_name not in sites:
            sites[site_name] = {
                "best_strategy": None,
                "best_time_ms": None,
                "last_success": None,
                "failures": {},
                "successes": {},
            }
        return sites[site_name]

    def iter_site_data(self):
        return list(self._data.get("sites", {}).items())

    def clear_site(self, site_name: str) -> None:
        if site_name in self._data.get("sites", {}):
            del self._data["sites"][site_name]
            self._dirty = True

    def get_strategy_order(self, site_name: str, is_main: bool = True) -> list[str]:
        config = self.config_provider() or {}
        site_config = config.get("sites", {}).get(site_name, {})
        forced = site_config.get("strategy")
        if forced and forced != "auto" and forced in self.strategy_names:
            return [forced]

        sd = self._get_site_data(site_name)
        ai_engine = self.ai_engine_provider()
        if ai_engine is not None:
            # Single source of truth: the engine's exploit ranking (posterior mean).
            ranked = [s for s in ai_engine.rank(site_name) if s in self.strategy_names]
        else:
            ranked = []
            best = sd["best_strategy"]
            if best and best in self.strategy_names and best not in RETIRED_STRATEGIES:
                ranked.append(best)
            ranked += [s for s in AUTO_STRATEGY_ORDER if s in self.strategy_names and s not in ranked]

        if not is_main:
            return ranked

        # Skip strategies that just failed repeatedly; one transient failure must not
        # bench a strategy that has worked many times before.
        now = time.time()
        result: list[str] = []
        cooldown_strats: list[str] = []
        for strat in ranked:
            fail_info = sd["failures"].get(strat)
            if fail_info and fail_info.get("consecutive", 0) >= self.COOLDOWN_AFTER_CONSECUTIVE_FAILURES:
                last_fail_time = parse_iso(fail_info.get("last_fail", ""))
                if last_fail_time and (now - last_fail_time) < self.failure_cooldown:
                    cooldown_strats.append(strat)
                    continue
            result.append(strat)

        if result:
            self.logger.debug(f"[AI] {site_name}: order {','.join(result[:3])}")
            return result
        # Everything failed recently: still try the most promising few.
        return cooldown_strats[:4]

    def record_success(self, site_name: str, strategy: str, elapsed_ms: float) -> None:
        sd = self._get_site_data(site_name)
        current_iso = now_iso()
        succ = sd["successes"].setdefault(strategy, {"count": 0, "avg_ms": 0, "last_ok": ""})
        old_avg, old_count = succ["avg_ms"], succ["count"]
        succ["count"] = old_count + 1
        succ["avg_ms"] = round((old_avg * old_count + elapsed_ms) / (old_count + 1), 1)
        succ["last_ok"] = current_iso
        fail = sd["failures"].get(strategy)
        if fail:
            fail["consecutive"] = 0
        if sd["best_strategy"] is None or elapsed_ms < (sd.get("best_time_ms") or 99999):
            sd["best_strategy"] = strategy
            sd["best_time_ms"] = round(elapsed_ms, 1)
        sd["last_success"] = current_iso
        self._dirty = True
        self._save_if_needed()

    def record_failure(self, site_name: str, strategy: str) -> None:
        sd = self._get_site_data(site_name)
        fail = sd["failures"].setdefault(strategy, {"count": 0, "last_fail": "", "consecutive": 0})
        fail["count"] += 1
        fail["last_fail"] = now_iso()
        fail["consecutive"] = fail.get("consecutive", 0) + 1
        if sd["best_strategy"] == strategy and fail["consecutive"] >= 3:
            sd["best_strategy"] = None
            sd["best_time_ms"] = None
        self._dirty = True
        self._save_if_needed()

    def get_site_strategy_info(self, site_name: str) -> dict[str, Any]:
        ai_engine = self.ai_engine_provider()
        insights = ai_engine.get_site_insights(site_name) if ai_engine is not None else None
        if insights:
            top = insights["predicted_strategy"]
            succ = (self._data.get("sites", {}).get(site_name) or {}).get("successes", {}).get(top) or {}
            return {"strategy": top, "time_ms": succ.get("avg_ms")}
        sd = self._data.get("sites", {}).get(site_name)
        if not sd:
            return {"strategy": "auto", "time_ms": None}
        return {
            "strategy": sd.get("best_strategy") or "auto",
            "time_ms": sd.get("best_time_ms"),
        }

    def reset_all(self) -> None:
        self._data = {"version": 1, "sites": {}}
        self._dirty = True
        self._do_save()
        self.logger.info("Strategy cache reset")


class AdaptiveStrategyEngine:
    """Per-site strategy ranking with discounted Beta-Bernoulli bandits.

    Each (site, strategy) pair keeps a Beta(a, b) posterior over "this strategy gets a
    verified connection through on this network". Before every new observation for a
    site, all of that site's posteriors are pulled back toward the prior by
    ``discount`` (discounted Thompson sampling), so evidence fades over roughly
    ``1 / (1 - discount)`` observations. That is what lets the engine follow an ISP
    that changes its DPI, without a separate drift detector.

    * Live traffic uses :meth:`rank` (exploit): strategies ordered by posterior mean,
      latency only breaks near-ties. Users never pay for exploration.
    * Exploration happens in background probes, which can ask for Thompson samples
      with ``predict(..., explore=True)``.
    * Untried strategies sit at the prior mean (0.5, or the cross-site prior), so they
      are tried after known-good ones and before known-bad ones.

    Version 3 of this engine also blended a per-site neural network, a hand-weighted
    linear score and a drift detector. The network was trained on features computed
    after the outcome was recorded (the label leaked into its inputs) and the drift
    detector reacted to the engine's own exploration, so both were removed.
    """

    VERSION = 4
    LATENCY_TIEBREAK = 0.05  # max score penalty for slow strategies (posterior mean is 0..1)
    PRIOR_STRENGTH_CAP = 2.0  # cross-site prior is worth at most two local observations

    def __init__(
        self,
        model_file: str,
        *,
        logger=None,
        train_intensity: str = "light",
        save_interval: int = 120,
        min_samples: int = 5,
        discount: float = 0.98,
        ring_buffer_size: int = 100,
        rng: _rng.Random | None = None,
        **_legacy_options: Any,
    ):
        self.model_file = model_file
        self.logger = logger or logging.getLogger(__name__)
        self.train_intensity = normalize_train_intensity(train_intensity)
        self.save_interval = save_interval
        self.min_samples = min_samples
        self.discount = discount
        self.ring_buffer_size = ring_buffer_size
        self.rng = rng or _rng.Random()
        self._data = self._default_data()
        self._dirty = False
        self._last_save = 0.0
        self._load()

    # ------------------------------------------------------------------ storage
    def _default_data(self) -> dict[str, Any]:
        return {
            "version": self.VERSION,
            "sites": {},
            "global_priors": {},
            "connections": {"total": 0, "first_try_ok": 0, "avg_connect_ms": None},
        }

    @staticmethod
    def _new_site() -> dict[str, Any]:
        return {
            "arms": {},
            "recent": [],
            "hour_matrix": {},
            "total_observations": 0,
            "connections": {"total": 0.0, "first_try_ok": 0.0, "avg_connect_ms": None},
        }

    def _migrate_v3_site(self, old: dict[str, Any]) -> dict[str, Any]:
        site = self._new_site()
        thompson = old.get("thompson", {}) or {}
        scores = old.get("strategy_scores", {}) or {}
        for strategy, params in thompson.items():
            a = max(1.0, float(params.get("alpha", 1.0)))
            b = max(1.0, float(params.get("beta", 1.0)))
            # v3 decayed rarely; cap old evidence so the new discounting can move it.
            evidence = (a - 1.0) + (b - 1.0)
            if evidence > 20.0:
                scale = 20.0 / evidence
                a = 1.0 + (a - 1.0) * scale
                b = 1.0 + (b - 1.0) * scale
            arm = {"a": round(a, 3), "b": round(b, 3), "latency_ms": None, "n": int(round(evidence))}
            latency = (scores.get(strategy) or {}).get("ema_latency")
            if latency is not None and (scores.get(strategy) or {}).get("ema_success", 0) > 0:
                arm["latency_ms"] = round(float(latency), 1)
            site["arms"][strategy] = arm
        site["recent"] = list(old.get("recent", []))[-self.ring_buffer_size:]
        site["hour_matrix"] = old.get("hour_matrix", {}) or {}
        site["total_observations"] = int(old.get("total_observations", 0) or 0)
        return site

    def legacy_backup_path(self, version: int) -> str:
        root, ext = os.path.splitext(self.model_file)
        return f"{root}.v{version}.bak{ext or '.json'}"

    def _backup_legacy_model(self, version: int) -> None:
        backup = self.legacy_backup_path(version)
        if os.path.exists(backup):
            return  # never overwrite the first, untouched copy
        try:
            shutil.copy2(self.model_file, backup)
            self.logger.info(f"[AI] Kept the v{version} model as {os.path.basename(backup)}")
        except OSError as e:
            self.logger.warning(f"[AI] Could not back up the v{version} model: {e}")

    def _load(self) -> None:
        try:
            with open(self.model_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if not isinstance(loaded, dict):
                raise ValueError("unexpected model format")
            version = loaded.get("version", 1)
            if version == self.VERSION:
                data = self._default_data()
                data.update(loaded)
                self._data = data
            elif version in (2, 3):
                # Older CleanNet versions cannot read v4 and would overwrite it, so keep
                # the original next to it: downgrading then only needs a file rename.
                self._backup_legacy_model(version)
                data = self._default_data()
                for name, site in (loaded.get("sites") or {}).items():
                    if isinstance(site, dict):
                        data["sites"][name] = self._migrate_v3_site(site)
                self._data = data
                self._dirty = True
                self.logger.info(f"[AI] Migrated model v{version} -> v{self.VERSION}")
            self.train_intensity = normalize_train_intensity(
                loaded.get("train_intensity", self.train_intensity),
                self.train_intensity,
            )
            self.logger.info(
                f"[AI v{self.VERSION}] Model loaded: {len(self._data.get('sites', {}))} sites, "
                f"train_intensity={self.train_intensity}"
            )
        except FileNotFoundError:
            pass
        except Exception as e:
            self.logger.warning(f"[AI] Model load error: {e}")

    def _save_if_needed(self) -> None:
        if self._dirty and (time.time() - self._last_save) > self.save_interval:
            self._do_save()

    def _do_save(self) -> None:
        try:
            self._data["train_intensity"] = self.train_intensity
            self._data["version"] = self.VERSION
            atomic_write_json(self.model_file, self._data, indent=None, ensure_ascii=False)
            self._dirty = False
            self._last_save = time.time()
        except Exception as e:
            self.logger.error(f"[AI] Model save error: {e}")

    def force_save(self) -> None:
        if self._dirty:
            self._do_save()

    def set_train_intensity(self, value: str) -> bool:
        normalized = normalize_train_intensity(value, "")
        if not normalized:
            return False
        self.train_intensity = normalized
        self._dirty = True
        self._do_save()
        return True

    def snapshot_site(self, site_name: str):
        site_ai = self._data.get("sites", {}).get(site_name)
        return copy.deepcopy(site_ai) if site_ai is not None else None

    def clear_site(self, site_name: str) -> None:
        if site_name in self._data.get("sites", {}):
            del self._data["sites"][site_name]
            self._dirty = True

    def restore_site(self, site_name: str, site_ai) -> None:
        if site_ai is not None:
            self._data.setdefault("sites", {})[site_name] = copy.deepcopy(site_ai)
        else:
            self._data.get("sites", {}).pop(site_name, None)
        self._dirty = True

    def reset(self) -> None:
        self._data = self._default_data()
        self._dirty = True
        self._do_save()
        self.logger.info(f"[AI v{self.VERSION}] Model reset")

    # ------------------------------------------------------------------ model
    def _get_site_ai(self, site_name: str) -> dict[str, Any]:
        sites = self._data.setdefault("sites", {})
        if site_name not in sites:
            sites[site_name] = self._new_site()
        return sites[site_name]

    def _prior(self, strategy: str) -> tuple[float, float]:
        prior = self._data.get("global_priors", {}).get(strategy)
        if not prior:
            return 1.0, 1.0
        return float(prior.get("alpha", 1.0)), float(prior.get("beta", 1.0))

    def _arm(self, site_ai: dict[str, Any], strategy: str) -> dict[str, Any]:
        arms = site_ai.setdefault("arms", {})
        if strategy not in arms:
            a, b = self._prior(strategy)
            arms[strategy] = {"a": a, "b": b, "latency_ms": None, "n": 0}
        return arms[strategy]

    def _discount_site(self, site_ai: dict[str, Any]) -> None:
        """Pull every arm of a site back toward its prior before a new observation."""
        g = self.discount
        for strategy, arm in site_ai.get("arms", {}).items():
            pa, pb = self._prior(strategy)
            arm["a"] = pa + (arm["a"] - pa) * g
            arm["b"] = pb + (arm["b"] - pb) * g

    @staticmethod
    def _mean(arm: dict[str, Any]) -> float:
        return arm["a"] / (arm["a"] + arm["b"])

    def _score(self, arm: dict[str, Any], value: float) -> float:
        latency = arm.get("latency_ms")
        penalty = 0.0 if latency is None else self.LATENCY_TIEBREAK * min(latency / 2000.0, 1.0)
        return value - penalty

    @staticmethod
    def _confidence(arm: dict[str, Any], prior: tuple[float, float]) -> float:
        evidence = (arm["a"] + arm["b"]) - (prior[0] + prior[1])
        return round(max(0.0, min(1.0, evidence / 10.0)), 2)

    def record(self, site_name: str, strategy: str, success: bool, elapsed_ms: float) -> None:
        now = datetime.now()
        site_ai = self._get_site_ai(site_name)
        self._discount_site(site_ai)
        arm = self._arm(site_ai, strategy)
        if success:
            arm["a"] += 1.0
            if elapsed_ms and elapsed_ms > 0:
                previous = arm.get("latency_ms")
                arm["latency_ms"] = round(
                    elapsed_ms if previous is None else previous * 0.8 + elapsed_ms * 0.2, 1
                )
        else:
            arm["b"] += 1.0
        arm["n"] = arm.get("n", 0) + 1
        site_ai["total_observations"] = site_ai.get("total_observations", 0) + 1

        # Kept for training (under-explored strategies) and the dashboard heatmap only;
        # the hour of day is not used for ranking.
        site_ai["recent"].append([strategy, bool(success), round(elapsed_ms or 0.0, 1), now.hour, now.weekday(), time.time()])
        if len(site_ai["recent"]) > self.ring_buffer_size:
            site_ai["recent"] = site_ai["recent"][-self.ring_buffer_size:]
        hour_cell = site_ai["hour_matrix"].setdefault(str(now.hour), {}).setdefault(strategy, {"ok": 0, "fail": 0})
        hour_cell["ok" if success else "fail"] += 1

        self._dirty = True
        self._save_if_needed()

    def record_connection(self, site_name: str, first_try: bool, connect_ms: float | None) -> None:
        """Outcome of one live connection: did the first strategy tried work, and how
        long did it take until the server answered (None when every strategy failed)."""
        site_ai = self._get_site_ai(site_name)
        bucket = site_ai.setdefault("connections", {"total": 0.0, "first_try_ok": 0.0, "avg_connect_ms": None})
        # Discounted like the arms so the per-site rate reflects recent behaviour.
        bucket["total"] = bucket["total"] * self.discount + 1.0
        bucket["first_try_ok"] = bucket["first_try_ok"] * self.discount + (1.0 if first_try else 0.0)
        if connect_ms is not None:
            prev = bucket.get("avg_connect_ms")
            bucket["avg_connect_ms"] = round(connect_ms if prev is None else prev * 0.9 + connect_ms * 0.1, 1)
        totals = self._data.setdefault("connections", {"total": 0, "first_try_ok": 0, "avg_connect_ms": None})
        totals["total"] += 1
        totals["first_try_ok"] += 1 if first_try else 0
        if connect_ms is not None:
            prev = totals.get("avg_connect_ms")
            totals["avg_connect_ms"] = round(connect_ms if prev is None else prev * 0.9 + connect_ms * 0.1, 1)
        self._dirty = True

    def predict(self, site_name: str, count_as_prediction: bool = False, *, explore: bool = False):
        """Rank automatic strategies for a site.

        Returns ``[(strategy, score, confidence), ...]`` best first, or None until the
        site has ``min_samples`` observations. ``explore=True`` ranks by Thompson
        samples instead of posterior means (for background probes only).
        """
        site_ai = self._data.get("sites", {}).get(site_name)
        if not site_ai or site_ai.get("total_observations", 0) < self.min_samples:
            return None
        return self._ranked(site_ai, explore=explore)

    def rank(self, site_name: str) -> list[str]:
        """Exploit ordering for live traffic; works from the first observation."""
        site_ai = self._data.get("sites", {}).get(site_name) or self._new_site()
        return [row[0] for row in self._ranked(site_ai, explore=False)]

    def _ranked(self, site_ai: dict[str, Any], *, explore: bool) -> list[tuple[str, float, float]]:
        rows = []
        arms = site_ai.get("arms", {})
        for position, strategy in enumerate(AUTO_STRATEGY_ORDER):
            prior = self._prior(strategy)
            arm = arms.get(strategy) or {"a": prior[0], "b": prior[1], "latency_ms": None, "n": 0}
            value = self.rng.betavariate(arm["a"], arm["b"]) if explore else self._mean(arm)
            # Catalog position is the final, stable tie-break.
            rows.append((strategy, round(self._score(arm, value), 4), self._confidence(arm, prior), -position))
        rows.sort(key=lambda row: (row[1], row[3]), reverse=True)
        return [row[:3] for row in rows]

    def _compute_global_reputation(self):
        """Cross-site prior for strategies a site has not tried yet (weak by design)."""
        global_stats: dict[str, dict[str, float]] = {}
        for site_ai in self._data.get("sites", {}).values():
            for strategy, arm in site_ai.get("arms", {}).items():
                stats = global_stats.setdefault(strategy, {"ok": 0.0, "fail": 0.0})
                stats["ok"] += max(0.0, arm["a"] - 1.0)
                stats["fail"] += max(0.0, arm["b"] - 1.0)
        priors = {}
        for strategy, stats in global_stats.items():
            total = stats["ok"] + stats["fail"]
            if total <= 0:
                continue
            strength = min(self.PRIOR_STRENGTH_CAP, total)
            rate = stats["ok"] / total
            priors[strategy] = {"alpha": 1.0 + strength * rate, "beta": 1.0 + strength * (1.0 - rate)}
        self._data["global_priors"] = priors
        return priors

    # ------------------------------------------------------------------ reporting
    def get_accuracy(self) -> float:
        """Share of live connections where the first strategy tried worked (percent)."""
        totals = self._data.get("connections", {})
        total = totals.get("total", 0)
        if not total:
            return 0.0
        return round(totals.get("first_try_ok", 0) / total * 100, 1)

    def get_site_insights(self, site_name: str):
        site_ai = self._data.get("sites", {}).get(site_name)
        predictions = self.predict(site_name)
        if not site_ai or not predictions:
            return None
        top_name = predictions[0][0]
        top_arm = self._arm(site_ai, top_name)
        connections = site_ai.get("connections", {})
        conn_total = connections.get("total", 0.0)
        hour_best = {}
        for hour, strats in site_ai.get("hour_matrix", {}).items():
            best_strat, best_rate = None, 0.0
            for strategy, data in strats.items():
                total = data["ok"] + data["fail"]
                if total >= 2 and data["ok"] / total > best_rate:
                    best_rate = data["ok"] / total
                    best_strat = strategy
            if best_strat:
                hour_best[hour] = {"strategy": best_strat, "rate": round(best_rate, 2)}
        return {
            "ai_active": True,
            "predicted_strategy": top_name,
            # Expected chance that the top strategy connects (posterior mean).
            "confidence": round(self._mean(top_arm), 2),
            "score": predictions[0][1],
            "total_observations": site_ai.get("total_observations", 0),
            "top_3": [{"strategy": p[0], "score": p[1], "confidence": p[2]} for p in predictions[:3]],
            "thompson_alpha": round(top_arm["a"], 1),
            "thompson_beta": round(top_arm["b"], 1),
            "first_try_rate": round(connections.get("first_try_ok", 0.0) / conn_total * 100, 1) if conn_total else None,
            "avg_connect_ms": connections.get("avg_connect_ms"),
            "hour_best": hour_best,
        }

    def get_global_stats(self) -> dict[str, Any]:
        sites = self._data.get("sites", {})
        total_obs = sum(s.get("total_observations", 0) for s in sites.values())
        total_success = sum(sum(1 for obs in s.get("recent", []) if obs[1]) for s in sites.values())
        recent_total = sum(len(s.get("recent", [])) for s in sites.values())
        totals = self._data.get("connections", {})
        return {
            # "accuracy" is kept as the key the dashboard reads; it is the first-try rate.
            "accuracy": self.get_accuracy(),
            "first_try_rate": self.get_accuracy(),
            "total_predictions": totals.get("total", 0),
            "correct_predictions": totals.get("first_try_ok", 0),
            "avg_connect_ms": totals.get("avg_connect_ms"),
            "sites_with_data": sum(1 for s in sites.values() if s.get("total_observations", 0) >= self.min_samples),
            "total_observations": total_obs,
            "total_success": total_success,
            "success_rate": round(total_success / recent_total * 100, 1) if recent_total else 0,
            "discount": self.discount,
            "engine_version": self.VERSION,
        }
