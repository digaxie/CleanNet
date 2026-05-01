"""Strategy cache and adaptive AI strategy engine."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import copy
import json
import logging
import math
import random as _rng
import time
from typing import Any, Callable, Iterable

from .strategy_catalog import (
    STRATEGY_GROUPS,
    STRATEGY_ORDER,
    STRATEGY_TO_GROUP,
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
                self._data = json.load(f)
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
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
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

        if is_main:
            ai_engine = self.ai_engine_provider()
            ai_prediction = ai_engine.predict(site_name, count_as_prediction=True) if ai_engine else None
            if ai_prediction:
                ai_order = [p[0] for p in ai_prediction]
                top_conf = ai_prediction[0][2] if ai_prediction else 0
                sd = self._get_site_data(site_name)
                now = time.time()
                result: list[str] = []
                cooldown_strats: list[str] = []
                for strat in ai_order:
                    fail_info = sd["failures"].get(strat)
                    if fail_info:
                        last_fail_time = parse_iso(fail_info.get("last_fail", ""))
                        if last_fail_time and (now - last_fail_time) < self.failure_cooldown:
                            cooldown_strats.append(strat)
                            continue
                    result.append(strat)

                if result:
                    self.logger.debug(
                        f"[AI] {site_name}: predicted [{result[0]}] "
                        f"(conf={top_conf}, order={','.join(result[:3])})"
                    )
                    return result
                if cooldown_strats:
                    return cooldown_strats[:4]

        sd = self._get_site_data(site_name)
        now = time.time()
        result: list[str] = []
        cooldown_strats: list[str] = []

        if sd["best_strategy"] and sd["best_strategy"] in self.strategy_names:
            result.append(sd["best_strategy"])

        for strat in STRATEGY_ORDER:
            if strat in result:
                continue
            if not is_main:
                result.append(strat)
                continue
            fail_info = sd["failures"].get(strat)
            if fail_info:
                last_fail_time = parse_iso(fail_info.get("last_fail", ""))
                if last_fail_time and (now - last_fail_time) < self.failure_cooldown:
                    cooldown_strats.append(strat)
                    continue
            result.append(strat)

        if not result and cooldown_strats:
            strong = [s for s in ["desync", "tls_record_frag", "fragment_burst", "sni_shuffle"] if s in cooldown_strats]
            weak = [s for s in cooldown_strats if s not in strong]
            result = (strong + weak)[:4]

        return result

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


class MiniNN:
    """2-layer feedforward neural network. Pure Python, zero dependencies."""

    def __init__(self, input_size: int = 10, hidden_size: int = 16, output_size: int = 1, learning_rate: float = 0.01):
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.output_size = output_size
        self.lr = learning_rate
        s1 = (2.0 / (input_size + hidden_size)) ** 0.5
        s2 = (2.0 / (hidden_size + output_size)) ** 0.5
        self.W1 = [[_rng.gauss(0, s1) for _ in range(hidden_size)] for _ in range(input_size)]
        self.b1 = [0.0] * hidden_size
        self.W2 = [[_rng.gauss(0, s2) for _ in range(output_size)] for _ in range(hidden_size)]
        self.b2 = [0.0] * output_size

    def forward(self, x):
        z1 = [
            sum(x[i] * self.W1[i][j] for i in range(self.input_size)) + self.b1[j]
            for j in range(self.hidden_size)
        ]
        h1 = [max(0.0, z) for z in z1]
        z2 = [
            sum(h1[i] * self.W2[i][j] for i in range(self.hidden_size)) + self.b2[j]
            for j in range(self.output_size)
        ]
        out = [1.0 / (1.0 + math.exp(-max(-500, min(500, z)))) for z in z2]
        return out, (x, z1, h1, z2)

    def backward(self, cache, target):
        x, z1, h1, z2 = cache
        out = [1.0 / (1.0 + math.exp(-max(-500, min(500, z)))) for z in z2]
        dz2 = [out[j] - target[j] for j in range(self.output_size)]
        for i in range(self.hidden_size):
            for j in range(self.output_size):
                self.W2[i][j] -= self.lr * h1[i] * dz2[j]
        for j in range(self.output_size):
            self.b2[j] -= self.lr * dz2[j]
        dh1 = [sum(dz2[j] * self.W2[i][j] for j in range(self.output_size)) for i in range(self.hidden_size)]
        dz1 = [dh1[i] * (1.0 if z1[i] > 0 else 0.0) for i in range(self.hidden_size)]
        for i in range(self.input_size):
            for j in range(self.hidden_size):
                self.W1[i][j] -= self.lr * x[i] * dz1[j]
        for j in range(self.hidden_size):
            self.b1[j] -= self.lr * dz1[j]

    def to_dict(self):
        return {
            "W1": self.W1,
            "b1": self.b1,
            "W2": self.W2,
            "b2": self.b2,
            "is": self.input_size,
            "hs": self.hidden_size,
            "os": self.output_size,
        }

    @classmethod
    def from_dict(cls, data, *, learning_rate: float = 0.01):
        nn = cls(data.get("is", 10), data.get("hs", 16), data.get("os", 1), learning_rate)
        nn.W1, nn.b1, nn.W2, nn.b2 = data["W1"], data["b1"], data["W2"], data["b2"]
        return nn


class AdaptiveStrategyEngine:
    """Machine-learning based per-site strategy ranker."""

    def __init__(
        self,
        model_file: str,
        *,
        logger=None,
        train_intensity: str = "light",
        save_interval: int = 120,
        min_samples: int = 5,
        decay_factor: float = 0.95,
        ring_buffer_size: int = 100,
        drift_check_interval: int = 60,
        nn_hidden_size: int = 16,
        nn_input_size: int = 10,
        nn_learning_rate: float = 0.01,
        thompson_decay_interval: int = 200,
    ):
        self.model_file = model_file
        self.logger = logger or logging.getLogger(__name__)
        self.train_intensity = normalize_train_intensity(train_intensity)
        self.save_interval = save_interval
        self.min_samples = min_samples
        self.decay_factor = decay_factor
        self.ring_buffer_size = ring_buffer_size
        self.drift_check_interval = drift_check_interval
        self.nn_hidden_size = nn_hidden_size
        self.nn_input_size = nn_input_size
        self.nn_learning_rate = nn_learning_rate
        self.thompson_decay_interval = thompson_decay_interval
        self._data = self._default_data()
        self._dirty = False
        self._last_save = 0.0
        self._nn_cache: dict[str, MiniNN] = {}
        self._load()

    def _default_data(self) -> dict[str, Any]:
        return {
            "version": 3,
            "sites": {},
            "global_weights": {
                s: {"w_success": 1.0, "w_latency": 1.0, "w_recency": 1.0, "w_temporal": 1.0}
                for s in STRATEGY_ORDER
            },
            "global_priors": {},
            "total_predictions": 0,
            "correct_predictions": 0,
        }

    def _load(self) -> None:
        try:
            with open(self.model_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            version = loaded.get("version", 1)
            if version in (2, 3):
                self._data = loaded
                if version == 2:
                    self._data["version"] = 3
                    self._data.setdefault("global_priors", {})
                    for site_ai in self._data.get("sites", {}).values():
                        site_ai.setdefault("thompson", {})
                        site_ai.setdefault("nn_weights", None)
                    self._dirty = True
                    self.logger.info("[AI] Migrated model v2 -> v3")

            for site_name, site_ai in self._data.get("sites", {}).items():
                if site_ai.get("nn_weights"):
                    try:
                        self._nn_cache[site_name] = MiniNN.from_dict(
                            site_ai["nn_weights"],
                            learning_rate=self.nn_learning_rate,
                        )
                    except Exception:
                        pass
            self.train_intensity = normalize_train_intensity(
                self._data.get("train_intensity", self.train_intensity),
                self.train_intensity,
            )
            self.logger.info(
                f"[AI v3] Model loaded: {len(self._data.get('sites', {}))} sites, "
                f"{self._data.get('total_predictions', 0)} predictions, "
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
            for site_name, nn in self._nn_cache.items():
                if site_name in self._data.get("sites", {}):
                    self._data["sites"][site_name]["nn_weights"] = nn.to_dict()
            with open(self.model_file, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False)
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

    def _get_site_ai(self, site_name: str) -> dict[str, Any]:
        sites = self._data.setdefault("sites", {})
        if site_name not in sites:
            global_priors = self._data.get("global_priors", {})
            thompson_init = {}
            for strat in STRATEGY_ORDER:
                prior = global_priors.get(strat, {"alpha": 1.0, "beta": 1.0})
                thompson_init[strat] = {"alpha": prior["alpha"], "beta": prior["beta"]}
            sites[site_name] = {
                "hour_matrix": {},
                "day_matrix": {},
                "recent": [],
                "strategy_scores": {},
                "total_observations": 0,
                "thompson": thompson_init,
                "nn_weights": None,
            }
        return sites[site_name]

    def _get_nn(self, site_name: str) -> MiniNN:
        if site_name not in self._nn_cache:
            site_ai = self._data.get("sites", {}).get(site_name)
            if site_ai and site_ai.get("nn_weights"):
                try:
                    self._nn_cache[site_name] = MiniNN.from_dict(
                        site_ai["nn_weights"],
                        learning_rate=self.nn_learning_rate,
                    )
                except Exception:
                    self._nn_cache[site_name] = MiniNN(self.nn_input_size, self.nn_hidden_size, learning_rate=self.nn_learning_rate)
            else:
                self._nn_cache[site_name] = MiniNN(self.nn_input_size, self.nn_hidden_size, learning_rate=self.nn_learning_rate)
        return self._nn_cache[site_name]

    @staticmethod
    def _gamma_sample(shape: float) -> float:
        if shape <= 0:
            return 0.001
        if shape < 1.0:
            return AdaptiveStrategyEngine._gamma_sample(shape + 1.0) * (_rng.random() ** (1.0 / shape))
        d = shape - 1.0 / 3.0
        c = 1.0 / math.sqrt(9.0 * d)
        for _ in range(100):
            while True:
                x = _rng.gauss(0, 1)
                v = 1.0 + c * x
                if v > 0:
                    break
            v = v * v * v
            u = _rng.random()
            if u < 1.0 - 0.0331 * (x * x) * (x * x):
                return d * v
            if math.log(max(u, 1e-300)) < 0.5 * x * x + d * (1.0 - v + math.log(max(v, 1e-300))):
                return d * v
        return d

    def _thompson_sample(self, site_ai: dict[str, Any], strategy: str) -> float:
        thompson = site_ai.setdefault("thompson", {})
        params = thompson.setdefault(strategy, {"alpha": 1.0, "beta": 1.0})
        x = self._gamma_sample(params["alpha"])
        y = self._gamma_sample(params["beta"])
        return x / (x + y) if (x + y) > 1e-10 else 0.5

    def _build_features(self, site_ai, strategy, hour, day, current_time):
        pi2 = 2.0 * math.pi
        hour_sin = math.sin(pi2 * hour / 24.0) * 0.5 + 0.5
        hour_cos = math.cos(pi2 * hour / 24.0) * 0.5 + 0.5
        day_sin = math.sin(pi2 * day / 7.0) * 0.5 + 0.5
        day_cos = math.cos(pi2 * day / 7.0) * 0.5 + 0.5

        ema = site_ai["strategy_scores"].get(strategy, {})
        ema_success = ema.get("ema_success", 0.5)
        ema_latency = ema.get("ema_latency", 500.0)
        latency_norm = max(0.0, 1.0 - min(ema_latency / 2000.0, 1.0))

        hour_data = site_ai["hour_matrix"].get(str(hour), {}).get(strategy)
        temporal = 0.5
        if hour_data:
            total = hour_data["ok"] + hour_data["fail"]
            if total >= 2:
                temporal = hour_data["ok"] / total

        recency = 0.0
        for obs in reversed(site_ai.get("recent", [])):
            if obs[0] == strategy and obs[1]:
                age = current_time - obs[5]
                recency = math.exp(-age / 3600.0)
                break

        strat_obs = sum(1 for obs in site_ai.get("recent", []) if obs[0] == strategy)
        obs_norm = min(1.0, strat_obs / 10.0)

        streak = 0.5
        for obs in reversed(site_ai.get("recent", [])):
            if obs[0] == strategy:
                if obs[1]:
                    streak = min(1.0, streak + 0.1)
                else:
                    streak = max(0.0, streak - 0.15)

        return [
            hour_sin,
            hour_cos,
            day_sin,
            day_cos,
            ema_success,
            latency_norm,
            temporal,
            recency,
            obs_norm,
            streak,
        ]

    def _detect_drift(self, site_ai) -> float:
        recent = site_ai.get("recent", [])
        if len(recent) < 40:
            return 0.0
        window_new = recent[-20:]
        window_old = recent[-40:-20]
        new_ok = sum(1 for obs in window_new if obs[1])
        old_ok = sum(1 for obs in window_old if obs[1])
        rate_delta = abs(new_ok / 20.0 - old_ok / 20.0)
        new_wins = Counter(obs[0] for obs in window_new if obs[1])
        old_wins = Counter(obs[0] for obs in window_old if obs[1])
        new_top = new_wins.most_common(1)[0][0] if new_wins else None
        old_top = old_wins.most_common(1)[0][0] if old_wins else None
        strat_changed = 1.0 if (new_top and old_top and new_top != old_top) else 0.0
        return min(1.0, rate_delta * 2.0 + strat_changed * 0.3)

    def _apply_drift_response(self, site_ai, drift_score: float) -> None:
        if drift_score < 0.3:
            return
        self.logger.info(f"[AI] Concept drift detected (score={drift_score:.2f}), boosting exploration")
        decay = max(0.5, 1.0 - drift_score)
        for hour_strats in site_ai.get("hour_matrix", {}).values():
            for strategy_data in hour_strats.values():
                strategy_data["ok"] = int(strategy_data["ok"] * decay)
                strategy_data["fail"] = int(strategy_data["fail"] * decay)
        for day_strats in site_ai.get("day_matrix", {}).values():
            for strategy_data in day_strats.values():
                strategy_data["ok"] = int(strategy_data["ok"] * decay)
                strategy_data["fail"] = int(strategy_data["fail"] * decay)
        flatten = max(0.3, 1.0 - drift_score)
        for params in site_ai.get("thompson", {}).values():
            params["alpha"] = max(1.0, params["alpha"] * flatten)
            params["beta"] = max(1.0, params["beta"] * flatten)
        for ema in site_ai.get("strategy_scores", {}).values():
            ema["ema_success"] = ema["ema_success"] * 0.7 + 0.5 * 0.3
        site_ai["_last_drift_time"] = time.time()
        site_ai["_drift_score"] = drift_score

    def _compute_global_reputation(self):
        global_stats: dict[str, dict[str, int]] = {}
        for site_ai in self._data.get("sites", {}).values():
            for obs in site_ai.get("recent", []):
                stats = global_stats.setdefault(obs[0], {"ok": 0, "fail": 0})
                if obs[1]:
                    stats["ok"] += 1
                else:
                    stats["fail"] += 1
        priors = {}
        for strategy, stats in global_stats.items():
            priors[strategy] = {
                "alpha": 1.0 + stats["ok"] * 0.1,
                "beta": 1.0 + stats["fail"] * 0.1,
            }
        self._data["global_priors"] = priors
        return priors

    def record(self, site_name: str, strategy: str, success: bool, elapsed_ms: float) -> None:
        now = datetime.now()
        hour = str(now.hour)
        day = str(now.weekday())
        site_ai = self._get_site_ai(site_name)

        hm = site_ai["hour_matrix"].setdefault(hour, {})
        hs = hm.setdefault(strategy, {"ok": 0, "fail": 0, "total_ms": 0.0})
        if success:
            hs["ok"] += 1
            hs["total_ms"] += elapsed_ms
        else:
            hs["fail"] += 1

        dm = site_ai["day_matrix"].setdefault(day, {})
        ds = dm.setdefault(strategy, {"ok": 0, "fail": 0})
        if success:
            ds["ok"] += 1
        else:
            ds["fail"] += 1

        site_ai["recent"].append([strategy, success, round(elapsed_ms, 1), int(hour), int(day), time.time()])
        if len(site_ai["recent"]) > self.ring_buffer_size:
            site_ai["recent"] = site_ai["recent"][-self.ring_buffer_size:]

        ema = site_ai["strategy_scores"].setdefault(strategy, {"ema_success": 0.5, "ema_latency": 500.0})
        alpha = 0.2
        ema["ema_success"] = ema["ema_success"] * (1 - alpha) + (1.0 if success else 0.0) * alpha
        ema["ema_latency"] = ema["ema_latency"] * (1 - alpha) + elapsed_ms * alpha

        site_ai["total_observations"] += 1

        ts = site_ai.setdefault("thompson", {})
        params = ts.setdefault(strategy, {"alpha": 1.0, "beta": 1.0})
        if success:
            params["alpha"] += 1.0
        else:
            params["beta"] += 1.0
        if site_ai["total_observations"] % self.thompson_decay_interval == 0:
            for sp in ts.values():
                sp["alpha"] = max(1.0, sp["alpha"] * self.decay_factor)
                sp["beta"] = max(1.0, sp["beta"] * self.decay_factor)

        group = STRATEGY_TO_GROUP.get(strategy)
        if group:
            siblings = [s for s in STRATEGY_GROUPS[group] if s != strategy]
            for sibling in siblings:
                sibling_params = ts.setdefault(sibling, {"alpha": 1.0, "beta": 1.0})
                if success:
                    sibling_params["alpha"] += 0.2
                else:
                    sibling_params["beta"] += 0.2

        gw = self._data["global_weights"].setdefault(
            strategy,
            {"w_success": 1.0, "w_latency": 1.0, "w_recency": 1.0, "w_temporal": 1.0},
        )
        if success:
            gw["w_success"] = min(3.0, gw["w_success"] + 0.01)
            if elapsed_ms < 300:
                gw["w_latency"] = min(3.0, gw["w_latency"] + 0.005)
        else:
            gw["w_success"] = max(0.1, gw["w_success"] - 0.02)

        try:
            nn = self._get_nn(site_name)
            features = self._build_features(site_ai, strategy, int(hour), int(day), time.time())
            _, cache = nn.forward(features)
            nn.backward(cache, [1.0 if success else 0.0])
        except Exception:
            pass

        self._dirty = True
        self._save_if_needed()

    def predict(self, site_name: str, count_as_prediction: bool = False):
        site_ai = self._get_site_ai(site_name)
        now = datetime.now()
        hour = now.hour
        day = now.weekday()
        current_time = time.time()

        if site_ai["total_observations"] < self.min_samples:
            return None

        last_drift_check = site_ai.get("_last_drift_check", 0)
        if current_time - last_drift_check > self.drift_check_interval:
            site_ai["_last_drift_check"] = current_time
            drift = self._detect_drift(site_ai)
            if drift > 0.3:
                self._apply_drift_response(site_ai, drift)

        scores = []
        nn = self._get_nn(site_name)

        for strat in STRATEGY_ORDER:
            linear_score, confidence = self._score_strategy_linear(site_ai, strat, hour, day, current_time)
            nn_score = 0.5
            try:
                features = self._build_features(site_ai, strat, hour, day, current_time)
                nn_out, _ = nn.forward(features)
                nn_score = nn_out[0]
            except Exception:
                pass

            blend = min(1.0, site_ai["total_observations"] / 100.0)
            base_score = blend * nn_score + (1.0 - blend) * linear_score
            thompson = self._thompson_sample(site_ai, strat)
            combined = 0.6 * base_score + 0.4 * thompson
            scores.append((strat, round(combined, 4), round(confidence, 2)))

        scores.sort(key=lambda x: x[1], reverse=True)

        if len(scores) > 1 and count_as_prediction:
            linear_top = max(
                STRATEGY_ORDER,
                key=lambda s: self._score_strategy_linear(site_ai, s, hour, day, current_time)[0],
            )
            if scores[0][0] != linear_top:
                self.logger.debug(f"[AI] Exploring: {scores[0][0]} for {site_name} (Thompson)")

        if count_as_prediction:
            self._data["total_predictions"] = self._data.get("total_predictions", 0) + 1
            self._data.setdefault("_last_predictions", {})[site_name] = scores[0][0]

        return scores

    def _score_strategy_linear(self, site_ai, strategy, hour, day, current_time):
        gw = self._data["global_weights"].get(
            strategy,
            {"w_success": 1.0, "w_latency": 1.0, "w_recency": 1.0, "w_temporal": 1.0},
        )
        ema = site_ai["strategy_scores"].get(strategy, {})
        ema_success = ema.get("ema_success", 0.5)
        ema_latency = ema.get("ema_latency", 500.0)

        temporal_score = 0.5
        hour_data = site_ai["hour_matrix"].get(str(hour), {}).get(strategy)
        if hour_data:
            total = hour_data["ok"] + hour_data["fail"]
            if total >= 2:
                temporal_score = hour_data["ok"] / total

        day_data = site_ai["day_matrix"].get(str(day), {}).get(strategy)
        day_score = 0.5
        if day_data:
            total = day_data["ok"] + day_data["fail"]
            if total >= 2:
                day_score = day_data["ok"] / total
        temporal_combined = temporal_score * 0.7 + day_score * 0.3

        latency_score = max(0.0, 1.0 - (ema_latency / 2000.0))

        recency_score = 0.0
        for obs in reversed(site_ai.get("recent", [])):
            if obs[0] == strategy and obs[1]:
                age = current_time - obs[5]
                recency_score = math.exp(-age / 3600.0)
                break

        strat_obs = sum(1 for obs in site_ai.get("recent", []) if obs[0] == strategy)
        confidence = min(1.0, strat_obs / 10.0)

        score = (
            gw["w_success"] * ema_success * 0.35
            + gw["w_temporal"] * temporal_combined * 0.30
            + gw["w_latency"] * latency_score * 0.20
            + gw["w_recency"] * recency_score * 0.15
        )
        score *= 0.8 + 0.2 * confidence
        return round(score, 4), round(confidence, 2)

    def record_prediction_result(self, site_name: str, winning_strategy: str) -> None:
        last_preds = self._data.get("_last_predictions", {})
        predicted = last_preds.get(site_name)
        if predicted and predicted == winning_strategy:
            self._data["correct_predictions"] = self._data.get("correct_predictions", 0) + 1

    def get_accuracy(self) -> float:
        total = self._data.get("total_predictions", 0)
        correct = self._data.get("correct_predictions", 0)
        if total == 0:
            return 0.0
        return round((correct / total) * 100, 1)

    def get_site_insights(self, site_name: str):
        site_ai = self._data.get("sites", {}).get(site_name)
        if not site_ai or site_ai["total_observations"] < self.min_samples:
            return None
        predictions = self.predict(site_name)
        if not predictions:
            return None
        top = predictions[0]
        ts = site_ai.get("thompson", {}).get(top[0], {"alpha": 1, "beta": 1})
        insights = {
            "ai_active": True,
            "predicted_strategy": top[0],
            "confidence": top[1],
            "score": top[2],
            "total_observations": site_ai["total_observations"],
            "top_3": [{"strategy": p[0], "score": p[1], "confidence": p[2]} for p in predictions[:3]],
            "thompson_alpha": round(ts["alpha"], 1),
            "thompson_beta": round(ts["beta"], 1),
            "drift_score": round(site_ai.get("_drift_score", 0.0), 2),
            "nn_active": site_name in self._nn_cache,
        }
        hour_best = {}
        for hour, strats in site_ai.get("hour_matrix", {}).items():
            best_strat, best_rate = None, 0
            for strategy, data in strats.items():
                total = data["ok"] + data["fail"]
                if total >= 2:
                    rate = data["ok"] / total
                    if rate > best_rate:
                        best_rate = rate
                        best_strat = strategy
            if best_strat:
                hour_best[hour] = {"strategy": best_strat, "rate": round(best_rate, 2)}
        insights["hour_best"] = hour_best
        return insights

    def get_global_stats(self) -> dict[str, Any]:
        total_obs = sum(s.get("total_observations", 0) for s in self._data.get("sites", {}).values())
        total_success = sum(
            sum(1 for obs in s.get("recent", []) if obs[1])
            for s in self._data.get("sites", {}).values()
        )
        nn_sites = len(self._nn_cache)
        drift_active = sum(
            1 for s in self._data.get("sites", {}).values()
            if s.get("_drift_score", 0) > 0.3
        )
        return {
            "total_predictions": self._data.get("total_predictions", 0),
            "correct_predictions": self._data.get("correct_predictions", 0),
            "accuracy": self.get_accuracy(),
            "sites_with_data": sum(
                1
                for s in self._data.get("sites", {}).values()
                if s.get("total_observations", 0) >= self.min_samples
            ),
            "total_observations": total_obs,
            "total_success": total_success,
            "success_rate": round((total_success / total_obs * 100), 1) if total_obs > 0 else 0,
            "global_weights": self._data.get("global_weights", {}),
            "nn_active_sites": nn_sites,
            "drift_active": drift_active,
            "engine_version": 3,
        }

    def reset(self) -> None:
        self._data = self._default_data()
        self._nn_cache.clear()
        self._dirty = True
        self._do_save()
        self.logger.info("[AI v3] Model reset")
