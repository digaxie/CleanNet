"""Config and site mutation rules used by dashboard endpoints."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import re
from typing import Any, Callable
from urllib.parse import urlsplit

from .config import validate_config

ALLOWED_HEALTH_CHECK_INTERVALS = {60, 120, 300}
ALLOWED_IP_UPDATE_INTERVALS = {300, 900, 1800, 3600}

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)(\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)*$")


def normalize_domain(value: Any) -> str:
    """Reduce user input such as ``https://www.Example.com/path`` to ``www.example.com``.

    Returns an empty string when the value is not a plausible hostname.
    """
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "//" + raw
    try:
        host = urlsplit(raw).hostname or ""
    except ValueError:
        return ""
    host = host.rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    return host if _HOSTNAME_RE.match(host) else ""


def _normalize_domain_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    result: list[str] = []
    for value in values:
        domain = normalize_domain(value)
        if domain and domain not in result:
            result.append(domain)
    return result


@dataclass(frozen=True)
class MutationResult:
    changed: bool = False
    refresh_ips: bool = False


@dataclass
class ConfigMutationContext:
    logger: Any
    get_config: Callable[[], dict[str, Any]]
    save_config: Callable[[], None]
    reload_config: Callable[[], bool]
    always_bypass: list[str]
    bypass_presets: dict[str, list[str]]


class ConfigMutationService:
    def __init__(self, context: ConfigMutationContext):
        self.ctx = context

    def _config(self) -> dict[str, Any]:
        return self.ctx.get_config()

    def _save_and_reload(self) -> None:
        self.ctx.save_config()
        self.ctx.reload_config()

    def toggle_site(self, site_name: str | None) -> MutationResult:
        config = self._config()
        if not site_name or site_name not in config.get("sites", {}):
            return MutationResult()
        current = config["sites"][site_name].get("enabled", True)
        config["sites"][site_name]["enabled"] = not current
        self._save_and_reload()
        return MutationResult(changed=True, refresh_ips=True)

    def remove_site(self, site_name: str | None) -> MutationResult:
        config = self._config()
        if not site_name or site_name not in config.get("sites", {}):
            return MutationResult()
        del config["sites"][site_name]
        self._save_and_reload()
        self.ctx.logger.info(f"Site removed: {site_name}")
        return MutationResult(changed=True)

    def remove_all_sites(self) -> MutationResult:
        config = self._config()
        config["sites"] = {}
        self._save_and_reload()
        self.ctx.logger.info("All sites removed")
        return MutationResult(changed=True)

    def add_site(self, req_data: dict[str, Any]) -> MutationResult:
        config = self._config()
        domain = normalize_domain(req_data.get("domain", ""))
        if not domain:
            return MutationResult()

        bare = domain[4:] if domain.startswith("www.") else domain
        base_name = bare.split(".")[0]
        if "domains" in req_data:
            domains = _normalize_domain_list(req_data.get("domains"))
        else:
            domains = [bare, f"www.{bare}"]
        if domain not in domains and bare not in domains:
            domains.insert(0, domain)
        if "dns_resolve" in req_data:
            dns_resolve = _normalize_domain_list(req_data.get("dns_resolve"))
        else:
            dns_resolve = list(domains)
        raw_ips = req_data.get("ips", [])
        ips = [str(ip).strip() for ip in raw_ips if str(ip).strip()] if isinstance(raw_ips, list) else []

        sites = config.setdefault("sites", {})
        existing = sites.get(base_name)
        if isinstance(existing, dict):
            # Adding e.g. "discord.gg" next to an existing "discord" site must not wipe the
            # existing site's domains, IPs and locked strategy; merge into it instead.
            for key, values in (("domains", domains), ("dns_resolve", dns_resolve), ("ips", ips)):
                merged = list(existing.get(key) or [])
                for value in values:
                    if value not in merged:
                        merged.append(value)
                existing[key] = merged
            existing["enabled"] = True
            self.ctx.logger.info(f"Site updated: {base_name} (+{len(domains)} domains)")
        else:
            sites[base_name] = {
                "enabled": True,
                "domains": domains,
                "dns_resolve": dns_resolve,
                "ips": ips,
            }
        self._save_and_reload()
        return MutationResult(changed=True, refresh_ips=True)

    def add_cdn_domain(self, site_name: str, cdn_domain: str) -> MutationResult:
        config = self._config()
        cdn_domain = normalize_domain(cdn_domain)
        if not site_name or not cdn_domain or site_name not in config.get("sites", {}):
            return MutationResult()

        site_cfg = config["sites"][site_name]
        domains = site_cfg.get("domains", [])
        dns_resolve = site_cfg.get("dns_resolve", [])
        if cdn_domain not in domains:
            domains.append(cdn_domain)
            site_cfg["domains"] = domains
        if cdn_domain not in dns_resolve:
            dns_resolve.append(cdn_domain)
            site_cfg["dns_resolve"] = dns_resolve
        self._save_and_reload()
        self.ctx.logger.info(f"CDN domain added: {cdn_domain} -> {site_name}")
        return MutationResult(changed=True, refresh_ips=True)

    def remove_domain(self, site_name: str, domain: str) -> MutationResult:
        config = self._config()
        domain = domain.strip().lower()
        if not site_name or not domain or site_name not in config.get("sites", {}):
            return MutationResult()

        site_cfg = config["sites"][site_name]
        domains = site_cfg.get("domains", [])
        dns_resolve = site_cfg.get("dns_resolve", [])
        if domain in domains:
            domains.remove(domain)
            site_cfg["domains"] = domains
        if domain in dns_resolve:
            dns_resolve.remove(domain)
            site_cfg["dns_resolve"] = dns_resolve
        self._save_and_reload()
        self.ctx.logger.info(f"Domain removed: {domain} from {site_name}")
        return MutationResult(changed=True, refresh_ips=True)

    def add_bypass(self, entry: str) -> MutationResult:
        return self.add_bypass_entries([entry])

    def add_bypass_entries(self, entries: list[str]) -> MutationResult:
        config = self._config()
        config.setdefault("proxy_bypass", [])
        existing = set(config["proxy_bypass"]) | set(self.ctx.always_bypass)
        changed = False
        for raw_entry in entries:
            entry = str(raw_entry or "").strip()
            if not entry or entry in existing:
                continue
            config["proxy_bypass"].append(entry)
            existing.add(entry)
            changed = True
        if not changed:
            return MutationResult()
        self._save_and_reload()
        return MutationResult(changed=True)

    def remove_bypass(self, entry: str) -> MutationResult:
        config = self._config()
        entry = entry.strip()
        if not entry or "proxy_bypass" not in config:
            return MutationResult()
        config["proxy_bypass"] = [value for value in config["proxy_bypass"] if value != entry]
        self._save_and_reload()
        return MutationResult(changed=True)

    def clear_bypass(self) -> MutationResult:
        config = self._config()
        if "proxy_bypass" not in config:
            return MutationResult()
        config["proxy_bypass"] = []
        self._save_and_reload()
        self.ctx.logger.info("Cleared all proxy bypass entries")
        return MutationResult(changed=True)

    def load_preset(self, preset_name: str) -> MutationResult:
        config = self._config()
        if preset_name not in self.ctx.bypass_presets:
            return MutationResult()
        config.setdefault("proxy_bypass", [])
        existing = set(config["proxy_bypass"]) | set(self.ctx.always_bypass)
        added = False
        for entry in self.ctx.bypass_presets[preset_name]:
            if entry not in existing:
                config["proxy_bypass"].append(entry)
                existing.add(entry)
                added = True
        if not added:
            return MutationResult()
        self._save_and_reload()
        self.ctx.logger.info(f"Loaded preset: {preset_name}")
        return MutationResult(changed=True)

    def set_privacy(self, key: str, value: bool) -> bool:
        if key not in ("hide_dns", "hide_sni"):
            return False
        config = self._config()
        privacy = config.setdefault("privacy", {})
        privacy[key] = bool(value)
        self.ctx.save_config()
        self.ctx.logger.info(f"[PRIVACY] {key} {'enabled' if value else 'disabled'}")
        return True

    def set_performance(self, settings: dict[str, Any]) -> MutationResult:
        config = self._config()
        performance = config.setdefault("performance", {})
        next_values: dict[str, Any] = {}

        if "low_latency_mode" in settings:
            next_values["low_latency_mode"] = bool(settings.get("low_latency_mode"))
        if "background_training" in settings:
            next_values["background_training"] = bool(settings.get("background_training"))
        if "health_check_interval" in settings:
            try:
                interval = int(settings.get("health_check_interval"))
            except (TypeError, ValueError):
                return MutationResult()
            if interval not in ALLOWED_HEALTH_CHECK_INTERVALS:
                return MutationResult()
            next_values["health_check_interval"] = interval
        if "ip_update_interval" in settings:
            try:
                interval = int(settings.get("ip_update_interval"))
            except (TypeError, ValueError):
                return MutationResult()
            if interval not in ALLOWED_IP_UPDATE_INTERVALS:
                return MutationResult()
            next_values["ip_update_interval"] = interval
        if "ping_target_host" in settings:
            target = str(settings.get("ping_target_host") or "").strip()
            if not target:
                return MutationResult()
            next_values["ping_target_host"] = target

        if not next_values:
            return MutationResult()

        changed = False
        for key, value in next_values.items():
            if performance.get(key) != value:
                performance[key] = value
                changed = True
        if not changed:
            return MutationResult()

        self._save_and_reload()
        self.ctx.logger.info("[PERFORMANCE] Settings updated")
        return MutationResult(changed=True)

    def set_site_strategy(self, site_name: str | None, strategy: str | None, valid_strategies: set[str]) -> MutationResult:
        config = self._config()
        if not site_name or site_name not in config.get("sites", {}):
            return MutationResult()

        strategy_value = str(strategy or "").strip()
        if strategy_value == "auto":
            site_cfg = config["sites"][site_name]
            if "strategy" not in site_cfg:
                return MutationResult()
            del site_cfg["strategy"]
            self._save_and_reload()
            self.ctx.logger.info(f"[STRATEGY] {site_name} unlocked to auto")
            return MutationResult(changed=True)

        if strategy_value not in valid_strategies:
            return MutationResult()

        site_cfg = config["sites"][site_name]
        if site_cfg.get("strategy") == strategy_value:
            return MutationResult()
        site_cfg["strategy"] = strategy_value
        self._save_and_reload()
        self.ctx.logger.info(f"[STRATEGY] {site_name} locked to {strategy_value}")
        return MutationResult(changed=True)

    def import_config(self, new_config: dict[str, Any]) -> MutationResult:
        if not isinstance(new_config, dict) or not isinstance(new_config.get("sites"), dict):
            return MutationResult()
        config = self._config()
        # Validate a merged copy first: an imported file with wrong types used to be
        # written straight into the live config and crash later readers.
        candidate = copy.deepcopy(config)
        candidate.update(copy.deepcopy(new_config))
        validated, errors = validate_config(candidate)
        if validated is None:
            return MutationResult()
        for err in errors:
            self.ctx.logger.warning(f"[CONFIG] Import: {err}")
        config.clear()
        config.update(validated)
        self._save_and_reload()
        self.ctx.logger.info("Config imported successfully")
        return MutationResult(changed=True, refresh_ips=True)
