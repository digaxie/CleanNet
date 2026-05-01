"""Configuration loading, validation, and derived site indexes."""

from __future__ import annotations

import copy
import json
from typing import Any

from .config_defaults import DEFAULT_CONFIG


def default_config() -> dict[str, Any]:
    return copy.deepcopy(DEFAULT_CONFIG)


def validate_config(config: Any) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate config structure and fill safe defaults."""
    errors: list[str] = []
    if not isinstance(config, dict):
        return None, ["Config is not a JSON object"]

    if "sites" not in config or not isinstance(config.get("sites"), dict):
        config["sites"] = {}
        errors.append("Missing or invalid 'sites' - reset to empty")
    if "proxy_port" not in config or not isinstance(config.get("proxy_port"), int):
        config["proxy_port"] = 8080
        errors.append("Missing or invalid 'proxy_port' - reset to 8080")
    if "dashboard_port" not in config or not isinstance(config.get("dashboard_port"), int):
        config["dashboard_port"] = 8888
        errors.append("Missing or invalid 'dashboard_port' - reset to 8888")
    if "proxy_bypass" not in config or not isinstance(config.get("proxy_bypass"), list):
        config["proxy_bypass"] = []
        errors.append("Missing or invalid 'proxy_bypass' - reset to empty")
    if "privacy" not in config or not isinstance(config.get("privacy"), dict):
        config["privacy"] = {}
        errors.append("Missing or invalid 'privacy' - reset to defaults")
    if not isinstance(config["privacy"].get("hide_dns"), bool):
        config["privacy"]["hide_dns"] = True
        errors.append("Missing or invalid 'privacy.hide_dns' - reset to True")
    if not isinstance(config["privacy"].get("hide_sni"), bool):
        config["privacy"]["hide_sni"] = True
        errors.append("Missing or invalid 'privacy.hide_sni' - reset to True")
    if "performance" not in config or not isinstance(config.get("performance"), dict):
        config["performance"] = {}
        errors.append("Missing or invalid 'performance' - reset to defaults")
    performance = config["performance"]
    if not isinstance(performance.get("low_latency_mode"), bool):
        performance["low_latency_mode"] = True
        errors.append("Missing or invalid 'performance.low_latency_mode' - reset to True")
    if not isinstance(performance.get("background_training"), bool):
        performance["background_training"] = False
        errors.append("Missing or invalid 'performance.background_training' - reset to False")
    if not isinstance(performance.get("health_check_interval"), int) or performance["health_check_interval"] < 30:
        performance["health_check_interval"] = 120
        errors.append("Missing or invalid 'performance.health_check_interval' - reset to 120")
    if not isinstance(performance.get("ip_update_interval"), int) or performance["ip_update_interval"] < 300:
        performance["ip_update_interval"] = 1800
        errors.append("Missing or invalid 'performance.ip_update_interval' - reset to 1800")
    if not isinstance(performance.get("ping_target_host"), str) or not performance["ping_target_host"].strip():
        performance["ping_target_host"] = "1.1.1.1"
        errors.append("Missing or invalid 'performance.ping_target_host' - reset to 1.1.1.1")

    bad_sites: list[str] = []
    for name, site in list(config["sites"].items()):
        if not isinstance(site, dict):
            bad_sites.append(name)
            continue
        if "domains" not in site or not isinstance(site.get("domains"), list) or not site["domains"]:
            bad_sites.append(name)
            errors.append(f"Site '{name}' missing 'domains' list - removed")
            continue
        if "dns_resolve" not in site or not isinstance(site.get("dns_resolve"), list):
            site["dns_resolve"] = site["domains"][:6]
        if "ips" not in site or not isinstance(site.get("ips"), list):
            site["ips"] = []
        if "enabled" not in site:
            site["enabled"] = True

        # Retire historical third-party VPN integration keys during config migration.
        if "vpn" in site:
            del site["vpn"]
            errors.append(f"Removed obsolete 'vpn' field from site '{name}'")

    for name in bad_sites:
        del config["sites"][name]

    if "vpn" in config:
        del config["vpn"]
        errors.append("Removed obsolete top-level 'vpn' field")

    return config, errors


def load_config_file(path: str, logger=None) -> dict[str, Any]:
    fallback = default_config()
    try:
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
        config, errors = validate_config(config)
        if config is None:
            if logger:
                logger.error(f"Config validation failed: {errors}")
            return fallback
        for err in errors:
            if logger:
                logger.warning(f"[CONFIG] {err}")
        if logger:
            logger.info(f"Config loaded: {len(config.get('sites', {}))} sites")
        return config
    except json.JSONDecodeError as e:
        if logger:
            logger.error(f"Config JSON parse error (line {e.lineno}): {e.msg}")
            logger.error("Using default config. Fix config.json and reload.")
        return fallback
    except FileNotFoundError:
        save_config_file(path, fallback, indent=2)
        if logger:
            logger.info("Default config.json created")
        return fallback
    except Exception as e:
        if logger:
            logger.error(f"Config read error: {e}")
        return fallback


def save_config_file(path: str, config: dict[str, Any], indent: int = 4) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=indent, ensure_ascii=False)


def build_lists_from_config(config: dict[str, Any]):
    all_domains: list[str] = []
    all_ips: list[str] = []
    domain_to_site: dict[str, str] = {}
    site_ips: dict[str, list[str]] = {}
    site_dns: dict[str, list[str]] = {}

    for site_name, site_data in config.get("sites", {}).items():
        if not site_data.get("enabled", True):
            continue
        domains = site_data.get("domains", [])
        if not domains:
            domains = [f"{site_name}.com", f"www.{site_name}.com"]
            site_data["domains"] = domains
        dns_resolve = site_data.get("dns_resolve", [])
        if not dns_resolve:
            dns_resolve = list(domains)
            site_data["dns_resolve"] = dns_resolve

        all_domains.extend(domains)
        site_dns[site_name] = dns_resolve

        site_ip_list = site_data.get("ips", [])
        all_ips.extend(site_ip_list)
        site_ips[site_name] = list(site_ip_list)

        for domain in domains:
            domain_to_site[domain.lower()] = site_name

    return list(set(all_domains)), list(set(all_ips)), domain_to_site, site_ips, site_dns
