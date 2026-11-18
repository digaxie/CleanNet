"""Configuration loading, validation, and derived site indexes."""

from __future__ import annotations

import copy
import json
import os
import shutil
import time
from typing import Any

from .config_defaults import DEFAULT_CONFIG


def default_config() -> dict[str, Any]:
    return copy.deepcopy(DEFAULT_CONFIG)


def atomic_write_json(path: str, data: Any, indent: int | None = 2, ensure_ascii: bool = False) -> None:
    """Write JSON so that a crash or power loss never leaves a truncated file behind.

    The data is written to a temporary file in the same folder and then swapped in
    with ``os.replace``, which is atomic on Windows and POSIX.
    """
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp_path = f"{path}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=ensure_ascii)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def _is_valid_port(value: Any) -> bool:
    # bool is a subclass of int; "proxy_port": true must not be accepted as port 1.
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < 65536


def _clean_domain_list(values: Any) -> list[str]:
    """Keep non-empty string entries, lowercased and de-duplicated, in order."""
    result: list[str] = []
    if not isinstance(values, list):
        return result
    for value in values:
        if not isinstance(value, str):
            continue
        value = value.strip().lower().rstrip(".")
        if value and value not in result:
            result.append(value)
    return result


def validate_config(config: Any) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate config structure and fill safe defaults."""
    errors: list[str] = []
    if not isinstance(config, dict):
        return None, ["Config is not a JSON object"]

    if "sites" not in config or not isinstance(config.get("sites"), dict):
        config["sites"] = {}
        errors.append("Missing or invalid 'sites' - reset to empty")
    if not _is_valid_port(config.get("proxy_port")):
        config["proxy_port"] = 8080
        errors.append("Missing or invalid 'proxy_port' - reset to 8080")
    if not _is_valid_port(config.get("dashboard_port")):
        config["dashboard_port"] = 8888
        errors.append("Missing or invalid 'dashboard_port' - reset to 8888")
    if config["dashboard_port"] == config["proxy_port"]:
        config["proxy_port"], config["dashboard_port"] = 8080, 8888
        errors.append("'proxy_port' and 'dashboard_port' must differ - reset to 8080/8888")
    if "proxy_bypass" not in config or not isinstance(config.get("proxy_bypass"), list):
        config["proxy_bypass"] = []
        errors.append("Missing or invalid 'proxy_bypass' - reset to empty")
    else:
        cleaned_bypass = [entry.strip() for entry in config["proxy_bypass"] if isinstance(entry, str) and entry.strip()]
        if len(cleaned_bypass) != len(config["proxy_bypass"]):
            errors.append("Removed invalid 'proxy_bypass' entries")
        config["proxy_bypass"] = cleaned_bypass
    if "privacy" not in config or not isinstance(config.get("privacy"), dict):
        config["privacy"] = {}
        errors.append("Missing or invalid 'privacy' - reset to defaults")
    if not isinstance(config["privacy"].get("hide_dns"), bool):
        config["privacy"]["hide_dns"] = False
        errors.append("Missing or invalid 'privacy.hide_dns' - reset to False")
    if not isinstance(config["privacy"].get("hide_sni"), bool):
        config["privacy"]["hide_sni"] = False
        errors.append("Missing or invalid 'privacy.hide_sni' - reset to False")
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
    if "setup" not in config or not isinstance(config.get("setup"), dict):
        config["setup"] = {"onboarding_completed": True}
        errors.append("Missing or invalid 'setup' - marked onboarding complete for existing config")
    setup = config["setup"]
    if not isinstance(setup.get("onboarding_completed"), bool):
        setup["onboarding_completed"] = False
        errors.append("Missing or invalid 'setup.onboarding_completed' - reset to False")

    bad_sites: list[str] = []
    for name, site in list(config["sites"].items()):
        if not isinstance(site, dict):
            bad_sites.append(name)
            continue
        domains = _clean_domain_list(site.get("domains"))
        if not domains:
            bad_sites.append(name)
            errors.append(f"Site '{name}' missing 'domains' list - removed")
            continue
        site["domains"] = domains
        if "dns_resolve" not in site or not isinstance(site.get("dns_resolve"), list):
            site["dns_resolve"] = domains[:6]
        else:
            site["dns_resolve"] = _clean_domain_list(site["dns_resolve"])
        if "ips" not in site or not isinstance(site.get("ips"), list):
            site["ips"] = []
        else:
            site["ips"] = [ip.strip() for ip in site["ips"] if isinstance(ip, str) and ip.strip()]
        if not isinstance(site.get("enabled", True), bool):
            site["enabled"] = True
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
        # utf-8-sig: Notepad and PowerShell 5 save UTF-8 with a BOM, which plain
        # "utf-8" + json.load rejects and would silently drop the user's config.
        with open(path, "r", encoding="utf-8-sig") as f:
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
        # Keep a copy: the next dashboard change saves the fallback over config.json,
        # which would otherwise destroy the user's (only slightly broken) site list.
        backup_path = f"{path}.corrupt-{int(time.time())}"
        try:
            shutil.copy2(path, backup_path)
        except OSError:
            backup_path = ""
        if logger:
            logger.error(f"Config JSON parse error (line {e.lineno}): {e.msg}")
            if backup_path:
                logger.error(f"Broken config saved as {os.path.basename(backup_path)}")
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
    atomic_write_json(path, config, indent=indent, ensure_ascii=False)


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
