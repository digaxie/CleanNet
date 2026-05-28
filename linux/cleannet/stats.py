"""Stats persistence helpers."""

from __future__ import annotations

import copy
import json
from typing import Any


def load_stats_file(path: str, defaults: dict[str, Any], logger=None):
    stats = copy.deepcopy(defaults.get("global", {}))
    site_stats = copy.deepcopy(defaults.get("sites", {}))
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data.get("global"), dict):
            for key in stats:
                if key in data["global"]:
                    stats[key] = data["global"][key]
        if isinstance(data.get("sites"), dict):
            site_stats.update(data["sites"])
        if logger:
            logger.info(f"Stats loaded: {stats.get('connections', 0)} total connections")
    except FileNotFoundError:
        pass
    except Exception as e:
        if logger:
            logger.warning(f"Stats load error: {e}")
    return stats, site_stats


def save_stats_file(path: str, stats: dict[str, Any], site_stats: dict[str, Any], logger=None) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"global": stats, "sites": site_stats}, f, indent=2)
    except Exception as e:
        if logger:
            logger.error(f"Stats save error: {e}")

