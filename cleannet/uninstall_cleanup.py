"""Undo CleanNet's changes to Windows, for the installer and uninstaller.

``CleanNet.exe --cleanup`` (uninstall) restores the proxy and removes autostart;
``CleanNet.exe --restore-proxy`` (install/upgrade) only restores the proxy.

Restoring the proxy means bringing back the proxy the user had before CleanNet, or
switching off a proxy that still points at CleanNet (left behind by a crash or by an older
uninstaller). Settings, sites and learned data in the data folder are left alone.
"""

from __future__ import annotations

import json
import logging
import os

from .settings import RuntimeSettings, build_app_paths
from .windows_integration import recover_orphaned_proxy, set_autostart

CLEANUP_FLAG = "--cleanup"
RESTORE_PROXY_FLAG = "--restore-proxy"


def _configured_proxy_port(config_file: str, default: int) -> int:
    try:
        with open(config_file, "r", encoding="utf-8-sig") as f:
            port = int(json.load(f).get("proxy_port", default))
    except (OSError, ValueError, TypeError, AttributeError):
        return default
    return port if 0 < port < 65536 else default


def _build_logger(data_dir: str) -> logging.Logger:
    logger = logging.getLogger("cleannet.cleanup")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers and os.path.isdir(data_dir):
        try:
            handler = logging.FileHandler(os.path.join(data_dir, "bypass.log"), encoding="utf-8")
        except OSError:
            return logger
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(handler)
    return logger


def run_cleanup(app_file: str, remove_autostart: bool = True, logger: logging.Logger | None = None) -> int:
    paths = build_app_paths(app_file)
    settings = RuntimeSettings()
    logger = logger or _build_logger(paths.script_dir)
    logger.info("[CLEANUP] Restoring Windows proxy" + (" and removing autostart" if remove_autostart else ""))

    ports = [_configured_proxy_port(paths.config_file, settings.local_port)]
    if settings.local_port not in ports:
        ports.append(settings.local_port)
    for port in ports:
        if recover_orphaned_proxy(settings.local_host, port, paths.script_dir, logger=logger):
            break

    if remove_autostart:
        set_autostart(False, settings.autostart_reg_name, paths.app_file, logger=logger)
    logger.info("[CLEANUP] Done")
    return 0
