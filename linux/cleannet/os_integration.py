"""Linux proxy, autostart, language, and proxy restore integration."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any


PROXY_BACKUP_FILE = "linux_proxy_state.json"
ENV_PROXY_FILE = "proxy.env"


@dataclass(frozen=True)
class ProxyBackend:
    name: str
    supported: bool
    manual_env_file: str = ""
    error: str = ""


def _run(args: list[str], timeout: float = 3.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def _is_kde() -> bool:
    return "KDE" in os.environ.get("XDG_CURRENT_DESKTOP", "").upper()


def _config_dir() -> str:
    root = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(root, "cleannet")


def _env_proxy_file_path() -> str:
    return os.path.join(_config_dir(), ENV_PROXY_FILE)


def _backup_path(app_dir: str) -> str:
    return os.path.join(app_dir, PROXY_BACKUP_FILE)


def _kde_commands() -> tuple[str, str] | None:
    writer = shutil.which("kwriteconfig6") or shutil.which("kwriteconfig5")
    reader = shutil.which("kreadconfig6") or shutil.which("kreadconfig5")
    if writer and reader:
        return writer, reader
    return None


def _has_gnome_proxy_schema() -> bool:
    if not shutil.which("gsettings"):
        return False
    try:
        res = _run(["gsettings", "list-schemas"])
    except Exception:
        return False
    return res.returncode == 0 and "org.gnome.system.proxy" in res.stdout.splitlines()


def detect_proxy_backend() -> ProxyBackend:
    if _is_kde() and _kde_commands():
        return ProxyBackend("kde", True)
    if _has_gnome_proxy_schema():
        return ProxyBackend("gnome", True)
    return ProxyBackend(
        "env-file",
        False,
        manual_env_file=_env_proxy_file_path(),
        error="No supported desktop proxy backend found; wrote an env file for manual use.",
    )


def build_bypass_list(always_bypass: list[str], user_bypass: list[str] | None = None) -> str:
    entries: list[str] = []
    seen: set[str] = set()
    for item in list(always_bypass or []) + list(user_bypass or []):
        if item and item not in seen:
            seen.add(item)
            entries.append(item)
    return ",".join(entries)


def is_app_proxy_server(server: str | None, host: str, port: int) -> bool:
    return (server or "").strip().lower() == f"{host}:{port}".lower()


def _require_success(res: subprocess.CompletedProcess[str], action: str) -> None:
    if res.returncode != 0:
        detail = (res.stderr or res.stdout or "").strip()
        raise RuntimeError(f"{action} failed: {detail or res.returncode}")


def _gsettings_get(schema: str, key: str) -> str:
    res = _run(["gsettings", "get", schema, key])
    _require_success(res, f"gsettings get {schema} {key}")
    return res.stdout.strip().strip("'\"")


def _gsettings_set(schema: str, key: str, value: str) -> None:
    res = _run(["gsettings", "set", schema, key, value])
    _require_success(res, f"gsettings set {schema} {key}")


def _read_gnome_state() -> dict[str, Any]:
    return {
        "mode": _gsettings_get("org.gnome.system.proxy", "mode") or "none",
        "http_host": _gsettings_get("org.gnome.system.proxy.http", "host"),
        "http_port": int(_gsettings_get("org.gnome.system.proxy.http", "port") or 0),
        "https_host": _gsettings_get("org.gnome.system.proxy.https", "host"),
        "https_port": int(_gsettings_get("org.gnome.system.proxy.https", "port") or 0),
        "ignore_hosts": _gsettings_get("org.gnome.system.proxy", "ignore-hosts"),
    }


def _write_gnome_state(state: dict[str, Any]) -> None:
    mode = str(state.get("mode") or "none")
    _gsettings_set("org.gnome.system.proxy", "mode", mode)
    if mode == "manual":
        _gsettings_set("org.gnome.system.proxy.http", "host", str(state.get("http_host") or ""))
        _gsettings_set("org.gnome.system.proxy.http", "port", str(int(state.get("http_port") or 0)))
        _gsettings_set("org.gnome.system.proxy.https", "host", str(state.get("https_host") or ""))
        _gsettings_set("org.gnome.system.proxy.https", "port", str(int(state.get("https_port") or 0)))
        _gsettings_set("org.gnome.system.proxy", "ignore-hosts", str(state.get("ignore_hosts") or "[]"))


def _enable_gnome_proxy(host: str, port: int, bypass_list: str) -> None:
    ignore_hosts = [item.strip() for item in bypass_list.split(",") if item.strip()]
    _write_gnome_state({
        "mode": "manual",
        "http_host": host,
        "http_port": port,
        "https_host": host,
        "https_port": port,
        "ignore_hosts": str(ignore_hosts),
    })


def _kread(group: str, key: str) -> str:
    commands = _kde_commands()
    if not commands:
        raise RuntimeError("KDE config tools are not installed")
    _writer, reader = commands
    res = _run([reader, "--file", "kioslaverc", "--group", group, "--key", key])
    _require_success(res, f"kreadconfig {group}/{key}")
    return res.stdout.strip()


def _kwrite(group: str, key: str, value: str) -> None:
    commands = _kde_commands()
    if not commands:
        raise RuntimeError("KDE config tools are not installed")
    writer, _reader = commands
    res = _run([writer, "--file", "kioslaverc", "--group", group, "--key", key, value])
    _require_success(res, f"kwriteconfig {group}/{key}")


def _notify_kde_proxy_change() -> None:
    if not shutil.which("dbus-send"):
        return
    try:
        _run([
            "dbus-send",
            "--type=signal",
            "/KIO/Scheduler",
            "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
            "string:''",
        ], timeout=2)
    except Exception:
        pass


def _read_kde_state() -> dict[str, Any]:
    return {
        "proxy_type": _kread("Proxy Settings", "ProxyType") or "0",
        "http_proxy": _kread("Proxy Settings", "httpProxy"),
        "https_proxy": _kread("Proxy Settings", "httpsProxy"),
        "no_proxy_for": _kread("Proxy Settings", "NoProxyFor"),
    }


def _write_kde_state(state: dict[str, Any]) -> None:
    _kwrite("Proxy Settings", "ProxyType", str(state.get("proxy_type") or "0"))
    _kwrite("Proxy Settings", "httpProxy", str(state.get("http_proxy") or ""))
    _kwrite("Proxy Settings", "httpsProxy", str(state.get("https_proxy") or ""))
    _kwrite("Proxy Settings", "NoProxyFor", str(state.get("no_proxy_for") or ""))
    _notify_kde_proxy_change()


def _enable_kde_proxy(host: str, port: int, bypass_list: str) -> None:
    _write_kde_state({
        "proxy_type": "1",
        "http_proxy": f"http://{host}:{port}",
        "https_proxy": f"http://{host}:{port}",
        "no_proxy_for": bypass_list,
    })


def _read_env_state() -> dict[str, Any]:
    path = _env_proxy_file_path()
    if not os.path.exists(path):
        return {"exists": False, "content": ""}
    with open(path, "r", encoding="utf-8") as f:
        return {"exists": True, "content": f.read()}


def _write_env_state(state: dict[str, Any]) -> None:
    path = _env_proxy_file_path()
    if state.get("exists"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(str(state.get("content") or ""))
    elif os.path.exists(path):
        os.remove(path)


def _write_env_proxy(host: str, port: int, bypass_list: str) -> None:
    path = _env_proxy_file_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    proxy = f"http://{host}:{port}"
    no_proxy = bypass_list
    content = (
        "# Generated by CleanNet. Source this file manually to use the local proxy in this shell.\n"
        f"export HTTP_PROXY={shlex.quote(proxy)}\n"
        f"export HTTPS_PROXY={shlex.quote(proxy)}\n"
        f"export NO_PROXY={shlex.quote(no_proxy)}\n"
        f"export http_proxy={shlex.quote(proxy)}\n"
        f"export https_proxy={shlex.quote(proxy)}\n"
        f"export no_proxy={shlex.quote(no_proxy)}\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _read_backend_state(backend: str) -> dict[str, Any]:
    if backend == "gnome":
        return _read_gnome_state()
    if backend == "kde":
        return _read_kde_state()
    return _read_env_state()


def _restore_backend_state(backend: str, state: dict[str, Any]) -> None:
    if backend == "gnome":
        _write_gnome_state(state)
    elif backend == "kde":
        _write_kde_state(state)
    else:
        _write_env_state(state)


def _enable_backend_proxy(backend: str, host: str, port: int, bypass_list: str) -> None:
    if backend == "gnome":
        _enable_gnome_proxy(host, port, bypass_list)
    elif backend == "kde":
        _enable_kde_proxy(host, port, bypass_list)
    else:
        _write_env_proxy(host, port, bypass_list)


def _load_backup(app_dir: str) -> dict[str, Any] | None:
    path = _backup_path(app_dir)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _save_backup(app_dir: str, backend: str, state: dict[str, Any], host: str, port: int) -> None:
    os.makedirs(app_dir, exist_ok=True)
    existing = _load_backup(app_dir)
    if existing:
        return
    with open(_backup_path(app_dir), "w", encoding="utf-8") as f:
        json.dump({
            "backend": backend,
            "state": state,
            "host": host,
            "port": port,
            "created_at": int(time.time()),
        }, f, indent=2)


def _delete_backup(app_dir: str) -> None:
    try:
        os.remove(_backup_path(app_dir))
    except FileNotFoundError:
        pass


def _server_from_gnome_state(state: dict[str, Any]) -> str:
    host = str(state.get("http_host") or "")
    port = int(state.get("http_port") or 0)
    return f"{host}:{port}" if host and port else ""


def _server_from_kde_proxy(value: str) -> str:
    raw = (value or "").strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.rstrip("/")
    return raw


def _server_from_env_state(state: dict[str, Any]) -> str:
    content = str(state.get("content") or "")
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("export HTTP_PROXY=") or line.startswith("HTTP_PROXY="):
            value = line.split("=", 1)[1].strip().strip("'\"")
            if "://" in value:
                value = value.split("://", 1)[1]
            return value.rstrip("/")
    return ""


def get_proxy_backup_status(app_dir: str) -> dict[str, Any]:
    backup = _load_backup(app_dir)
    if not backup:
        return {"exists": False}
    return {
        "exists": True,
        "backend": backup.get("backend", ""),
        "created_at": backup.get("created_at", 0),
    }


def get_proxy_summary(app_dir: str, host: str, port: int) -> dict[str, Any]:
    backend = detect_proxy_backend()
    payload = {
        "enabled": False,
        "server": "",
        "owned_by_cleannet": False,
        "backend": backend.name,
        "supported": backend.supported,
        "error": backend.error,
        "manual_env_file": backend.manual_env_file,
        "backup": get_proxy_backup_status(app_dir),
    }
    try:
        state = _read_backend_state(backend.name)
        if backend.name == "gnome":
            payload["enabled"] = state.get("mode") == "manual"
            payload["server"] = _server_from_gnome_state(state)
        elif backend.name == "kde":
            payload["enabled"] = state.get("proxy_type") == "1"
            payload["server"] = _server_from_kde_proxy(str(state.get("http_proxy") or ""))
        else:
            payload["enabled"] = bool(state.get("exists"))
            payload["server"] = _server_from_env_state(state)
        payload["owned_by_cleannet"] = bool(payload["enabled"] and is_app_proxy_server(payload["server"], host, port))
    except Exception as exc:
        payload["error"] = str(exc)
    return payload


def ensure_system_proxy_enabled(
    host: str,
    port: int,
    always_bypass: list[str],
    user_bypass: list[str] | None,
    app_dir: str = "",
    logger=None,
) -> bool:
    summary = get_proxy_summary(app_dir, host, port)
    if summary.get("owned_by_cleannet"):
        return True
    return set_system_proxy(True, host, port, always_bypass, user_bypass, app_dir, logger=logger)


def recover_orphaned_proxy(host: str, port: int, app_dir: str, logger=None) -> bool:
    summary = get_proxy_summary(app_dir, host, port)
    if not summary.get("owned_by_cleannet") and not summary.get("backup", {}).get("exists"):
        return False
    restored = set_system_proxy(False, host, port, [], [], app_dir, logger=logger)
    if restored and logger:
        logger.info("[PROXY] Cleared stale CleanNet proxy on Linux")
    return restored


def set_system_proxy(
    enable: bool,
    host: str,
    port: int,
    always_bypass: list[str],
    user_bypass: list[str] | None,
    app_dir: str,
    logger=None,
) -> bool:
    backend = detect_proxy_backend()
    app_dir = app_dir or os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share"), "cleannet")
    try:
        if enable:
            state = _read_backend_state(backend.name)
            _save_backup(app_dir, backend.name, state, host, port)
            _enable_backend_proxy(backend.name, host, port, build_bypass_list(always_bypass, user_bypass))
            if logger:
                if backend.name == "env-file":
                    logger.warning(f"Linux desktop proxy backend not found; wrote manual env file: {backend.manual_env_file}")
                else:
                    logger.info(f"Linux proxy enabled via {backend.name}")
            return True

        backup = _load_backup(app_dir)
        if backup:
            _restore_backend_state(str(backup.get("backend") or backend.name), dict(backup.get("state") or {}))
            _delete_backup(app_dir)
            if logger:
                logger.info("[PROXY] Previous Linux proxy state restored")
            return True

        summary = get_proxy_summary(app_dir, host, port)
        if summary.get("owned_by_cleannet"):
            _restore_backend_state(backend.name, {"mode": "none"} if backend.name == "gnome" else {"proxy_type": "0"} if backend.name == "kde" else {"exists": False})
            if logger:
                logger.info(f"Linux CleanNet proxy cleared via {backend.name}")
        return True
    except Exception as exc:
        if logger:
            logger.error(f"Linux proxy settings error: {exc}")
        return False


def _get_autostart_path(reg_name: str) -> str:
    config_dir = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    autostart_dir = os.path.join(config_dir, "autostart")
    os.makedirs(autostart_dir, exist_ok=True)
    return os.path.join(autostart_dir, f"{reg_name}.desktop")


def get_autostart(reg_name: str) -> bool:
    path = _get_autostart_path(reg_name)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            return "X-GNOME-Autostart-enabled=false" not in content and "Hidden=true" not in content
        except Exception:
            pass
    return False


def set_autostart(enable: bool, reg_name: str, script_path: str, executable: str | None = None, logger=None) -> bool:
    path = _get_autostart_path(reg_name)
    try:
        if enable:
            python_exec = executable or sys.executable
            source_dir = os.path.dirname(os.path.abspath(script_path))
            if os.path.basename(source_dir) == "cleannet":
                source_dir = os.path.dirname(source_dir)
            desktop_entry = (
                "[Desktop Entry]\n"
                "Type=Application\n"
                f"Name={reg_name}\n"
                f"Exec={shlex.quote(python_exec)} -m cleannet\n"
                f"Path={source_dir}\n"
                "Terminal=false\n"
                "Hidden=false\n"
            )
            with open(path, "w", encoding="utf-8") as f:
                f.write(desktop_entry)
            if logger:
                logger.info("Linux autostart enabled")
        else:
            if os.path.exists(path):
                os.remove(path)
            if logger:
                logger.info("Linux autostart disabled")
        return True
    except Exception as e:
        if logger:
            logger.error(f"Linux autostart error: {e}")
        return False


def get_user_language() -> str:
    lang = os.environ.get("LANG", "en_US").split("_")[0].lower()
    if lang in ("tr", "de"):
        return lang
    return "en"
