"""Windows proxy, autostart, language, and proxy restore integration."""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any

try:
    import ctypes
    import winreg
except ImportError:  # pragma: no cover - Windows runtime module.
    ctypes = None
    winreg = None


INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
CONNECTIONS_KEY = INTERNET_SETTINGS_KEY + r"\Connections"
AUTOSTART_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
PROXY_BACKUP_FILE = "proxy_state.json"
CONNECTION_PROXY_FLAG = 0x02


def build_bypass_list(always_bypass: list[str], user_bypass: list[str] | None = None) -> str:
    entries: list[str] = []
    seen: set[str] = set()
    for item in list(always_bypass or []) + list(user_bypass or []):
        if item and item not in seen:
            seen.add(item)
            entries.append(item)
    return ";".join(entries)


def is_app_proxy_server(server: str | None, host: str, port: int) -> bool:
    return (server or "").strip().lower() == f"{host}:{port}".lower()


def _backup_path(app_dir: str) -> str:
    return os.path.join(app_dir, PROXY_BACKUP_FILE)


def _read_value(key, name: str) -> dict[str, Any]:
    try:
        value, value_type = winreg.QueryValueEx(key, name)
        if isinstance(value, (bytes, bytearray)):
            value = list(value)
        return {"exists": True, "value": value, "type": value_type}
    except FileNotFoundError:
        return {"exists": False, "value": None, "type": None}


def _write_value(key, name: str, item: dict[str, Any]) -> None:
    if item.get("exists"):
        value = item.get("value")
        value_type = int(item["type"])
        if value_type == getattr(winreg, "REG_BINARY", 3) and isinstance(value, list):
            value = bytes(int(part) & 0xFF for part in value)
        winreg.SetValueEx(key, name, 0, value_type, value)
        return
    try:
        winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass


def _refresh_proxy_settings() -> None:
    if ctypes is None:
        return
    try:
        ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
        ctypes.windll.user32.SendMessageTimeoutW(
            0xFFFF,
            0x001A,
            0,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            0x0002,
            5000,
            None,
        )
    except Exception:
        pass


def _pack_dword(value: int) -> bytes:
    return int(value).to_bytes(4, "little", signed=False)


def _unpack_dword(data: bytes, offset: int, default: int = 0) -> int:
    if offset < 0 or offset + 4 > len(data):
        return default
    return int.from_bytes(data[offset : offset + 4], "little", signed=False)


def _coerce_binary(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, list):
        return bytes(int(part) & 0xFF for part in value)
    return b""


def _connection_tail(data: bytes) -> bytes:
    if len(data) < 16:
        return _pack_dword(0)
    proxy_len = _unpack_dword(data, 12)
    bypass_len_offset = 16 + proxy_len
    if bypass_len_offset + 4 > len(data):
        return _pack_dword(0)
    bypass_len = _unpack_dword(data, bypass_len_offset)
    tail_offset = bypass_len_offset + 4 + bypass_len
    if tail_offset > len(data):
        return _pack_dword(0)
    return data[tail_offset:] or _pack_dword(0)


def _build_connection_settings_blob(
    existing: Any,
    enable: bool,
    proxy_server: str,
    bypass_list: str,
) -> bytes:
    data = _coerce_binary(existing)
    if len(data) >= 8:
        version = data[:4]
        counter = (_unpack_dword(data, 4) + 1) & 0xFFFFFFFF
    else:
        version = b"\x46\x00\x00\x00"
        counter = 1

    flags = _unpack_dword(data, 8, 1)
    if enable:
        flags |= CONNECTION_PROXY_FLAG
    else:
        flags &= ~CONNECTION_PROXY_FLAG

    proxy_bytes = proxy_server.encode("ascii", "ignore")
    bypass_bytes = bypass_list.encode("ascii", "ignore")
    return (
        version
        + _pack_dword(counter)
        + _pack_dword(flags)
        + _pack_dword(len(proxy_bytes))
        + proxy_bytes
        + _pack_dword(len(bypass_bytes))
        + bypass_bytes
        + _connection_tail(data)
    )


def _read_connection_state() -> dict[str, Any]:
    state: dict[str, Any] = {}
    if winreg is None:
        return state
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, CONNECTIONS_KEY, 0, winreg.KEY_READ)
    except Exception:
        return state
    try:
        for name in ("DefaultConnectionSettings", "SavedLegacySettings"):
            state[name] = _read_value(key, name)
    finally:
        winreg.CloseKey(key)
    return state


def _write_connection_state(state: dict[str, Any]) -> None:
    if winreg is None or not state:
        return
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, CONNECTIONS_KEY, 0, winreg.KEY_ALL_ACCESS)
    except Exception:
        return
    try:
        for name in ("DefaultConnectionSettings", "SavedLegacySettings"):
            if name in state:
                _write_value(key, name, state[name])
    finally:
        winreg.CloseKey(key)


def _sync_connection_proxy_settings(enable: bool, host: str, port: int, bypass_list: str) -> bool:
    if winreg is None:
        return False
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, CONNECTIONS_KEY, 0, winreg.KEY_ALL_ACCESS)
    except Exception:
        return False
    try:
        proxy_server = f"{host}:{port}"
        for name in ("DefaultConnectionSettings", "SavedLegacySettings"):
            try:
                existing, value_type = winreg.QueryValueEx(key, name)
            except FileNotFoundError:
                existing, value_type = b"", getattr(winreg, "REG_BINARY", 3)
            blob = _build_connection_settings_blob(existing, enable, proxy_server, bypass_list)
            winreg.SetValueEx(key, name, 0, value_type, blob)
        return True
    except Exception:
        return False
    finally:
        winreg.CloseKey(key)


def read_proxy_state() -> dict[str, Any]:
    if winreg is None:
        return {}
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_READ)
    try:
        state = {
            "ProxyEnable": _read_value(key, "ProxyEnable"),
            "ProxyServer": _read_value(key, "ProxyServer"),
            "ProxyOverride": _read_value(key, "ProxyOverride"),
        }
    finally:
        winreg.CloseKey(key)
    state["ConnectionSettings"] = _read_connection_state()
    return state


def _write_proxy_state(state: dict[str, Any]) -> None:
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_ALL_ACCESS)
    try:
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
            if name in state:
                _write_value(key, name, state[name])
    finally:
        winreg.CloseKey(key)
    _write_connection_state(state.get("ConnectionSettings", {}))
    _refresh_proxy_settings()


def _write_app_proxy(host: str, port: int, bypass_list: str) -> None:
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_ALL_ACCESS)
    try:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, bypass_list)
    finally:
        winreg.CloseKey(key)
    _sync_connection_proxy_settings(True, host, port, bypass_list)


def _save_backup(app_dir: str, state: dict[str, Any], host: str, port: int) -> None:
    payload = {
        "version": 1,
        "created_at": int(time.time()),
        "app_proxy": f"{host}:{port}",
        "state": state,
    }
    with open(_backup_path(app_dir), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def _load_backup(app_dir: str) -> dict[str, Any] | None:
    try:
        with open(_backup_path(app_dir), "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _clear_backup(app_dir: str) -> None:
    try:
        os.remove(_backup_path(app_dir))
    except FileNotFoundError:
        pass


def get_proxy_backup_status(app_dir: str) -> dict[str, Any]:
    backup = _load_backup(app_dir)
    if not backup:
        return {"exists": False}
    return {
        "exists": True,
        "created_at": backup.get("created_at"),
        "app_proxy": backup.get("app_proxy"),
    }


def get_proxy_summary(app_dir: str, host: str, port: int) -> dict[str, Any]:
    try:
        state = read_proxy_state()
        server = state.get("ProxyServer", {}).get("value")
        enabled = bool(state.get("ProxyEnable", {}).get("value", 0))
        return {
            "enabled": enabled,
            "server": server or "",
            "owned_by_cleannet": enabled and is_app_proxy_server(server, host, port),
            "backup": get_proxy_backup_status(app_dir),
        }
    except Exception:
        return {"enabled": False, "server": "", "owned_by_cleannet": False, "backup": {"exists": False}}


def ensure_system_proxy_enabled(
    host: str,
    port: int,
    always_bypass: list[str],
    user_bypass: list[str] | None,
    logger=None,
) -> bool:
    if winreg is None:
        return False
    try:
        bypass_list = build_bypass_list(always_bypass, user_bypass)
        current = read_proxy_state()
        enabled = bool(current.get("ProxyEnable", {}).get("value", 0))
        server = current.get("ProxyServer", {}).get("value")
        override = current.get("ProxyOverride", {}).get("value") or ""
        if enabled and is_app_proxy_server(server, host, port) and override == bypass_list:
            return True

        _write_app_proxy(host, port, bypass_list)
        _refresh_proxy_settings()
        _write_app_proxy(host, port, bypass_list)
        if logger:
            logger.warning("[PROXY] Repaired Windows proxy ownership")
        return True
    except Exception as e:
        if logger:
            logger.error(f"Proxy repair error: {e}")
        return False


def recover_orphaned_proxy(host: str, port: int, app_dir: str, logger=None) -> bool:
    """Clean up a previous CleanNet proxy before a new runtime takes ownership.

    This preserves a user's existing proxy whenever it is not owned by CleanNet.
    """
    if winreg is None:
        return False
    try:
        backup = _load_backup(app_dir)
        if backup and isinstance(backup.get("state"), dict):
            _write_proxy_state(backup["state"])
            _clear_backup(app_dir)
            if logger:
                logger.info("[PROXY] Recovered previous proxy state from CleanNet backup")
            return True

        current = read_proxy_state()
        enabled = bool(current.get("ProxyEnable", {}).get("value", 0))
        server = current.get("ProxyServer", {}).get("value")
        if enabled and is_app_proxy_server(server, host, port):
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_ALL_ACCESS)
            try:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            finally:
                winreg.CloseKey(key)
            _sync_connection_proxy_settings(False, host, port, "")
            _refresh_proxy_settings()
            if logger:
                logger.info("[PROXY] Cleared stale CleanNet proxy without backup")
            return True
    except Exception as e:
        if logger:
            logger.warning(f"[PROXY] Startup recovery skipped: {e}")
    return False


def set_system_proxy(
    enable: bool,
    host: str,
    port: int,
    always_bypass: list[str],
    user_bypass: list[str] | None,
    app_dir: str,
    logger=None,
) -> bool:
    if winreg is None:
        return False
    try:
        backup_path = _backup_path(app_dir)
        if enable:
            if not os.path.exists(backup_path):
                current = read_proxy_state()
                _save_backup(app_dir, current, host, port)
            bypass_list = build_bypass_list(always_bypass, user_bypass)
            _write_app_proxy(host, port, bypass_list)
            _refresh_proxy_settings()
            _write_app_proxy(host, port, bypass_list)
            return True

        backup = _load_backup(app_dir)
        if backup and isinstance(backup.get("state"), dict):
            _write_proxy_state(backup["state"])
            _clear_backup(app_dir)
            if logger:
                logger.info("[PROXY] Previous Windows proxy state restored")
            return True

        current = read_proxy_state()
        enabled = bool(current.get("ProxyEnable", {}).get("value", 0))
        server = current.get("ProxyServer", {}).get("value")
        if not enabled or not is_app_proxy_server(server, host, port):
            return True

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_ALL_ACCESS)
        try:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        finally:
            winreg.CloseKey(key)
        _sync_connection_proxy_settings(False, host, port, "")
        _refresh_proxy_settings()
        return True
    except Exception as e:
        if logger:
            logger.error(f"Proxy settings error: {e}")
        return False


def get_autostart(reg_name: str) -> bool:
    if winreg is None:
        return False
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_REG_KEY, 0, winreg.KEY_READ)
        try:
            winreg.QueryValueEx(key, reg_name)
            return True
        except FileNotFoundError:
            return False
        finally:
            winreg.CloseKey(key)
    except Exception:
        return False


def set_autostart(enable: bool, reg_name: str, script_path: str, executable: str | None = None, logger=None) -> bool:
    if winreg is None:
        return False
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_REG_KEY, 0, winreg.KEY_ALL_ACCESS)
        try:
            if enable:
                pythonw = os.path.join(os.path.dirname(executable or sys.executable), "pythonw.exe")
                if not os.path.exists(pythonw):
                    pythonw = executable or sys.executable
                cmd = f'"{pythonw}" "{script_path}"'
                winreg.SetValueEx(key, reg_name, 0, winreg.REG_SZ, cmd)
                if logger:
                    logger.info("Autostart enabled")
            else:
                try:
                    winreg.DeleteValue(key, reg_name)
                    if logger:
                        logger.info("Autostart disabled")
                except FileNotFoundError:
                    pass
        finally:
            winreg.CloseKey(key)
        return True
    except Exception as e:
        if logger:
            logger.error(f"Autostart error: {e}")
        return False


def get_user_language() -> str:
    if winreg is None:
        return "en"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\International")
        try:
            locale_name = winreg.QueryValueEx(key, "LocaleName")[0]
        finally:
            winreg.CloseKey(key)
        lang = locale_name.split("-")[0].lower()
        if lang in ("tr", "de"):
            return lang
    except Exception:
        pass
    return "en"
