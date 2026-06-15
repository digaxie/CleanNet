"""Windows proxy, autostart, language, and proxy restore integration."""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
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

# Win32 messages used by SessionEndWatcher to learn that Windows is logging off,
# restarting, or shutting down. https://learn.microsoft.com/windows/win32/shutdown
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_QUERYENDSESSION = 0x0011
WM_ENDSESSION = 0x0016


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


def _dns_and_route_ready(probe_host: str, probe_port: int, dns_probe_hosts: list[str]) -> bool:
    # Passthrough traffic relies on the system resolver, so DNS must work...
    resolved = False
    for name in dns_probe_hosts:
        try:
            socket.getaddrinfo(name, probe_port)
            resolved = True
            break
        except OSError:
            continue
    if not resolved:
        return False
    # ...and we must be able to reach a public endpoint over TCP.
    try:
        with socket.create_connection((probe_host, probe_port), timeout=3):
            return True
    except OSError:
        return False


def wait_for_network_ready(
    probe_host: str = "1.1.1.1",
    probe_port: int = 443,
    dns_probe_hosts: list[str] | None = None,
    max_wait: float = 120.0,
    interval: float = 2.0,
    logger=None,
    sleep=time.sleep,
    monotonic=time.monotonic,
) -> bool:
    """Block until the machine has real connectivity, bounded by ``max_wait``.

    At Windows logon the autostart entry runs before DHCP/DNS are ready. Enabling
    the system proxy in that window forces every connection through the local
    engine while it still cannot reach upstream, leaving the machine with no
    internet until the user restarts the app. Gate proxy activation on this check.

    Probes use raw sockets, so they are unaffected by any current system proxy.
    Returns True once connectivity is confirmed, or False if ``max_wait`` elapses.
    """
    if not (probe_host or "").strip():
        probe_host = "1.1.1.1"
    dns_probe_hosts = dns_probe_hosts or ["microsoft.com", "example.com"]
    deadline = monotonic() + max_wait
    attempts = 0
    while True:
        attempts += 1
        if _dns_and_route_ready(probe_host, probe_port, dns_probe_hosts):
            if logger and attempts > 1:
                logger.info(f"[STARTUP] Network ready after {attempts} probe(s)")
            return True
        if monotonic() >= deadline:
            if logger:
                logger.warning(
                    f"[STARTUP] Network not confirmed within {int(max_wait)}s; enabling proxy anyway"
                )
            return False
        sleep(interval)


class SessionEndWatcher:
    """Restore the user's system proxy when Windows logs off / restarts / shuts down.

    Why this exists
    ---------------
    While running, CleanNet points the *Windows system proxy* at its local engine
    (127.0.0.1:<port>). On a normal Exit we put the user's original proxy settings
    back. But when Windows shuts down or restarts *without* the user clicking Exit,
    a windowed app's ``atexit``/signal handlers do not run reliably, so that proxy
    entry would be left behind. If autostart is disabled, the next boot has nothing
    listening on that port and every proxy-aware app (browsers, etc.) loses internet
    until CleanNet is opened again. This watcher closes that gap.

    How it works
    ------------
    Windows notifies *top-level* windows of an impending session end via
    ``WM_QUERYENDSESSION`` / ``WM_ENDSESSION``. We create a single hidden top-level
    window on a dedicated daemon thread purely to receive that notification, then run
    the exact same proxy restore we do on Exit. We never block or delay shutdown: we
    answer ``WM_QUERYENDSESSION`` with TRUE immediately and only restore a couple of
    HKCU registry values on the definitive ``WM_ENDSESSION``.

    Transparency / scope (what this does and does NOT do)
    -----------------------------------------------------
    * It only RESTORES the user's own previous proxy settings - i.e. it removes
      CleanNet's footprint. It never enables anything or adds persistence.
    * No autostart entry, no scheduled task, no network listener, no elevation.
    * The hidden window handles only the session-end messages above; everything else
      is passed to ``DefWindowProcW``. It cannot do anything a co-process at the same
      integrity level could not already do directly to the user's HKCU registry.
    """

    def __init__(self, on_session_end, logger=None, class_name: str = "CleanNetSessionEndWatcher"):
        self._on_session_end = on_session_end
        self._logger = logger
        self._class_name = class_name
        self._thread: threading.Thread | None = None
        self._hwnd = None
        self._wndproc = None  # keep the ctypes callback alive for the window's lifetime
        self._fired = False
        self._fire_lock = threading.Lock()

    def start(self) -> bool:
        if ctypes is None or self._thread is not None:
            return False
        self._thread = threading.Thread(
            target=self._run, name="cleannet-session-watcher", daemon=True
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        if ctypes is None or self._hwnd is None:
            return
        try:
            ctypes.windll.user32.PostMessageW(self._hwnd, WM_CLOSE, 0, 0)
        except Exception:
            pass

    def _fire(self) -> None:
        with self._fire_lock:
            if self._fired:
                return
            self._fired = True
        try:
            self._on_session_end()
        except Exception as exc:
            if self._logger:
                self._logger.error(f"[SHUTDOWN] Proxy restore on session end failed: {exc}")

    def _run(self) -> None:
        try:
            self._message_loop()
        except Exception as exc:
            if self._logger:
                self._logger.debug(f"Session-end watcher stopped: {exc}")

    def _message_loop(self) -> None:
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        WNDPROC = ctypes.WINFUNCTYPE(
            ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
        )

        class WNDCLASS(ctypes.Structure):
            _fields_ = [
                ("style", wintypes.UINT),
                ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HICON),
                ("hCursor", wintypes.HANDLE),
                ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR),
            ]

        def wndproc(hwnd, msg, wparam, lparam):
            try:
                if msg == WM_QUERYENDSESSION:
                    return 1  # always agree; never block or delay the user's shutdown
                if msg == WM_ENDSESSION:
                    if wparam:  # wParam is TRUE only when the session is really ending
                        self._fire()
                    return 0
                if msg == WM_DESTROY:
                    user32.PostQuitMessage(0)
                    return 0
            except Exception:
                pass
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._wndproc = WNDPROC(wndproc)

        # Set explicit restypes/argtypes so HWND/HMODULE pointers are not truncated on 64-bit.
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        user32.DefWindowProcW.restype = ctypes.c_ssize_t
        user32.DefWindowProcW.argtypes = [
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
        ]
        user32.RegisterClassW.restype = wintypes.ATOM
        user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASS)]
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
        ]
        user32.GetMessageW.argtypes = [
            ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT
        ]

        hinst = kernel32.GetModuleHandleW(None)
        wndclass = WNDCLASS()
        wndclass.lpfnWndProc = self._wndproc
        wndclass.hInstance = hinst
        wndclass.lpszClassName = self._class_name
        user32.RegisterClassW(ctypes.byref(wndclass))  # ignore "already registered" on re-entry

        # A normal (never-shown) top-level window; message-only windows do NOT receive
        # the session-end broadcast, so we deliberately avoid HWND_MESSAGE here.
        hwnd = user32.CreateWindowExW(
            0, self._class_name, "CleanNet", 0, 0, 0, 0, 0, None, None, hinst, None
        )
        if not hwnd:
            if self._logger:
                self._logger.debug("Session-end watcher window could not be created")
            return
        self._hwnd = hwnd

        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))


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
