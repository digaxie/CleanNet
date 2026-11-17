"""System tray and user-triggered lifecycle actions."""

from __future__ import annotations

from dataclasses import dataclass
import asyncio
import ctypes
import math
import os
import subprocess
import sys
import tempfile
import threading
import webbrowser
from typing import Any, Awaitable, Callable

from .windows_integration import get_user_language


try:
    import pystray
    from PIL import Image, ImageDraw

    TRAY_AVAILABLE = True
except ImportError:
    pystray = None
    Image = None
    ImageDraw = None
    TRAY_AVAILABLE = False


STATUS_COLORS = {
    "running": (67, 181, 129),
    "stopped": (150, 150, 150),
    "error": (240, 71, 71),
    "reconnecting": (250, 166, 26),
}
STATUS_TEXT = {
    "running": "Active",
    "stopped": "Stopped",
    "error": "Connection Error",
    "reconnecting": "Reconnecting",
}


@dataclass
class TrayRuntimeContext:
    version: str
    logger: Any
    local_host: str
    web_port: int
    log_file: str
    app_file: str
    python_executable: str
    get_status: Callable[[], str]
    get_ping_ms: Callable[[], int]
    get_loop: Callable[[], Any]
    get_shutdown_event: Callable[[], Any]
    set_running: Callable[[bool], None]
    force_save: Callable[[], None]
    set_proxy_enabled: Callable[[bool], None]
    release_instance_lock: Callable[[], None]
    resolve_bypass_ips: Callable[[], Awaitable[Any]]
    asset_dir: str | None = None


def build_status_title(status: str, ping_ms: int) -> str:
    ping_str = f" | {ping_ms}ms" if ping_ms > 0 else ""
    return f"CleanNet - {STATUS_TEXT.get(status, status)}{ping_str}"


def build_full_shutdown_prompt(lang: str) -> tuple[str, str]:
    if lang == "tr":
        return (
            "CleanNet - Tam Kapatma",
            "Bu islem asagidakileri yapacaktir:\n\n"
            "1. DPI Bypass proxy'si durdurulacak\n"
            "2. Windows proxy ayarlari sifirlanacak\n"
            "3. DNS onbellegi temizlenecek (ipconfig /flushdns)\n\n"
            "Diger uygulamalariniz etkilenmeyecektir.\n\n"
            "Devam etmek istiyor musunuz?",
        )
    if lang == "de":
        return (
            "CleanNet - Vollstaendiges Herunterfahren",
            "Folgende Aktionen werden ausgefuehrt:\n\n"
            "1. DPI-Bypass-Proxy wird gestoppt\n"
            "2. Windows-Proxy-Einstellungen werden zurueckgesetzt\n"
            "3. DNS-Cache wird geleert (ipconfig /flushdns)\n\n"
            "Andere Anwendungen werden nicht beeintraechtigt.\n\n"
            "Moechten Sie fortfahren?",
        )
    return (
        "CleanNet - Full Shutdown",
        "The following actions will be performed:\n\n"
        "1. DPI Bypass proxy will be stopped\n"
        "2. Windows proxy settings will be cleared\n"
        "3. DNS cache will be flushed (ipconfig /flushdns)\n\n"
        "Other applications will not be affected.\n\n"
        "Do you want to continue?",
    )


def _candidate_icon_paths(app_dir: str | None, names: list[str]) -> list[str]:
    roots: list[str] = []
    frozen_dir = getattr(sys, "_MEIPASS", None)
    if frozen_dir:
        roots.append(frozen_dir)
    if app_dir:
        roots.append(app_dir)

    paths: list[str] = []
    seen: set[str] = set()
    for root in roots:
        for rel_dir in ("assets", ""):
            for name in names:
                path = os.path.join(root, rel_dir, name)
                norm = os.path.abspath(path)
                if norm not in seen:
                    seen.add(norm)
                    paths.append(norm)
    return paths


def load_tray_icon(app_dir: str | None = None, size: int = 64):
    if not TRAY_AVAILABLE:
        raise RuntimeError("Tray dependencies are not available")

    for path in _candidate_icon_paths(
        app_dir,
        ["cleannet_tray.png", "tray_icon.png", "icon_tray.png", "cleannet_app.png", "app_icon.png"],
    ):
        if not os.path.exists(path):
            continue
        try:
            image = Image.open(path).convert("RGBA")
            image.thumbnail((size, size), Image.Resampling.LANCZOS)
            canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
            x = (size - image.width) // 2
            y = (size - image.height) // 2
            canvas.alpha_composite(image, (x, y))
            return canvas
        except Exception:
            continue
    return None


def create_icon(color, app_dir: str | None = None):
    if not TRAY_AVAILABLE:
        raise RuntimeError("Tray dependencies are not available")

    asset_icon = load_tray_icon(app_dir)
    if asset_icon is not None:
        return asset_icon

    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx, cy, radius = size // 2, size // 2, 26
    pts = [
        (
            cx + radius * math.cos(math.radians(angle - 90)),
            cy + radius * math.sin(math.radians(angle - 90)),
        )
        for angle in range(0, 360, 60)
    ]
    draw.polygon(pts, outline=color, fill=None)
    draw.polygon(pts, outline=color)
    inner = [
        (
            cx + (radius - 2) * math.cos(math.radians(angle - 90)),
            cy + (radius - 2) * math.sin(math.radians(angle - 90)),
        )
        for angle in range(0, 360, 60)
    ]
    draw.polygon(inner, outline=color)
    draw.line([(cx, cy), (cx, cy - 14)], fill=color, width=3)
    draw.line([(cx, cy), (cx + 10, cy + 6)], fill=color, width=3)
    draw.ellipse([cx - 3, cy - 3, cx + 3, cy + 3], fill=color)
    return img


class TrayManager:
    def __init__(self, context: TrayRuntimeContext):
        self.ctx = context

    def signal_shutdown(self) -> None:
        loop = self.ctx.get_loop()
        event = self.ctx.get_shutdown_event()
        if loop and event:
            loop.call_soon_threadsafe(event.set)

    def update(self, icon) -> None:
        if not icon:
            return
        try:
            color = STATUS_COLORS.get(self.ctx.get_status(), (150, 150, 150))
            icon.icon = create_icon(color, self.ctx.asset_dir)
            icon.title = build_status_title(self.ctx.get_status(), self.ctx.get_ping_ms())
        except Exception:
            pass

    def open_dashboard(self, _icon=None, _item=None) -> None:
        webbrowser.open(f"http://{self.ctx.local_host}:{self.ctx.web_port}")

    def refresh_ips(self, _icon=None, _item=None) -> None:
        loop = self.ctx.get_loop()
        if loop:
            asyncio.run_coroutine_threadsafe(self.ctx.resolve_bypass_ips(), loop)

    def open_log(self, _icon=None, _item=None) -> None:
        if os.path.exists(self.ctx.log_file):
            os.startfile(self.ctx.log_file)

    def exit(self, icon=None, _item=None) -> None:
        self.ctx.logger.info("User exit")
        self.ctx.set_running(False)
        self.ctx.force_save()
        self.ctx.set_proxy_enabled(False)
        self.signal_shutdown()
        if icon:
            icon.stop()

    def _run_full_shutdown(self, icon) -> None:
        mb_yesno = 0x04
        mb_iconwarning = 0x30
        mb_topmost = 0x40000
        id_yes = 6

        title, message = build_full_shutdown_prompt(get_user_language())
        result = ctypes.windll.user32.MessageBoxW(
            0,
            message,
            title,
            mb_yesno | mb_iconwarning | mb_topmost,
        )
        if result != id_yes:
            return

        self.ctx.logger.info("Full shutdown initiated")
        self.ctx.set_running(False)
        self.ctx.force_save()
        self.ctx.set_proxy_enabled(False)
        self.signal_shutdown()

        bat_content = (
            "@echo off\r\n"
            "ipconfig /flushdns >nul 2>&1\r\n"
            "echo [OK] DNS cache flushed.\r\n"
            "timeout /t 2 /nobreak >nul\r\n"
        )
        bat_path = os.path.join(tempfile.gettempdir(), "dpi_bypass_shutdown.bat")
        try:
            with open(bat_path, "w", encoding="utf-8") as f:
                f.write(bat_content)
            ctypes.windll.shell32.ShellExecuteW(None, "runas", bat_path, None, None, 1)
        except Exception as e:
            self.ctx.logger.error(f"Full shutdown error: {e}")
        if icon:
            icon.stop()

    def full_shutdown(self, icon=None, _item=None) -> None:
        threading.Thread(target=self._run_full_shutdown, args=(icon,), daemon=True).start()

    def restart(self, icon=None, _item=None) -> None:
        self.ctx.set_running(False)
        self.signal_shutdown()
        if icon:
            icon.stop()
        self.ctx.release_instance_lock()
        subprocess.Popen([
            self.ctx.python_executable,
            "-c",
            (
                "import subprocess,time;"
                "time.sleep(2);"
                f"subprocess.Popen([{self.ctx.python_executable!r}, {self.ctx.app_file!r}])"
            ),
        ])

    def setup(self):
        if not TRAY_AVAILABLE:
            raise RuntimeError("Tray dependencies are not available")

        menu = pystray.Menu(
            pystray.MenuItem(f"CleanNet v{self.ctx.version}", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(lambda _t: f"Status: {STATUS_TEXT.get(self.ctx.get_status(), self.ctx.get_status())}", None, enabled=False),
            pystray.MenuItem(lambda _t: f"Ping: {self.ctx.get_ping_ms()}ms" if self.ctx.get_ping_ms() > 0 else "Ping: --", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Dashboard", self.open_dashboard),
            pystray.MenuItem("Refresh IPs", self.refresh_ips),
            pystray.MenuItem("Log File", self.open_log),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Restart", self.restart),
            pystray.MenuItem("Exit", self.exit),
            pystray.MenuItem("Full Shutdown (Reset Network)", self.full_shutdown),
        )
        return pystray.Icon(
            "cleannet",
            create_icon(STATUS_COLORS["running"], self.ctx.asset_dir),
            "CleanNet - Active",
            menu,
        )
