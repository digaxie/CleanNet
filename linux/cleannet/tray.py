"""System tray and user-triggered lifecycle actions.

Uses PyQt6 QSystemTrayIcon for native KDE Plasma support.
Falls back to pystray if PyQt6 is not available.
"""

from __future__ import annotations

from dataclasses import dataclass
import asyncio
import math
import os
import shutil
import subprocess
import sys
import threading
import webbrowser
from typing import Any, Awaitable, Callable

from .os_integration import get_user_language


# ── Try PyQt6 first (native KDE support) ──
QT_AVAILABLE = False
try:
    from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu
    from PyQt6.QtGui import QIcon, QImage, QPixmap, QAction, QCursor
    from PyQt6.QtCore import QTimer, Qt
    QT_AVAILABLE = True
except ImportError:
    try:
        from PyQt5.QtWidgets import QApplication, QSystemTrayIcon, QMenu, QAction
        from PyQt5.QtGui import QIcon, QImage, QPixmap, QCursor
        from PyQt5.QtCore import QTimer, Qt
        QT_AVAILABLE = True
    except ImportError:
        pass

# ── Fallback to pystray ──
try:
    import pystray
    from PIL import Image, ImageDraw
    PYSTRAY_AVAILABLE = True
except ImportError:
    pystray = None
    Image = None
    ImageDraw = None
    PYSTRAY_AVAILABLE = False

TRAY_AVAILABLE = QT_AVAILABLE or PYSTRAY_AVAILABLE


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
            "2. Linux proxy ayarlari sifirlanacak\n"
            "3. DNS onbellegi temizlenecek (resolvectl flush-caches)\n\n"
            "Diger uygulamalariniz etkilenmeyecektir.\n\n"
            "Devam etmek istiyor musunuz?",
        )
    if lang == "de":
        return (
            "CleanNet - Vollstaendiges Herunterfahren",
            "Folgende Aktionen werden ausgefuehrt:\n\n"
            "1. DPI-Bypass-Proxy wird gestoppt\n"
            "2. Linux-Proxy-Einstellungen werden zurueckgesetzt\n"
            "3. DNS-Cache wird geleert (resolvectl flush-caches)\n\n"
            "Andere Anwendungen werden nicht beeintraechtigt.\n\n"
            "Moechten Sie fortfahren?",
        )
    return (
        "CleanNet - Full Shutdown",
        "The following actions will be performed:\n\n"
        "1. DPI Bypass proxy will be stopped\n"
        "2. Linux proxy settings will be cleared\n"
        "3. DNS cache will be flushed (resolvectl flush-caches)\n\n"
        "Other applications will not be affected.\n\n"
        "Do you want to continue?",
    )


def _find_icon_file(app_dir: str | None) -> str | None:
    """Find a PNG icon file from the assets directory."""
    if not app_dir:
        return None
    names = ["cleannet_tray.png", "tray_icon.png", "icon_tray.png",
             "cleannet_app.png", "app_icon.png"]
    for rel_dir in ("assets", ""):
        for name in names:
            path = os.path.join(app_dir, rel_dir, name)
            if os.path.exists(path):
                return path
    return None


# ═══════════════════════════════════════════════════════════════
# Qt-based tray (native KDE Plasma support)
# ═══════════════════════════════════════════════════════════════

class _QtTrayIcon:
    """A Qt-based system tray icon wrapper that mimics pystray's run()/stop() interface."""

    def __init__(self, manager: "TrayManager"):
        self.manager = manager
        self._app: QApplication | None = None
        self._tray: QSystemTrayIcon | None = None
        self._timer: QTimer | None = None
        self._stopped = False

    def run(self):
        """Blocking call that runs the Qt event loop (like pystray's icon.run())."""
        self._app = QApplication.instance() or QApplication(sys.argv)
        ctx = self.manager.ctx

        # Create tray icon
        self._tray = QSystemTrayIcon()

        # Set icon from file
        icon_path = _find_icon_file(ctx.asset_dir)
        if icon_path:
            pixmap = QPixmap(icon_path)
            if not pixmap.isNull():
                try:
                    aspect = Qt.AspectRatioMode.KeepAspectRatio
                    smooth = Qt.TransformationMode.SmoothTransformation
                except AttributeError:
                    aspect = Qt.KeepAspectRatio
                    smooth = Qt.SmoothTransformation
                scaled_pixmap = pixmap.scaled(22, 22, aspect, smooth)
                self._tray.setIcon(QIcon(scaled_pixmap))
            else:
                self._tray.setIcon(QIcon(icon_path))
        else:
            # Fallback: create a simple colored icon
            pixmap = QPixmap(64, 64)
            pixmap.fill()
            self._tray.setIcon(QIcon(pixmap))

        self._tray.setToolTip(f"CleanNet v{ctx.version} - Active")

        # Build context menu
        self._menu = QMenu()
        menu = self._menu

        header = menu.addAction(f"CleanNet v{ctx.version}")
        header.setEnabled(False)
        menu.addSeparator()

        self._status_action = menu.addAction("Status: Active")
        self._status_action.setEnabled(False)
        self._ping_action = menu.addAction("Ping: --")
        self._ping_action.setEnabled(False)
        menu.addSeparator()

        dashboard_action = menu.addAction("Dashboard")
        dashboard_action.triggered.connect(self.manager.open_dashboard)

        refresh_action = menu.addAction("Refresh IPs")
        refresh_action.triggered.connect(self.manager.refresh_ips)

        log_action = menu.addAction("Log File")
        log_action.triggered.connect(self.manager.open_log)

        menu.addSeparator()

        restart_action = menu.addAction("Restart")
        restart_action.triggered.connect(lambda: self.manager.restart(self))

        exit_action = menu.addAction("Exit")
        exit_action.triggered.connect(lambda: self.manager.exit(self))

        shutdown_action = menu.addAction("Full Shutdown (Reset Network)")
        shutdown_action.triggered.connect(lambda: self.manager.full_shutdown(self))

        self._tray.setContextMenu(menu)

        # Double-click opens dashboard
        self._tray.activated.connect(self._on_activated)

        # Periodic status update
        self._timer = QTimer()
        self._timer.timeout.connect(self._update_status)
        self._timer.start(2000)

        self._tray.show()

        ctx.logger.info("Qt system tray icon started (KDE native)")
        self._app.exec()

    def _on_activated(self, reason):
        """Handle tray icon activation (click)."""
        # QSystemTrayIcon.ActivationReason.Trigger = single click
        # QSystemTrayIcon.ActivationReason.DoubleClick = double click
        # QSystemTrayIcon.ActivationReason.Context = right click (request context menu)
        try:
            trigger = QSystemTrayIcon.ActivationReason.Trigger
            double = QSystemTrayIcon.ActivationReason.DoubleClick
            context = QSystemTrayIcon.ActivationReason.Context
        except AttributeError:
            trigger = QSystemTrayIcon.Trigger
            double = QSystemTrayIcon.DoubleClick
            context = QSystemTrayIcon.Context

        if reason in (trigger, double):
            self.manager.open_dashboard()
        elif reason == context:
            if hasattr(self, "_menu") and self._menu:
                self._menu.popup(QCursor.pos())

    def _update_status(self):
        """Periodically update status text and tooltip."""
        ctx = self.manager.ctx
        try:
            status = ctx.get_status()
            ping = ctx.get_ping_ms()
            self._status_action.setText(f"Status: {STATUS_TEXT.get(status, status)}")
            self._ping_action.setText(f"Ping: {ping}ms" if ping > 0 else "Ping: --")
            self._tray.setToolTip(build_status_title(status, ping))
        except Exception:
            pass

    def stop(self):
        """Stop the Qt event loop."""
        if self._stopped:
            return
        self._stopped = True
        try:
            if self._timer:
                self._timer.stop()
            if self._tray:
                self._tray.hide()
            if self._app:
                self._app.quit()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# pystray fallback (for non-KDE environments)
# ═══════════════════════════════════════════════════════════════

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
    if not PYSTRAY_AVAILABLE:
        return None

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
    if not PYSTRAY_AVAILABLE:
        return None

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


# ═══════════════════════════════════════════════════════════════
# TrayManager (main interface used by app.py)
# ═══════════════════════════════════════════════════════════════

class TrayManager:
    def __init__(self, context: TrayRuntimeContext):
        self.ctx = context

    def signal_shutdown(self) -> None:
        loop = self.ctx.get_loop()
        event = self.ctx.get_shutdown_event()
        if loop and event:
            loop.call_soon_threadsafe(event.set)

    def update(self, icon) -> None:
        # For Qt tray, updates are handled by the internal QTimer
        if not icon or isinstance(icon, _QtTrayIcon):
            return
        # pystray fallback update
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
        if os.path.exists(self.ctx.log_file) and shutil.which("xdg-open"):
            subprocess.Popen(["xdg-open", self.ctx.log_file])

    def exit(self, icon=None, _item=None) -> None:
        self.ctx.logger.info("User exit")
        self.ctx.set_running(False)
        self.ctx.force_save()
        self.ctx.set_proxy_enabled(False)
        self.signal_shutdown()
        if icon:
            icon.stop()

    def _run_full_shutdown(self, icon) -> None:
        title, message = build_full_shutdown_prompt(get_user_language())

        # Try kdialog first (KDE native), then zenity
        confirmed = False
        try:
            res = subprocess.run(["kdialog", "--title", title, "--yesno", message], capture_output=True)
            confirmed = (res.returncode == 0)
        except FileNotFoundError:
            try:
                res = subprocess.run(["zenity", "--question", "--title", title, "--text", message], capture_output=True)
                confirmed = (res.returncode == 0)
            except FileNotFoundError:
                self.ctx.logger.warning("No kdialog or zenity found; full shutdown confirmation was skipped")
                confirmed = True

        if not confirmed:
            return

        self.ctx.logger.info("Full shutdown initiated on Linux")
        self.ctx.set_running(False)
        self.ctx.force_save()
        self.ctx.set_proxy_enabled(False)
        self.signal_shutdown()

        if not shutil.which("resolvectl"):
            self.ctx.logger.warning("DNS cache flush skipped: resolvectl was not found")
        else:
            subprocess.run(["resolvectl", "flush-caches"], capture_output=True)
            self.ctx.logger.info("[OK] DNS cache flushed via resolvectl.")

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
        source_dir = os.path.dirname(os.path.abspath(self.ctx.app_file))
        if os.path.basename(source_dir) == "cleannet":
            source_dir = os.path.dirname(source_dir)
        subprocess.Popen([
            self.ctx.python_executable,
            "-c",
            (
                "import subprocess,time;"
                "time.sleep(2);"
                f"subprocess.Popen([{self.ctx.python_executable!r}, '-m', 'cleannet'], cwd={source_dir!r})"
            ),
        ])

    def setup(self):
        if not TRAY_AVAILABLE:
            raise RuntimeError("Tray dependencies are not available")

        # ── Prefer Qt-based tray on KDE Plasma ──
        if QT_AVAILABLE:
            self.ctx.logger.info("Using Qt system tray (native KDE support)")
            return _QtTrayIcon(self)

        # ── Fallback: pystray ──
        if not PYSTRAY_AVAILABLE:
            raise RuntimeError("No tray backend available")

        self.ctx.logger.info("Using pystray fallback tray")
        menu = pystray.Menu(
            pystray.MenuItem(f"CleanNet v{self.ctx.version}", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(lambda _t: f"Status: {STATUS_TEXT.get(self.ctx.get_status(), self.ctx.get_status())}", None, enabled=False),
            pystray.MenuItem(lambda _t: f"Ping: {self.ctx.get_ping_ms()}ms" if self.ctx.get_ping_ms() > 0 else "Ping: --", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Dashboard", self.open_dashboard, default=True),
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
