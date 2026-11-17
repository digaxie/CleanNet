"""System tray icon (pystray on Windows; PyQt6 with a pystray fallback on Linux)."""

from __future__ import annotations

import sys

if sys.platform == "win32":
    from .tray_windows import TRAY_AVAILABLE, TrayManager, TrayRuntimeContext  # noqa: F401
else:
    from .tray_linux import TRAY_AVAILABLE, TrayManager, TrayRuntimeContext  # noqa: F401
