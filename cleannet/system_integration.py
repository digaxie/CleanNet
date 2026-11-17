"""Operating-system integration chosen for the running platform.

Everything platform-specific about the system proxy, autostart and UI language lives
in ``windows_integration`` (registry / WinINet) or ``linux_integration`` (GNOME, KDE
or an env file). Both expose the same functions; the rest of CleanNet imports them
from here and never needs to know which one is active.
"""

from __future__ import annotations

import sys

from .network_ready import wait_for_network_ready  # noqa: F401  (shared by both)

IS_WINDOWS = sys.platform == "win32"
PLATFORM_NAME = "windows" if IS_WINDOWS else "linux"

if IS_WINDOWS:
    from .windows_integration import (  # noqa: F401
        SessionEndWatcher,
        ensure_system_proxy_enabled,
        get_autostart,
        get_proxy_summary,
        get_user_language,
        recover_orphaned_proxy,
        set_autostart,
        set_system_proxy,
    )
else:
    from .linux_integration import (  # noqa: F401
        ensure_system_proxy_enabled,
        get_autostart,
        get_proxy_summary,
        get_user_language,
        recover_orphaned_proxy,
        set_autostart,
        set_system_proxy,
    )

    # Linux has no session-end broadcast to hook; the desktop session's own
    # shutdown runs our signal handlers, which restore the proxy.
    SessionEndWatcher = None
