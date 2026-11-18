"""
DPI Bypass Service v5 - asyncio Engine + Multi-Strategy
System Tray + Web Dashboard + DoH DNS + Health Check + Logging
Configurable site bypass system via config.json
"""

import sys

from cleannet.uninstall_cleanup import CLEANUP_FLAG, RESTORE_PROXY_FLAG, run_cleanup

# Run by the installer and uninstaller: undo CleanNet's Windows settings, start nothing.
if CLEANUP_FLAG in sys.argv[1:]:
    sys.exit(run_cleanup(__file__, remove_autostart=True))
if RESTORE_PROXY_FLAG in sys.argv[1:]:
    sys.exit(run_cleanup(__file__, remove_autostart=False))

from cleannet.bootstrap import create_app


_service = create_app(__file__)


def start_proxy():
    _service.start()


if __name__ == "__main__":
    start_proxy()
