"""Live network-flow snapshots for the dashboard (netstat on Windows, ss on Linux)."""

from __future__ import annotations

import sys

if sys.platform == "win32":
    from .network_monitor_windows import NetworkFlow, NetworkMonitor, exception_entry_for_flow  # noqa: F401
else:
    from .network_monitor_linux import NetworkFlow, NetworkMonitor, exception_entry_for_flow  # noqa: F401
