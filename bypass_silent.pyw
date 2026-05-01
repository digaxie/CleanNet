"""
DPI Bypass Service v5 - asyncio Engine + Multi-Strategy
System Tray + Web Dashboard + DoH DNS + Health Check + Logging
Configurable site bypass system via config.json
"""

from cleannet.bootstrap import create_app


_service = create_app(__file__)


def start_proxy():
    _service.start()


if __name__ == "__main__":
    start_proxy()
