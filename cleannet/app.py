"""Application lifecycle orchestration for CleanNet."""

from __future__ import annotations

import asyncio
import atexit
from dataclasses import dataclass
import os
import signal
import sys
import threading
import time
import webbrowser
from typing import Any, Awaitable, Callable

from .instance import SingleInstance


@dataclass
class CleanNetAppContext:
    logger: Any
    version: str
    get_site_names: Callable[[], list[str]]
    local_host: str
    local_port: int
    web_port: int
    proxy_engine: Any
    dashboard_server: Any
    background_tasks: Any
    training_manager: Any
    tray_available: bool
    tray_manager: Any
    set_proxy_enabled: Callable[[bool], Any]
    ensure_proxy_enabled: Callable[[], Any] | None
    force_save: Callable[[], None]
    save_stats: Callable[[], None]
    recover_proxy: Callable[[], None]
    instance_name: str = "CleanNetDPIBypass"
    instance_factory: Callable[[str], Any] = SingleInstance
    new_event_loop: Callable[[], Any] = asyncio.new_event_loop
    set_event_loop: Callable[[Any], None] = asyncio.set_event_loop
    start_server: Callable[..., Awaitable[Any]] = asyncio.start_server
    create_task: Callable[[Awaitable[Any]], Any] = asyncio.create_task
    event_factory: Callable[[], Any] = asyncio.Event
    thread_factory: Callable[..., Any] = threading.Thread
    time_func: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    exit_func: Callable[[int], None] = sys.exit
    register_atexit: Callable[[Callable[[], None]], Any] = atexit.register
    signal_func: Callable[[Any, Any], Any] = signal.signal
    is_onboarding_complete: Callable[[], bool] = lambda: True
    wait_for_network: Callable[[], Any] = lambda: True
    open_url: Callable[[str], Any] = webbrowser.open
    # Builds a watcher that restores the user's proxy on Windows logoff/restart/shutdown.
    # Receives (on_session_end_callback, logger) and returns an object with start()/stop().
    # Left as None in tests/non-Windows; when None the app simply runs without it.
    session_watcher_factory: Callable[..., Any] | None = None


class CleanNetApp:
    def __init__(self, context: CleanNetAppContext):
        self.ctx = context
        self.status = "stopped"
        self.running = False
        self.loop = None
        self.shutdown_event = None
        self.instance_lock = None
        self.port_ready = threading.Event()
        self.start_time = None
        self.proxy_owned = False
        self.session_watcher = None

    def enable_system_proxy(self) -> bool:
        if self.proxy_owned:
            return True
        self.ctx.recover_proxy()
        self.ctx.set_proxy_enabled(True)
        self.proxy_owned = True
        if self.ctx.ensure_proxy_enabled:
            self.ctx.ensure_proxy_enabled()
        if self.start_time is None:
            self.start_time = self.ctx.time_func()
        self.ctx.logger.info("System proxy enabled")
        return True

    def _enable_proxy_when_network_ready(self) -> None:
        """Wait for real connectivity, then take over the system proxy.

        Runs on a background thread so the tray/UI come up immediately. Without
        this gate, autostart at logon enables the proxy before the network is
        up, which blackholes all traffic until the user restarts the app.
        """
        try:
            self.ctx.wait_for_network()
        except Exception as exc:
            self.ctx.logger.debug(f"Network readiness check failed: {exc}")
        if self.running and not self.proxy_owned:
            self.enable_system_proxy()

    def set_running(self, value: bool) -> None:
        self.running = value

    def release_instance_lock(self) -> None:
        if self.instance_lock:
            self.instance_lock.release()
            self.instance_lock = None

    def signal_shutdown_event(self) -> None:
        if not self.shutdown_event:
            return
        try:
            if self.loop:
                self.loop.call_soon_threadsafe(self.shutdown_event.set)
            else:
                self.shutdown_event.set()
        except Exception:
            try:
                self.shutdown_event.set()
            except Exception:
                pass

    def wait_while_running(self) -> None:
        try:
            while self.running:
                self.ctx.sleep(1)
        except Exception:
            pass

    def install_exit_handlers(self) -> None:
        self.ctx.register_atexit(self.atexit_handler)
        self.ctx.signal_func(signal.SIGINT, self.cleanup_handler)
        self.ctx.signal_func(signal.SIGTERM, self.cleanup_handler)
        sigbreak = getattr(signal, "SIGBREAK", None)
        if sigbreak is not None:
            self.ctx.signal_func(sigbreak, self.cleanup_handler)

    def atexit_handler(self) -> None:
        self.ctx.force_save()
        self.ctx.save_stats()
        if self.proxy_owned:
            self.ctx.recover_proxy()
            self.proxy_owned = False
        self.release_instance_lock()

    def cleanup_handler(self, _signum=None, _frame=None) -> None:
        self.ctx.force_save()
        self.ctx.save_stats()
        if self.proxy_owned:
            self.ctx.set_proxy_enabled(False)
            self.proxy_owned = False
        self.release_instance_lock()
        self.ctx.exit_func(0)

    def on_session_end(self) -> None:
        """Restore the user's system proxy when Windows logs off / restarts / shuts down.

        Mirrors the Exit cleanup so a reboot never leaves the system proxy pointing at
        our (now-dead) local engine - which would otherwise break internet for every
        proxy-aware app until CleanNet is reopened. Unlike ``cleanup_handler`` this does
        NOT exit the process: the OS is already tearing us down, so we just put the
        user's original proxy back and persist state.
        """
        self.ctx.force_save()
        self.ctx.save_stats()
        if self.proxy_owned:
            self.ctx.set_proxy_enabled(False)
            self.proxy_owned = False
            self.ctx.logger.info("[SHUTDOWN] Session ending; restored original system proxy")

    def _start_session_watcher(self) -> None:
        if not self.ctx.session_watcher_factory:
            return
        try:
            self.session_watcher = self.ctx.session_watcher_factory(
                self.on_session_end, self.ctx.logger
            )
            self.session_watcher.start()
        except Exception as exc:
            self.session_watcher = None
            self.ctx.logger.warning(f"Session-end watcher unavailable: {exc}")

    def _stop_session_watcher(self) -> None:
        if not self.session_watcher:
            return
        try:
            self.session_watcher.stop()
        except Exception:
            pass
        self.session_watcher = None

    async def async_main(self) -> None:
        self.shutdown_event = self.ctx.event_factory()

        try:
            proxy = await self.ctx.start_server(
                self.ctx.proxy_engine.handle_proxy_client,
                self.ctx.local_host,
                self.ctx.local_port,
            )
        except OSError:
            self.ctx.logger.warning(f"Port {self.ctx.local_port} already in use")
            self.port_ready.set()
            return

        self.port_ready.set()
        self.running = True
        self.status = "running"
        self.ctx.logger.info(f"Proxy listening: {self.ctx.local_host}:{self.ctx.local_port}")

        web = None
        try:
            web = await self.ctx.start_server(
                self.ctx.dashboard_server.handle_http,
                self.ctx.local_host,
                self.ctx.web_port,
            )
            self.ctx.logger.info(f"Dashboard: http://{self.ctx.local_host}:{self.ctx.web_port}")
        except OSError:
            self.ctx.logger.warning(f"Dashboard port {self.ctx.web_port} busy")

        self.ctx.create_task(self.ctx.background_tasks.health_check_loop())
        self.ctx.create_task(self.ctx.background_tasks.proxy_ownership_loop())
        self.ctx.create_task(self.ctx.background_tasks.strategy_retest_loop())
        self.ctx.create_task(self.ctx.training_manager.self_training_loop())
        await self.shutdown_event.wait()

        proxy.close()
        await proxy.wait_closed()
        if web:
            web.close()
            await web.wait_closed()

    def run_async_loop(self, loop) -> None:
        self.ctx.set_event_loop(loop)
        try:
            loop.run_until_complete(self.async_main())
        except Exception:
            pass

    def start(self) -> None:
        self.ctx.logger.info("=" * 50)
        self.ctx.logger.info(f"CleanNet v{self.ctx.version} starting...")
        self.ctx.logger.info(f"Bypass sites: {', '.join(self.ctx.get_site_names())}")

        self.instance_lock = self.ctx.instance_factory(self.ctx.instance_name)
        if not self.instance_lock.acquire():
            self.ctx.logger.warning("Another CleanNet instance is already running")
            self.ctx.exit_func(0)

        self.port_ready.clear()
        self.loop = self.ctx.new_event_loop()
        async_thread = self.ctx.thread_factory(target=self.run_async_loop, args=(self.loop,), daemon=True)
        async_thread.start()

        if not self.port_ready.wait(timeout=5):
            self.ctx.logger.error("Proxy failed to start")
            self.release_instance_lock()
            self.ctx.exit_func(0)

        if not self.running:
            self.release_instance_lock()
            self.ctx.exit_func(0)

        self.start_time = self.ctx.time_func()
        self._start_session_watcher()
        if self.ctx.is_onboarding_complete():
            self.ctx.thread_factory(
                target=self._enable_proxy_when_network_ready,
                daemon=True,
            ).start()
        else:
            self.ctx.recover_proxy()
            self.ctx.logger.info("First-run setup pending; system proxy is not enabled yet")
            if os.environ.get("CLEANNET_NO_AUTO_OPEN") != "1":
                try:
                    self.ctx.open_url(f"http://{self.ctx.local_host}:{self.ctx.web_port}/?setup=1")
                except Exception as exc:
                    self.ctx.logger.warning(f"Could not open setup dashboard: {exc}")

        if self.ctx.tray_available:
            try:
                icon = self.ctx.tray_manager.setup()
                icon.run()
                if self.running:
                    self.ctx.logger.warning("Tray loop ended unexpectedly; continuing without tray")
                    self.wait_while_running()
            except Exception as exc:
                self.ctx.logger.error(f"Tray error: {exc}")
                self.wait_while_running()
        else:
            self.wait_while_running()

        self.running = False
        self.status = "stopped"
        self.signal_shutdown_event()
        self._stop_session_watcher()
        if self.proxy_owned:
            self.ctx.set_proxy_enabled(False)
            self.proxy_owned = False
        self.release_instance_lock()
        self.ctx.logger.info("DPI Bypass shut down")
