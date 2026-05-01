"""Background maintenance tasks for CleanNet."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import random
import socket
import ssl
import time
from typing import Any, Awaitable, Callable


Reader = Any
Writer = Any


def default_site_tester(local_host: str, local_port: int, test_domain: str) -> None:
    sock = socket.create_connection((local_host, local_port), timeout=10)
    try:
        sock.sendall(f"CONNECT {test_domain}:443 HTTP/1.1\r\nHost: {test_domain}:443\r\n\r\n".encode())
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Proxy closed connection")
            response += chunk
        if b"200" not in response.split(b"\r\n")[0]:
            raise ConnectionError("Proxy rejected CONNECT")
        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(sock, server_hostname=test_domain)
        tls_sock.do_handshake()
        tls_sock.close()
    except Exception:
        sock.close()
        raise


@dataclass
class BackgroundTaskContext:
    logger: Any
    get_config: Callable[[], dict[str, Any]]
    get_running: Callable[[], bool]
    set_ping_ms: Callable[[int], None]
    ping_history: Any
    test_results: dict[str, Any]
    get_bypass_ips: Callable[[], list[str]]
    get_bypass_domains: Callable[[], list[str]]
    local_host: str
    local_port: int
    health_check_interval: int
    ip_update_interval: int
    ping_target_host: str
    strategy_retest_interval: int
    resolve_bypass_ips: Callable[[], Awaitable[bool]]
    notify: Callable[[str, str], None]
    strategy_cache: Any
    save_stats: Callable[[], None]
    ensure_proxy_enabled: Callable[[], Any] | None
    parse_iso: Callable[[str | None], float | None]
    now_iso: Callable[[], str]
    open_connection: Callable[..., Awaitable[tuple[Reader, Writer]]] = asyncio.open_connection
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    perf_counter: Callable[[], float] = time.perf_counter
    time_func: Callable[[], float] = time.time
    site_tester: Callable[[str, int, str], None] = default_site_tester
    create_task: Callable[[Awaitable[Any]], Any] = asyncio.create_task
    proxy_watch_interval: int = 5


class BackgroundTaskManager:
    def __init__(self, context: BackgroundTaskContext):
        self.ctx = context

    async def measure_ping(self) -> int:
        writer = None
        try:
            ip = self.ctx.ping_target_host.strip()
            if not ip:
                bypass_ips = self.ctx.get_bypass_ips()
                ip = random.choice(bypass_ips) if bypass_ips else "1.1.1.1"
            start = self.ctx.perf_counter()
            _, writer = await asyncio.wait_for(self.ctx.open_connection(ip, 443), timeout=5)
            elapsed = (self.ctx.perf_counter() - start) * 1000
            ping_ms = round(elapsed)
            self.ctx.set_ping_ms(ping_ms)
            self.ctx.ping_history.append(ping_ms)
            return ping_ms
        except Exception:
            self.ctx.set_ping_ms(-1)
            return -1
        finally:
            try:
                if writer:
                    writer.close()
            except Exception:
                pass

    async def test_site_connection(self, site_name: str) -> dict[str, Any]:
        site_cfg = self.ctx.get_config().get("sites", {}).get(site_name)
        if not site_cfg:
            self.ctx.test_results[site_name] = {
                "status": "fail",
                "ms": 0,
                "time": self.ctx.now_iso(),
                "error": "Site not found",
            }
            return self.ctx.test_results[site_name]

        domains = site_cfg.get("dns_resolve", site_cfg.get("domains", []))
        test_domain = domains[0] if domains else f"{site_name}.com"
        self.ctx.test_results[site_name] = {"status": "testing", "ms": 0, "time": self.ctx.now_iso()}

        start = self.ctx.perf_counter()
        try:
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    self.ctx.site_tester,
                    self.ctx.local_host,
                    self.ctx.local_port,
                    test_domain,
                ),
                timeout=20,
            )
            elapsed = round((self.ctx.perf_counter() - start) * 1000)
            result = {"status": "ok", "ms": elapsed, "time": self.ctx.now_iso()}
        except Exception as e:
            elapsed = round((self.ctx.perf_counter() - start) * 1000)
            result = {
                "status": "fail",
                "ms": elapsed,
                "time": self.ctx.now_iso(),
                "error": str(e)[:50],
            }

        self.ctx.test_results[site_name] = result
        self.ctx.logger.info(f"[TEST] {site_name}: {result['status']} ({result.get('ms', 0)}ms)")

        async def clear_test() -> None:
            await self.ctx.sleep(8)
            self.ctx.test_results.pop(site_name, None)

        self.ctx.create_task(clear_test())
        return result

    async def health_check_loop(self) -> None:
        await self.ctx.sleep(5)
        await self.ctx.resolve_bypass_ips()
        await self.measure_ping()
        if self.ctx.ensure_proxy_enabled:
            self.ctx.ensure_proxy_enabled()
        self.ctx.notify(
            "DPI Bypass",
            f"Active - {len(self.ctx.get_bypass_ips())} IPs, {len(self.ctx.get_bypass_domains())} domains",
        )

        last_ip_update = self.ctx.time_func()
        while self.ctx.get_running():
            await self.ctx.sleep(self.ctx.health_check_interval)
            if not self.ctx.get_running():
                break
            await self.measure_ping()
            self.ctx.strategy_cache._save_if_needed()
            self.ctx.save_stats()
            if self.ctx.ensure_proxy_enabled:
                self.ctx.ensure_proxy_enabled()

            if self.ctx.time_func() - last_ip_update > self.ctx.ip_update_interval:
                await self.ctx.resolve_bypass_ips()
                last_ip_update = self.ctx.time_func()

    async def proxy_ownership_loop(self) -> None:
        await self.ctx.sleep(2)
        while self.ctx.get_running():
            if self.ctx.ensure_proxy_enabled:
                self.ctx.ensure_proxy_enabled()
            await self.ctx.sleep(self.ctx.proxy_watch_interval)

    async def strategy_retest_loop(self) -> None:
        while self.ctx.get_running():
            await self.ctx.sleep(self.ctx.strategy_retest_interval)
            if not self.ctx.get_running():
                break
            now = self.ctx.time_func()
            for _site_name, site_data in self.ctx.strategy_cache.iter_site_data():
                if site_data.get("best_strategy"):
                    continue
                expired = []
                for strategy, fail_info in site_data.get("failures", {}).items():
                    last_fail = self.ctx.parse_iso(fail_info.get("last_fail", ""))
                    if last_fail and (now - last_fail) > self.ctx.strategy_retest_interval:
                        expired.append(strategy)
                for strategy in expired:
                    del site_data["failures"][strategy]
            self.ctx.strategy_cache._save_if_needed()
