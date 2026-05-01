"""Async proxy engine for CleanNet."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
import random
import time
from typing import Any, Awaitable, Callable

from .proxy import (
    is_valid_tls_reply,
    looks_like_tls_client_hello,
    parse_connect_target,
    parse_http_forward_target,
    rewrite_http_forward_request,
)


Reader = Any
Writer = Any


@dataclass
class ProxyRuntimeContext:
    logger: Any
    stats: dict[str, Any]
    site_stats: dict[str, Any]
    strategy_history: Any
    domain_ips: dict[str, list[str]]
    blocked_domains: dict[str, float]
    site_semaphores: dict[str, asyncio.Semaphore]
    connection_tracker: Any
    strategy_cache: Any
    ai_engine: Any
    strategy_funcs: dict[str, Callable[[Writer, bytes], Awaitable[None]]]
    direct_strategy: Callable[[Writer, bytes], Awaitable[None]]
    get_privacy_settings: Callable[[], dict[str, bool]]
    resolve_domain_privately: Callable[[str], Awaitable[list[str]]]
    resolve_domain_doh: Callable[[str], list[str]]
    is_ip_literal: Callable[[str], bool]
    hash_host: Callable[[str], str]
    find_site_for_host: Callable[[str], str | None]
    is_main_domain: Callable[[str, str], bool]
    get_bypass_ip: Callable[[str], str | None]
    get_domain_ips: Callable[[str], list[str]]
    get_site_ips: Callable[[str], list[str]]
    record_privacy_event: Callable[..., None]
    doh_bootstrap_map: dict[str, str]
    global_sni_strategy: str
    strategy_success_timeout: float
    blocked_domain_ttl: int
    site_max_concurrent: int
    open_connection: Callable[..., Awaitable[tuple[Reader, Writer]]] = asyncio.open_connection


def close_writer(writer: Writer | None) -> None:
    try:
        if writer:
            writer.close()
    except Exception:
        pass


class ProxyEngine:
    def __init__(self, context: ProxyRuntimeContext):
        self.ctx = context

    async def tunnel_plain(self, client_reader, client_writer, server_reader, server_writer):
        async def client_to_server():
            try:
                while True:
                    data = await client_reader.read(8192)
                    if not data:
                        break
                    server_writer.write(data)
                    await server_writer.drain()
            except Exception:
                pass

        async def server_to_client():
            try:
                while True:
                    data = await server_reader.read(8192)
                    if not data:
                        break
                    client_writer.write(data)
                    await client_writer.drain()
            except Exception:
                pass

        tasks = [asyncio.create_task(client_to_server()), asyncio.create_task(server_to_client())]
        _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()

    async def forward_with_sni_shield(
        self,
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        first_chunk: bytes,
        target_host: str,
        target_port: int,
    ) -> dict[str, str]:
        active_reader = server_reader
        active_writer = server_writer
        try:
            if not looks_like_tls_client_hello(first_chunk):
                self.ctx.logger.info(f"[SNI-SHIELD] {target_host}:{target_port} skipped (not TLS ClientHello)")
                await self.ctx.direct_strategy(active_writer, first_chunk)
                await self.tunnel_plain(client_reader, client_writer, active_reader, active_writer)
                return {"status": "not_tls", "detail": "non-TLS CONNECT payload"}

            strategy_name = self.ctx.global_sni_strategy
            self.ctx.logger.info(f"[SNI-SHIELD] {target_host}:{target_port} using {strategy_name}")
            try:
                await self.ctx.strategy_funcs[strategy_name](active_writer, first_chunk)
                server_reply = await asyncio.wait_for(
                    active_reader.read(8192),
                    timeout=self.ctx.strategy_success_timeout,
                )
                if not is_valid_tls_reply(server_reply):
                    raise ConnectionError("invalid TLS reply")
                client_writer.write(server_reply)
                await client_writer.drain()
                self.ctx.logger.info(f"[SNI-SHIELD] {target_host}:{target_port} confirmed via {strategy_name}")
                await self.tunnel_plain(client_reader, client_writer, active_reader, active_writer)
                return {"status": "hidden", "detail": f"{strategy_name} confirmed"}
            except Exception as e:
                self.ctx.logger.warning(f"[SNI-SHIELD] {strategy_name} failed for {self.ctx.hash_host(target_host)}: {e}")
                close_writer(active_writer)
                active_reader, active_writer = await self.try_connect(target_host, target_port)
                if not active_writer:
                    return {"status": "failed", "detail": "fallback connect failed"}
                await self.ctx.direct_strategy(active_writer, first_chunk)
                try:
                    server_reply = await asyncio.wait_for(
                        active_reader.read(8192),
                        timeout=self.ctx.strategy_success_timeout,
                    )
                    if is_valid_tls_reply(server_reply):
                        client_writer.write(server_reply)
                        await client_writer.drain()
                        self.ctx.logger.info(f"[SNI-SHIELD] {target_host}:{target_port} fell back to direct")
                        await self.tunnel_plain(client_reader, client_writer, active_reader, active_writer)
                        return {"status": "fallback", "detail": "direct fallback"}
                except Exception:
                    pass
                return {"status": "failed", "detail": "direct fallback failed"}
        finally:
            close_writer(active_writer)

    async def try_connect(
        self,
        host: str,
        port: int,
        alt_ips: list[str] | None = None,
        timeout: float = 10,
        use_privacy_dns: bool | None = None,
        privacy_context: dict[str, Any] | None = None,
    ):
        if use_privacy_dns is None:
            use_privacy_dns = self.ctx.get_privacy_settings()["hide_dns"]

        candidates: list[str] = []
        seen: set[str] = set()
        dns_source = None

        def add_candidate(value: str | None):
            if not value or value in seen:
                return
            seen.add(value)
            candidates.append(value)

        if host:
            if self.ctx.is_ip_literal(host):
                add_candidate(host)
                dns_source = "ip"
                if privacy_context is not None:
                    privacy_context["dns_status"] = "hidden"
                    privacy_context["dns_detail"] = f"IP {host}"
            elif use_privacy_dns:
                resolved_ips = await self.ctx.resolve_domain_privately(host)
                for resolved_ip in resolved_ips:
                    add_candidate(resolved_ip)
                if privacy_context is not None:
                    if resolved_ips:
                        privacy_context["dns_status"] = "hidden"
                        dns_source = "bootstrap" if host in self.ctx.doh_bootstrap_map else "doh"
                        mode = "bootstrap" if dns_source == "bootstrap" else "DoH"
                        privacy_context["dns_detail"] = f"{mode} -> {resolved_ips[0]}"
                    else:
                        privacy_context["dns_status"] = "blocked"
                        privacy_context["dns_detail"] = "DoH failed"
            else:
                add_candidate(host)
                dns_source = "direct"
                if privacy_context is not None:
                    privacy_context["dns_status"] = "direct"
                    privacy_context["dns_detail"] = "system DNS / hostname connect"

        if alt_ips:
            for alt_ip in alt_ips:
                add_candidate(alt_ip)

        if use_privacy_dns and host and not self.ctx.is_ip_literal(host) and not candidates:
            self.ctx.logger.warning(
                f"[DNS-PRIVACY] Blocked connection to {self.ctx.hash_host(host)}:{port} because no DoH result was available"
            )
            return None, None

        for idx, candidate in enumerate(candidates):
            try:
                per_attempt_timeout = timeout if idx == 0 else min(timeout, 8)
                reader, writer = await asyncio.wait_for(
                    self.ctx.open_connection(candidate, port),
                    timeout=per_attempt_timeout,
                )
                if privacy_context is not None:
                    if dns_source == "bootstrap":
                        privacy_context["dns_detail"] = f"bootstrap -> {candidate}"
                    elif dns_source == "doh":
                        privacy_context["dns_detail"] = f"DoH -> {candidate}"
                    elif dns_source == "ip":
                        privacy_context["dns_detail"] = f"IP {candidate}"
                    privacy_context["connected_target"] = candidate
                return reader, writer
            except Exception as e:
                self.ctx.logger.debug(f"Connection failed {candidate}:{port} -> {e}")
        return None, None

    async def handle_http_forward(self, initial_data, client_reader, client_writer):
        server_writer = None
        conn_id = None
        try:
            target = parse_http_forward_target(initial_data)
            if not target:
                return

            conn_id = self.ctx.connection_tracker.track(
                target.host,
                target.port,
                self.ctx.find_site_for_host(target.host),
                "http",
            )
            self.ctx.logger.info(f"[HTTP-FORWARD] {target.method} {target.host}:{target.port}{target.path[:60]}")

            server_reader, server_writer = await self.try_connect(target.host, target.port, timeout=15)
            if not server_writer:
                return

            rewritten = rewrite_http_forward_request(initial_data, target)
            if rewritten is None:
                return

            server_writer.write(rewritten)
            await server_writer.drain()
            await self.tunnel_plain(client_reader, client_writer, server_reader, server_writer)
        except Exception as e:
            self.ctx.logger.debug(f"[HTTP-FORWARD] Error: {e}")
        finally:
            self.ctx.connection_tracker.release(conn_id)
            close_writer(server_writer)

    async def handle_proxy_client(self, reader, writer):
        server_writer = None
        sem_acquired = False
        sem_site = None
        conn_id = None
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=30)
            if not data:
                return

            first_line = data.split(b"\n")[0]
            if b"CONNECT" not in first_line:
                await self.handle_http_forward(data, reader, writer)
                return

            target = parse_connect_target(first_line)
            if not target:
                return
            target_host, target_port = target

            site_name = self.ctx.find_site_for_host(target_host)
            should_bypass = site_name is not None
            target_lower = target_host.lower()
            conn_id = self.ctx.connection_tracker.track(
                target_host,
                target_port,
                site_name,
                "bypass" if should_bypass else "direct",
            )

            if should_bypass and target_lower in self.ctx.blocked_domains:
                if (time.time() - self.ctx.blocked_domains[target_lower]) < self.ctx.blocked_domain_ttl:
                    self.ctx.logger.debug(f"[FAST-FAIL] {target_host} blocked (cache)")
                    return
                del self.ctx.blocked_domains[target_lower]

            bypass_ip = self.ctx.get_bypass_ip(target_host) if should_bypass else None

            if should_bypass and bypass_ip == target_lower:
                loop = asyncio.get_event_loop()
                try:
                    ips = await loop.run_in_executor(None, self.ctx.resolve_domain_doh, target_lower)
                    if ips:
                        self.ctx.domain_ips[target_lower] = ips
                        bypass_ip = random.choice(ips)
                except Exception:
                    pass

            connect_host = bypass_ip if bypass_ip else target_host
            self.ctx.stats["connections"] += 1

            if not should_bypass:
                privacy = self.ctx.get_privacy_settings()
                self.ctx.logger.info(f"[PASSTHROUGH{'-SHIELD' if privacy['hide_sni'] else ''}] {target_host}:{target_port}")
                privacy_dns: dict[str, Any] = {}
                server_reader, server_writer = await self.try_connect(connect_host, target_port, privacy_context=privacy_dns)
                if not server_writer:
                    self.ctx.record_privacy_event(
                        target_host,
                        dns_status=privacy_dns.get("dns_status", "blocked"),
                        dns_detail=privacy_dns.get("dns_detail", "connect failed"),
                        sni_status="failed",
                        sni_detail="upstream connect failed",
                    )
                    return
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                if privacy["hide_sni"]:
                    try:
                        first_chunk = await asyncio.wait_for(reader.read(8192), timeout=10)
                    except asyncio.TimeoutError:
                        return
                    if not first_chunk:
                        return
                    shield_result = await self.forward_with_sni_shield(
                        reader,
                        writer,
                        server_reader,
                        server_writer,
                        first_chunk,
                        target_host,
                        target_port,
                    )
                    self.ctx.record_privacy_event(
                        target_host,
                        dns_status=privacy_dns.get("dns_status", "unknown"),
                        dns_detail=privacy_dns.get("dns_detail", ""),
                        sni_status=shield_result.get("status", "unknown"),
                        sni_detail=shield_result.get("detail", ""),
                    )
                else:
                    self.ctx.record_privacy_event(
                        target_host,
                        dns_status=privacy_dns.get("dns_status", "direct"),
                        dns_detail=privacy_dns.get("dns_detail", ""),
                        sni_status="direct",
                        sni_detail="shield off",
                    )
                    await self.tunnel_plain(reader, writer, server_reader, server_writer)
                return

            is_main = self.ctx.is_main_domain(target_host, site_name)
            if site_name not in self.ctx.site_stats:
                self.ctx.site_stats[site_name] = {"connections": 0, "successes": 0, "failures": 0, "total_ms": 0}
            self.ctx.site_stats[site_name]["connections"] += 1
            self.ctx.logger.info(f"[BYPASS] {target_host} -> {connect_host} ({'MAIN' if is_main else 'CDN'})")
            privacy_dns_status = "hidden" if self.ctx.is_ip_literal(connect_host) else "direct"
            privacy_dns_detail = f"IP {connect_host}" if self.ctx.is_ip_literal(connect_host) else "hostname connect"

            if site_name not in self.ctx.site_semaphores:
                self.ctx.site_semaphores[site_name] = asyncio.Semaphore(self.ctx.site_max_concurrent)
            sem_site = site_name
            try:
                await asyncio.wait_for(self.ctx.site_semaphores[site_name].acquire(), timeout=30)
                sem_acquired = True
            except asyncio.TimeoutError:
                self.ctx.logger.debug(f"[THROTTLE] {target_host} too many concurrent, dropping")
                return

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            try:
                first_chunk = await asyncio.wait_for(reader.read(8192), timeout=10)
            except asyncio.TimeoutError:
                return
            if not first_chunk:
                return

            strategies = self.ctx.strategy_cache.get_strategy_order(site_name, is_main=is_main)
            site_data = self.ctx.strategy_cache._get_site_data(site_name)
            has_best = site_data.get("best_strategy") and site_data["best_strategy"] != "direct"
            if not is_main:
                if has_best:
                    strategies = [s for s in strategies if s != "direct"][:3]
                elif "direct" not in strategies:
                    strategies = ["direct"] + strategies

            domain_ips = self.ctx.get_domain_ips(target_host)
            pool_1 = domain_ips if domain_ips else [connect_host]
            ip_pools_to_try = [pool_1]

            site_ips = self.ctx.get_site_ips(target_host)
            if site_ips:
                fallback = [ip for ip in site_ips if ip not in pool_1]
                if fallback:
                    ip_pools_to_try.append(fallback)

            max_ips_per_pool = 2 if not is_main else len(pool_1)
            success = False
            all_conn_failed = True

            for ip_pool in ip_pools_to_try:
                random.shuffle(ip_pool)
                ips_tried = 0
                for try_ip in ip_pool:
                    if ips_tried >= max_ips_per_pool:
                        break
                    ips_tried += 1
                    remaining_ips = [ip for ip in ip_pool if ip != try_ip]
                    for strat_name in strategies:
                        self.ctx.stats["strategy_tries"] += 1
                        server_reader, server_writer = await self.try_connect(try_ip, target_port, remaining_ips)
                        if not server_writer:
                            break

                        start_t = time.perf_counter()
                        try:
                            await self.ctx.strategy_funcs[strat_name](server_writer, first_chunk)
                        except Exception as e:
                            self.ctx.logger.info(f"[STRATEGY] {site_name}: {strat_name} failed ({e}) IP:{try_ip}")
                            close_writer(server_writer)
                            self.ctx.strategy_cache.record_failure(site_name, strat_name)
                            self.ctx.ai_engine.record(site_name, strat_name, False, 0)
                            self.ctx.strategy_history.append({
                                "time": datetime.now().strftime("%H:%M:%S"),
                                "site": site_name,
                                "strategy": strat_name,
                                "ms": 0,
                                "success": False,
                            })
                            self.ctx.stats["strategy_fallbacks"] += 1
                            continue

                        try:
                            server_reply = await asyncio.wait_for(
                                server_reader.read(8192),
                                timeout=self.ctx.strategy_success_timeout,
                            )
                            if not server_reply:
                                raise ConnectionError("Empty response")
                            if len(server_reply) >= 2 and server_reply[0] == 0x15:
                                raise ConnectionError("TLS Alert")
                            if len(server_reply) >= 3 and server_reply[0] != 0x16:
                                raise ConnectionError("Invalid TLS response")
                        except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                            self.ctx.logger.info(f"[STRATEGY] {site_name}: {strat_name} failed ({e}) IP:{try_ip}")
                            close_writer(server_writer)
                            self.ctx.strategy_cache.record_failure(site_name, strat_name)
                            self.ctx.ai_engine.record(site_name, strat_name, False, 0)
                            self.ctx.strategy_history.append({
                                "time": datetime.now().strftime("%H:%M:%S"),
                                "site": site_name,
                                "strategy": strat_name,
                                "ms": 0,
                                "success": False,
                            })
                            self.ctx.stats["strategy_fallbacks"] += 1
                            continue

                        all_conn_failed = False
                        elapsed_ms = (time.perf_counter() - start_t) * 1000
                        self.ctx.strategy_cache.record_success(site_name, strat_name, elapsed_ms)
                        self.ctx.ai_engine.record(site_name, strat_name, True, elapsed_ms)
                        self.ctx.ai_engine.record_prediction_result(site_name, strat_name)
                        self.ctx.strategy_history.append({
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "site": site_name,
                            "strategy": strat_name,
                            "ms": round(elapsed_ms),
                            "success": True,
                        })
                        if site_name in self.ctx.site_stats:
                            self.ctx.site_stats[site_name]["successes"] += 1
                            self.ctx.site_stats[site_name]["total_ms"] += elapsed_ms
                        self.ctx.logger.info(f"[STRATEGY] {site_name}: {strat_name} success ({elapsed_ms:.0f}ms) IP:{try_ip}")
                        self.ctx.record_privacy_event(
                            target_host,
                            site_name=site_name,
                            dns_status=privacy_dns_status,
                            dns_detail=f"IP {try_ip}",
                            sni_status="hidden" if strat_name != "direct" else "direct",
                            sni_detail=f"{strat_name} confirmed",
                        )

                        writer.write(server_reply)
                        await writer.drain()
                        await self.tunnel_plain(reader, writer, server_reader, server_writer)
                        success = True
                        break

                    if success:
                        break
                if success:
                    return

            if connect_host != target_host:
                self.ctx.logger.info(f"[FALLBACK] {target_host} trying via hostname...")
                for fallback_strat in ["direct", "tls_record_frag", "fragment_burst", "desync"]:
                    server_reader_h, server_writer_h = await self.try_connect(target_host, target_port, timeout=8)
                    if not server_writer_h:
                        break
                    start_t = time.perf_counter()
                    try:
                        await self.ctx.strategy_funcs[fallback_strat](server_writer_h, first_chunk)
                        server_reply = await asyncio.wait_for(server_reader_h.read(8192), timeout=8)
                        if server_reply and len(server_reply) >= 1 and server_reply[0] == 0x16:
                            elapsed_ms = (time.perf_counter() - start_t) * 1000
                            self.ctx.strategy_cache.record_success(site_name, fallback_strat, elapsed_ms)
                            self.ctx.ai_engine.record(site_name, fallback_strat, True, elapsed_ms)
                            self.ctx.strategy_history.append({
                                "time": datetime.now().strftime("%H:%M:%S"),
                                "site": site_name,
                                "strategy": fallback_strat,
                                "ms": round(elapsed_ms),
                                "success": True,
                            })
                            self.ctx.logger.info(f"[FALLBACK] {target_host}: {fallback_strat} success ({elapsed_ms:.0f}ms)")
                            self.ctx.record_privacy_event(
                                target_host,
                                site_name=site_name,
                                dns_status="direct",
                                dns_detail=f"hostname fallback -> {target_host}",
                                sni_status="hidden" if fallback_strat != "direct" else "fallback",
                                sni_detail=f"{fallback_strat} fallback success",
                            )
                            writer.write(server_reply)
                            await writer.drain()
                            server_writer = server_writer_h
                            await self.tunnel_plain(reader, writer, server_reader_h, server_writer_h)
                            return
                    except Exception:
                        pass
                    close_writer(server_writer_h)

            if site_name in self.ctx.site_stats:
                self.ctx.site_stats[site_name]["failures"] += 1
            if all_conn_failed and not is_main:
                self.ctx.blocked_domains[target_lower] = time.time()
                self.ctx.logger.warning(
                    f"[BLOCKED] {self.ctx.hash_host(target_host)} fully blocked, {self.ctx.blocked_domain_ttl}s fast-fail active"
                )
            else:
                self.ctx.logger.error(f"All strategies failed: {self.ctx.hash_host(target_host)}")
            self.ctx.record_privacy_event(
                target_host,
                site_name=site_name,
                dns_status=privacy_dns_status,
                dns_detail=privacy_dns_detail,
                sni_status="failed",
                sni_detail="all strategies failed",
            )
        except Exception as e:
            self.ctx.logger.debug(f"Proxy error: {e}")
        finally:
            self.ctx.connection_tracker.release(conn_id)
            if sem_acquired and sem_site and sem_site in self.ctx.site_semaphores:
                try:
                    self.ctx.site_semaphores[sem_site].release()
                except ValueError:
                    pass
            for item in (server_writer, writer):
                close_writer(item)
