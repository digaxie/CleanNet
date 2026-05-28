"""DoH DNS resolution and privacy DNS cache management."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import json
import socket
import ssl
import time
from typing import Any, Callable
import urllib.parse
import urllib.request


DOH_PROVIDERS = [
    {"host": "dns.google", "path": "/resolve", "bootstrap_ips": ["8.8.8.8", "8.8.4.4"]},
    {"host": "cloudflare-dns.com", "path": "/dns-query", "bootstrap_ips": ["1.1.1.1", "1.0.0.1"]},
]
DOH_BOOTSTRAP_MAP = {provider["host"]: list(provider["bootstrap_ips"]) for provider in DOH_PROVIDERS}


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def decode_chunked(data: bytes) -> bytes | None:
    decoded = bytearray()
    pos = 0
    while True:
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            return None
        size_line = data[pos:line_end].split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_line or b"0", 16)
        except ValueError:
            return None
        pos = line_end + 2
        if len(data) < pos + chunk_size + 2:
            return None
        decoded.extend(data[pos:pos + chunk_size])
        pos += chunk_size
        if data[pos:pos + 2] != b"\r\n":
            return None
        pos += 2
        if chunk_size == 0:
            return bytes(decoded)


def read_http_response(sock, max_bytes: int = 256 * 1024) -> bytes | None:
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 32 * 1024:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk

    if b"\r\n\r\n" not in data:
        return None

    header_bytes, body = data.split(b"\r\n\r\n", 1)
    header_lines = header_bytes.split(b"\r\n")
    status_line = header_lines[0].decode("iso-8859-1", errors="ignore")
    if " 200 " not in status_line:
        return None

    content_length = None
    is_chunked = False
    for line in header_lines[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                content_length = int(line.split(b":", 1)[1].strip())
            except Exception:
                content_length = None
            break
        if line.lower().startswith(b"transfer-encoding:") and b"chunked" in line.lower():
            is_chunked = True

    if content_length is not None:
        while len(body) < content_length and len(body) < max_bytes:
            chunk = sock.recv(min(4096, content_length - len(body)))
            if not chunk:
                break
            body += chunk
        return body[:content_length]

    if is_chunked:
        while len(body) < max_bytes:
            decoded = decode_chunked(body)
            if decoded is not None:
                return decoded
            chunk = sock.recv(4096)
            if not chunk:
                break
            body += chunk
        return decode_chunked(body)

    while len(body) < max_bytes:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    return body


@dataclass
class DnsResolverContext:
    logger: Any
    domain_ips: dict[str, list[str]]
    site_ips: dict[str, list[str]]
    privacy_cache: dict[str, dict[str, Any]]
    stats: dict[str, Any]
    get_site_dns: Callable[[], dict[str, list[str]]]
    set_bypass_ips: Callable[[list[str]], None]
    hash_host: Callable[[str], str]
    privacy_cache_ttl: int = 900
    time_func: Callable[[], float] = time.time


class DnsResolver:
    def __init__(
        self,
        context: DnsResolverContext,
        *,
        providers: list[dict[str, Any]] | None = None,
        ssl_context=None,
        fallback_opener=None,
    ):
        self.ctx = context
        self.providers = providers if providers is not None else DOH_PROVIDERS
        self.bootstrap_map = {provider["host"]: list(provider["bootstrap_ips"]) for provider in self.providers}
        self.ssl_context = ssl_context or ssl.create_default_context()
        self.fallback_opener = fallback_opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self.ssl_context),
        )

    def query_provider_bootstrap(self, provider: dict[str, Any], domain: str, timeout: int = 5) -> list[str]:
        query = urllib.parse.quote(domain, safe="")
        request_bytes = (
            f"GET {provider['path']}?name={query}&type=A HTTP/1.1\r\n"
            f"Host: {provider['host']}\r\n"
            "Accept: application/dns-json\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")

        for bootstrap_ip in provider["bootstrap_ips"]:
            try:
                with socket.create_connection((bootstrap_ip, 443), timeout=timeout) as raw_sock:
                    raw_sock.settimeout(timeout)
                    with self.ssl_context.wrap_socket(raw_sock, server_hostname=provider["host"]) as tls_sock:
                        tls_sock.sendall(request_bytes)
                        body = read_http_response(tls_sock)
                        if not body:
                            continue
                        data = json.loads(body.decode("utf-8", errors="ignore"))
                        ips = [answer["data"] for answer in data.get("Answer", []) if answer.get("type") == 1]
                        if ips:
                            return ips
            except Exception:
                continue
        return []

    def resolve_domain_doh(self, domain: str, timeout: int = 5) -> list[str]:
        domain = (domain or "").strip().lower()
        if not domain:
            return []

        if domain in self.bootstrap_map:
            return list(self.bootstrap_map[domain])

        for provider in self.providers:
            ips = self.query_provider_bootstrap(provider, domain, timeout=timeout)
            if ips:
                return ips

        for provider in self.providers:
            try:
                url = (
                    f"https://{provider['host']}{provider['path']}"
                    f"?name={urllib.parse.quote(domain, safe='')}&type=A"
                )
                req = urllib.request.Request(url, headers={
                    "Accept": "application/dns-json",
                    "User-Agent": "Mozilla/5.0",
                })
                resp = self.fallback_opener.open(req, timeout=timeout)
                data = json.loads(resp.read())
                ips = [answer["data"] for answer in data.get("Answer", []) if answer.get("type") == 1]
                if ips:
                    return ips
            except Exception:
                continue
        return []

    async def resolve_domain_privately(self, domain: str) -> list[str]:
        domain = (domain or "").strip().lower()
        if not domain or is_ip_literal(domain):
            return [domain] if domain else []

        now = self.ctx.time_func()
        cached = self.ctx.privacy_cache.get(domain)
        if cached and (now - cached["ts"]) < self.ctx.privacy_cache_ttl:
            return list(cached["ips"])

        known_ips = self.ctx.domain_ips.get(domain)
        if known_ips:
            self.ctx.privacy_cache[domain] = {"ips": list(known_ips), "ts": now}
            return list(known_ips)

        loop = asyncio.get_event_loop()
        ips = await loop.run_in_executor(None, self.resolve_domain_doh, domain)
        if ips:
            self.ctx.privacy_cache[domain] = {"ips": list(ips), "ts": self.ctx.time_func()}
            self.ctx.logger.debug(f"[DNS-PRIVACY] {domain}: {len(ips)} IPs cached via DoH")
            return ips

        self.ctx.logger.warning(f"[DNS-PRIVACY] DoH resolution failed for {self.ctx.hash_host(domain)}")
        return []

    async def resolve_bypass_ips(self) -> bool:
        loop = asyncio.get_event_loop()
        all_new_ips: set[str] = set()
        resolved_domains = 0

        domains_to_resolve: set[str] = set()
        site_dns = self.ctx.get_site_dns()
        for dns_list in site_dns.values():
            domains_to_resolve.update(dns_list)

        domain_list = list(domains_to_resolve)
        for i in range(0, len(domain_list), 5):
            batch = domain_list[i:i + 5]
            tasks = [loop.run_in_executor(None, self.resolve_domain_doh, domain) for domain in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for domain, result in zip(batch, results):
                if isinstance(result, list) and result:
                    self.ctx.domain_ips[domain] = result
                    all_new_ips.update(result)
                    resolved_domains += 1

        for site_name, dns_domains in site_dns.items():
            site_new_ips = set(self.ctx.site_ips.get(site_name, []))
            for domain in dns_domains:
                if domain in self.ctx.domain_ips:
                    site_new_ips.update(self.ctx.domain_ips[domain])
            if site_new_ips:
                self.ctx.site_ips[site_name] = list(site_new_ips)

        if all_new_ips:
            bypass_ips = list(all_new_ips)
            self.ctx.set_bypass_ips(bypass_ips)
            self.ctx.stats["ip_updates"] += 1
            self.ctx.stats["last_ip_refresh"] = int(self.ctx.time_func())
            self.ctx.logger.info(f"IPs updated (DoH): {len(bypass_ips)} IPs, {resolved_domains} domains")
            return True

        self.ctx.logger.warning("DNS resolution failed")
        return False
