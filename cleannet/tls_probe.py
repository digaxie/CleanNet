"""Verified TLS probes: run a real TLS client handshake through a bypass strategy.

The proxy can only judge a live connection by the first server bytes, which is
fooled in two ways:

* DPI that intercepts the connection answers with its own (valid) certificate for a
  different host. That reply also starts with a TLS handshake record.
* A strategy that alters ClientHello content gets a ServerHello, but the TLS
  transcript no longer matches and the handshake fails one step later.

A probe drives Python's TLS client through ``ssl.MemoryBIO``: the client's real
ClientHello bytes go through the strategy function, the server's replies are fed
back, and the handshake is completed including certificate, hostname and Finished
verification. Only that counts as "verified".
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
import ssl
import time
from typing import Any, Awaitable, Callable

# OpenSSL X509_V_ERR_HOSTNAME_MISMATCH: a trusted certificate for some *other* name.
# Seen when DPI redirects the connection to a block page server.
X509_V_ERR_HOSTNAME_MISMATCH = 62

STATUS_VERIFIED = "verified"          # full handshake, certificate valid for the host
STATUS_UNVERIFIED = "unverified"      # handshake completes, but the chain is not trusted locally
STATUS_INTERCEPTED = "intercepted"    # certificate for a different host: DPI interception
STATUS_FAILED = "failed"              # reset, alert, timeout or broken handshake


@dataclass
class ProbeResult:
    status: str
    elapsed_ms: float = 0.0
    detail: str = ""
    tls_version: str = ""

    @property
    def success(self) -> bool:
        return self.status in (STATUS_VERIFIED, STATUS_UNVERIFIED)

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["success"] = self.success
        return data


Strategy = Callable[[Any, bytes], Awaitable[None]]
OpenConnection = Callable[..., Awaitable[tuple[Any, Any]]]


def _close(writer) -> None:
    try:
        if writer:
            writer.close()
    except Exception:
        pass


async def _handshake(
    open_connection: OpenConnection,
    strategy: Strategy,
    host: str,
    ip: str,
    port: int,
    context: ssl.SSLContext,
    timeout: float,
) -> tuple[float, str]:
    """Run one handshake; returns (elapsed_ms, tls_version) or raises."""
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=host)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    client_hello = outgoing.read()

    reader, writer = await asyncio.wait_for(open_connection(ip, port), timeout=timeout)
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        start = time.perf_counter()
        await strategy(writer, client_hello)
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError()
            data = await asyncio.wait_for(reader.read(16384), timeout=remaining)
            if not data:
                raise ConnectionError("server closed the connection")
            incoming.write(data)
            try:
                tls.do_handshake()
            except ssl.SSLWantReadError:
                pending = outgoing.read()
                if pending:
                    writer.write(pending)
                    await writer.drain()
                continue
            # Handshake done: send the client's final flight (Finished) like a real client.
            pending = outgoing.read()
            if pending:
                writer.write(pending)
                await writer.drain()
            return (time.perf_counter() - start) * 1000, tls.version() or ""
    finally:
        _close(writer)


async def verified_probe(
    open_connection: OpenConnection,
    strategy: Strategy,
    host: str,
    ip: str,
    port: int = 443,
    *,
    timeout: float = 8,
    context: ssl.SSLContext | None = None,
    unverified_context: ssl.SSLContext | None = None,
) -> ProbeResult:
    context = context or ssl.create_default_context()
    try:
        elapsed, version = await _handshake(open_connection, strategy, host, ip, port, context, timeout)
        return ProbeResult(STATUS_VERIFIED, round(elapsed, 1), "certificate valid", version)
    except ssl.SSLCertVerificationError as exc:
        if exc.verify_code == X509_V_ERR_HOSTNAME_MISMATCH:
            return ProbeResult(STATUS_INTERCEPTED, 0.0, "certificate is for a different host (DPI interception)")
        cert_detail = exc.verify_message or "certificate not trusted"
    except (asyncio.TimeoutError, TimeoutError):
        return ProbeResult(STATUS_FAILED, 0.0, "timeout")
    except ssl.SSLError as exc:
        return ProbeResult(STATUS_FAILED, 0.0, f"TLS error: {exc.reason or exc}")
    except (ConnectionError, OSError) as exc:
        return ProbeResult(STATUS_FAILED, 0.0, f"connection: {exc}")

    # The chain is not trusted by this machine's store (missing intermediate or root).
    # Still check that the handshake itself completes so strategies are judged fairly.
    if unverified_context is None:
        unverified_context = ssl.create_default_context()
        unverified_context.check_hostname = False
        unverified_context.verify_mode = ssl.CERT_NONE
    try:
        elapsed, version = await _handshake(open_connection, strategy, host, ip, port, unverified_context, timeout)
        return ProbeResult(STATUS_UNVERIFIED, round(elapsed, 1), cert_detail, version)
    except (asyncio.TimeoutError, TimeoutError):
        return ProbeResult(STATUS_FAILED, 0.0, "timeout")
    except ssl.SSLError as exc:
        return ProbeResult(STATUS_FAILED, 0.0, f"TLS error: {exc.reason or exc}")
    except (ConnectionError, OSError) as exc:
        return ProbeResult(STATUS_FAILED, 0.0, f"connection: {exc}")


def classify_tls_error(exc: BaseException) -> str:
    """Map a client-side TLS exception (e.g. from the site tester) to a probe status."""
    if isinstance(exc, ssl.SSLCertVerificationError) and exc.verify_code == X509_V_ERR_HOSTNAME_MISMATCH:
        return STATUS_INTERCEPTED
    return STATUS_FAILED
