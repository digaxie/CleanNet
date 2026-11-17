"""Pure proxy parsing helpers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HttpForwardTarget:
    method: str
    path: str
    version: str
    host_part: str
    host: str
    port: int


def looks_like_tls_client_hello(data: bytes) -> bool:
    return (
        isinstance(data, (bytes, bytearray))
        and len(data) > 6
        and data[0] == 0x16
        and data[1] == 0x03
        and data[5] == 0x01
    )


def is_valid_tls_reply(data: bytes | None) -> bool:
    if not data:
        return False
    if len(data) >= 2 and data[0] == 0x15:
        return False
    if len(data) >= 1 and data[0] in (0x14, 0x16, 0x17):
        return True
    return False


def tls_record_end(data: bytes) -> int | None:
    """Return the byte length of the first TLS record in ``data``.

    Returns None when the 5-byte record header is incomplete. The value may exceed
    ``len(data)`` when the record body has not fully arrived yet.
    """
    if len(data) < 5:
        return None
    return 5 + int.from_bytes(data[3:5], "big")


def split_host_port(host_port: str) -> tuple[str, int | None] | None:
    """Split ``host[:port]`` or ``[v6]:port`` into ``(host, port)``.

    The port is None when it is absent. Returns None for malformed input or a port
    outside 1-65535. IPv6 literals are returned without their brackets.
    """
    host_port = host_port.strip()
    if host_port.startswith("["):
        end = host_port.find("]")
        if end == -1:
            return None
        host = host_port[1:end]
        rest = host_port[end + 1:]
        if not rest:
            return host, None
        if not rest.startswith(":"):
            return None
        port_s = rest[1:]
    elif host_port.count(":") == 1:
        host, port_s = host_port.split(":", 1)
    else:
        # No port, or a bare (unbracketed) IPv6 literal that cannot carry one.
        return host_port, None
    try:
        port = int(port_s)
    except ValueError:
        return None
    if not 0 < port < 65536:
        return None
    return host, port


def parse_connect_target(first_line: bytes) -> tuple[str, int] | None:
    parts = first_line.split(b" ")
    if len(parts) < 2:
        return None
    try:
        authority = parts[1].decode("utf-8")
    except UnicodeDecodeError:
        return None
    split = split_host_port(authority)
    if not split:
        return None
    host, port = split
    if not host or port is None:
        return None
    return host, port


def parse_http_forward_target(initial_data: bytes) -> HttpForwardTarget | None:
    first_line = initial_data.split(b"\r\n")[0].decode("utf-8", errors="replace")
    parts = first_line.split(" ")
    if len(parts) < 3:
        return None

    method, url, version = parts[0], parts[1], parts[2]
    url_body = url[7:] if url[:7].lower() == "http://" else url
    slash_idx = url_body.find("/")
    if slash_idx == -1:
        host_part = url_body
        path = "/"
    else:
        host_part = url_body[:slash_idx]
        path = url_body[slash_idx:]

    split = split_host_port(host_part)
    if not split:
        return None
    host = split[0]
    port = split[1] if split[1] is not None else 80

    if not host:
        return None

    return HttpForwardTarget(method, path, version, host_part, host, port)


# Hop-by-hop headers belong to the client<->proxy hop and must not be forwarded.
_HOP_BY_HOP_HEADERS = (b"proxy-connection:", b"proxy-authorization:", b"connection:", b"keep-alive:")


def rewrite_http_forward_request(initial_data: bytes, target: HttpForwardTarget) -> bytes | None:
    """Turn an absolute-form proxy request into an origin-form request for ``target``.

    The upstream side is a raw tunnel to one host. A kept-alive client could send its
    next request, possibly for a different host, down the same socket and it would
    reach the wrong server. Forcing ``Connection: close`` gives every forwarded
    request its own upstream connection.
    """
    header_end = initial_data.find(b"\r\n\r\n")
    if header_end == -1:
        return None

    header_bytes = initial_data[:header_end]
    body_bytes = initial_data[header_end:]
    first_line_end = header_bytes.find(b"\r\n")

    new_first_line = f"{target.method} {target.path} {target.version}".encode()
    rest_headers = b"" if first_line_end == -1 else header_bytes[first_line_end + 2:]

    kept: list[bytes] = []
    has_host = False
    for line in rest_headers.split(b"\r\n") if rest_headers else []:
        lower = line.lower()
        if lower.startswith(_HOP_BY_HOP_HEADERS):
            continue
        if lower.startswith(b"host:"):
            has_host = True
        kept.append(line)
    if not has_host:
        kept.insert(0, f"Host: {target.host_part}".encode())
    kept.append(b"Connection: close")

    return new_first_line + b"\r\n" + b"\r\n".join(kept) + body_bytes
