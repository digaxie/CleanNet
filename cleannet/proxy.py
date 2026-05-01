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


def parse_connect_target(first_line: bytes) -> tuple[str, int] | None:
    parts = first_line.split(b" ")
    if len(parts) < 2:
        return None
    host_port = parts[1].split(b":")
    if len(host_port) != 2:
        return None
    try:
        return host_port[0].decode("utf-8"), int(host_port[1])
    except (UnicodeDecodeError, ValueError):
        return None


def parse_http_forward_target(initial_data: bytes) -> HttpForwardTarget | None:
    first_line = initial_data.split(b"\r\n")[0].decode("utf-8", errors="replace")
    parts = first_line.split(" ")
    if len(parts) < 3:
        return None

    method, url, version = parts[0], parts[1], parts[2]
    url_body = url[7:] if url.startswith("http://") else url
    slash_idx = url_body.find("/")
    if slash_idx == -1:
        host_part = url_body
        path = "/"
    else:
        host_part = url_body[:slash_idx]
        path = url_body[slash_idx:]

    if ":" in host_part:
        host, port_s = host_part.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            return None
    else:
        host = host_part
        port = 80

    if not host:
        return None

    return HttpForwardTarget(method, path, version, host_part, host, port)


def rewrite_http_forward_request(initial_data: bytes, target: HttpForwardTarget) -> bytes | None:
    header_end = initial_data.find(b"\r\n\r\n")
    if header_end == -1:
        return None

    header_bytes = initial_data[:header_end]
    body_bytes = initial_data[header_end:]
    first_line_end = header_bytes.find(b"\r\n")

    new_first_line = f"{target.method} {target.path} {target.version}".encode()
    rest_headers = b"" if first_line_end == -1 else header_bytes[first_line_end:]

    has_host = any(
        line.lower().startswith(b"host:")
        for line in rest_headers.split(b"\r\n")
    )
    if not has_host:
        rest_headers = f"\r\nHost: {target.host_part}".encode() + rest_headers

    return new_first_line + rest_headers + body_bytes
