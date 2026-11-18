import unittest

from cleannet.proxy import (
    is_valid_tls_reply,
    looks_like_tls_client_hello,
    parse_connect_target,
    parse_http_forward_target,
    rewrite_http_forward_request,
    split_host_port,
    tls_record_end,
)


class ProxyParsingTests(unittest.TestCase):
    def test_parse_connect_target(self):
        self.assertEqual(parse_connect_target(b"CONNECT example.com:443 HTTP/1.1"), ("example.com", 443))
        self.assertIsNone(parse_connect_target(b"CONNECT example.com HTTP/1.1"))
        self.assertIsNone(parse_connect_target(b"CONNECT example.com:nope HTTP/1.1"))

    def test_parse_connect_target_ipv6_literal(self):
        # Regression: splitting on every ":" rejected all bracketed IPv6 CONNECT targets.
        self.assertEqual(parse_connect_target(b"CONNECT [2001:db8::1]:443 HTTP/1.1"), ("2001:db8::1", 443))
        self.assertIsNone(parse_connect_target(b"CONNECT [2001:db8::1] HTTP/1.1"))
        self.assertIsNone(parse_connect_target(b"CONNECT [2001:db8::1 HTTP/1.1"))

    def test_parse_connect_target_rejects_out_of_range_port(self):
        self.assertIsNone(parse_connect_target(b"CONNECT example.com:0 HTTP/1.1"))
        self.assertIsNone(parse_connect_target(b"CONNECT example.com:70000 HTTP/1.1"))

    def test_split_host_port(self):
        self.assertEqual(split_host_port("example.com"), ("example.com", None))
        self.assertEqual(split_host_port("example.com:8080"), ("example.com", 8080))
        self.assertEqual(split_host_port("[::1]:8080"), ("::1", 8080))
        self.assertEqual(split_host_port("[::1]"), ("::1", None))

    def test_parse_http_forward_target_absolute_url(self):
        target = parse_http_forward_target(b"GET http://example.com:8080/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")

        self.assertEqual(target.method, "GET")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.port, 8080)
        self.assertEqual(target.path, "/path?q=1")

    def test_parse_http_forward_target_ipv6_and_uppercase_scheme(self):
        target = parse_http_forward_target(b"GET HTTP://[::1]:8080/x HTTP/1.1\r\n\r\n")

        self.assertEqual(target.host, "::1")
        self.assertEqual(target.port, 8080)
        self.assertEqual(target.path, "/x")

    def test_rewrite_http_forward_request_adds_host_header(self):
        target = parse_http_forward_target(b"GET http://example.com/path HTTP/1.1\r\nUser-Agent: test\r\n\r\n")

        rewritten = rewrite_http_forward_request(b"GET http://example.com/path HTTP/1.1\r\nUser-Agent: test\r\n\r\n", target)

        self.assertEqual(
            rewritten,
            b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nConnection: close\r\n\r\n",
        )

    def test_rewrite_http_forward_request_adds_host_header_without_other_headers(self):
        target = parse_http_forward_target(b"GET http://example.com/path HTTP/1.1\r\n\r\n")

        rewritten = rewrite_http_forward_request(b"GET http://example.com/path HTTP/1.1\r\n\r\n", target)

        self.assertEqual(rewritten, b"GET /path HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")

    def test_rewrite_http_forward_request_keeps_existing_host_header(self):
        target = parse_http_forward_target(b"GET http://example.com/path HTTP/1.1\r\nHost: other\r\n\r\n")

        rewritten = rewrite_http_forward_request(b"GET http://example.com/path HTTP/1.1\r\nHost: other\r\n\r\n", target)

        self.assertEqual(rewritten, b"GET /path HTTP/1.1\r\nHost: other\r\nConnection: close\r\n\r\n")

    def test_rewrite_strips_hop_by_hop_headers_and_keeps_body(self):
        raw = (
            b"POST http://example.com/p HTTP/1.1\r\nHost: example.com\r\n"
            b"Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic x\r\n"
            b"Connection: keep-alive\r\nContent-Length: 2\r\n\r\nok"
        )
        target = parse_http_forward_target(raw)

        rewritten = rewrite_http_forward_request(raw, target)

        self.assertEqual(
            rewritten,
            b"POST /p HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        )

    def test_rewrite_invalid_request_returns_none(self):
        target = parse_http_forward_target(b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n")

        self.assertIsNone(rewrite_http_forward_request(b"GET http://example.com/path HTTP/1.1", target))

    def test_parse_http_forward_target_origin_form(self):
        target = parse_http_forward_target(b"GET example.com/path HTTP/1.1\r\n\r\n")

        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.port, 80)
        self.assertEqual(target.path, "/path")

    def test_tls_helpers_match_proxy_expectations(self):
        self.assertTrue(looks_like_tls_client_hello(b"\x16\x03\x01\x00\x2a\x01payload"))
        self.assertFalse(looks_like_tls_client_hello(b"\x16\x03\x01\x00\x2a"))
        self.assertTrue(is_valid_tls_reply(b"\x16\x03\x03"))
        self.assertFalse(is_valid_tls_reply(b"\x15\x03\x03"))
        self.assertFalse(is_valid_tls_reply(b""))

    def test_tls_record_end(self):
        self.assertIsNone(tls_record_end(b"\x16\x03\x01"))
        self.assertEqual(tls_record_end(b"\x16\x03\x01\x01\x00"), 5 + 256)


if __name__ == "__main__":
    unittest.main()
