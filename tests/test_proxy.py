import unittest

from cleannet.proxy import (
    is_valid_tls_reply,
    looks_like_tls_client_hello,
    parse_connect_target,
    parse_http_forward_target,
    rewrite_http_forward_request,
)


class ProxyParsingTests(unittest.TestCase):
    def test_parse_connect_target(self):
        self.assertEqual(parse_connect_target(b"CONNECT example.com:443 HTTP/1.1"), ("example.com", 443))
        self.assertIsNone(parse_connect_target(b"CONNECT example.com HTTP/1.1"))
        self.assertIsNone(parse_connect_target(b"CONNECT example.com:nope HTTP/1.1"))

    def test_parse_http_forward_target_absolute_url(self):
        target = parse_http_forward_target(b"GET http://example.com:8080/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")

        self.assertEqual(target.method, "GET")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.port, 8080)
        self.assertEqual(target.path, "/path?q=1")

    def test_rewrite_http_forward_request_adds_host_header(self):
        target = parse_http_forward_target(b"GET http://example.com/path HTTP/1.1\r\nUser-Agent: test\r\n\r\n")

        rewritten = rewrite_http_forward_request(b"GET http://example.com/path HTTP/1.1\r\nUser-Agent: test\r\n\r\n", target)

        self.assertEqual(
            rewritten,
            b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n",
        )

    def test_rewrite_http_forward_request_adds_host_header_without_other_headers(self):
        target = parse_http_forward_target(b"GET http://example.com/path HTTP/1.1\r\n\r\n")

        rewritten = rewrite_http_forward_request(b"GET http://example.com/path HTTP/1.1\r\n\r\n", target)

        self.assertEqual(rewritten, b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")

    def test_rewrite_http_forward_request_keeps_existing_host_header(self):
        target = parse_http_forward_target(b"GET http://example.com/path HTTP/1.1\r\nHost: other\r\n\r\n")

        rewritten = rewrite_http_forward_request(b"GET http://example.com/path HTTP/1.1\r\nHost: other\r\n\r\n", target)

        self.assertEqual(rewritten, b"GET /path HTTP/1.1\r\nHost: other\r\n\r\n")

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


if __name__ == "__main__":
    unittest.main()
