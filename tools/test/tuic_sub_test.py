"""TUIC #6978 fallback and CLI export, with no sockets or real panel: python3 tools/test/tuic_sub_test.py."""

import base64
import contextlib
import email.message
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error


ROOT = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory() as tmp:
    config = Path(tmp) / "config.json"
    config.write_text(json.dumps({"path": "/sub/", "upstream": "http://127.0.0.1:1", "auto": False, "dns": False}))
    with mock.patch.dict(os.environ, {"KIT_SUB_CONFIG": str(config)}):
        spec = importlib.util.spec_from_file_location("kit_sub_tuic", ROOT / "scripts/kit-sub.py")
        ks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ks)


ID_A = "11111111-1111-4111-8111-111111111111"
ID_B = "22222222-2222-4222-8222-222222222222"
LINK = f"tuic://{ID_A}:secret%3Aone@server.example:8444?alpn=h3#TUIC"
OTHER_LINK = f"tuic://{ID_B}:other@server.example:8444?alpn=h3#Other"
RAW = b"vless://11111111-1111-4111-8111-111111111111@server.example:443?security=reality&pbk=key&sni=tls.example&fp=chrome\n"


def page(sub_id="alice", links=None, **overrides):
    obj = {"sId": sub_id, "enabled": True, "expire": 0, "downloadByte": 0, "uploadByte": 0,
           "totalByte": 0, "links": [LINK] if links is None else links}
    obj.update(overrides)
    data = json.dumps(obj).replace("<", "\\u003c")
    return ('<!doctype html><head><script>window.X_UI_BASE_PATH="/sub/";'
            'window.__SUB_PAGE_DATA__=' + data + ';</script></head><body></body>').encode()


def handled(code, content_type, body, path="/sub/alice", ua="Happ/4.8.0", extra_headers=None):
    """Exercise BaseHTTPRequestHandler on memory buffers; a listening socket is unnecessary."""
    handler = object.__new__(ks.Handler)
    handler.path = path
    handler.command = "GET"
    handler.request_version = "HTTP/1.1"
    handler.requestline = f"GET {path} HTTP/1.1"
    handler.close_connection = True
    handler.headers = email.message.Message()
    handler.headers["Host"] = "server.example"
    handler.headers["User-Agent"] = ua
    handler.headers["Accept"] = "*/*"
    handler.wfile = io.BytesIO()
    headers = {"content-type": content_type, **(extra_headers or {})}
    with mock.patch.object(ks, "upstream", return_value=(code, headers, body)):
        handler.do_GET()
    return handler.wfile.getvalue().split(b"\r\n\r\n", 1)


class PageData(unittest.TestCase):
    def test_only_valid_tuic_links_and_exact_subscriber(self):
        html = page(links=["vless://x@host:443", LINK, "not a link", OTHER_LINK])
        self.assertEqual(ks.tuic_links_from_page(html, "alice"), [LINK, OTHER_LINK])
        with self.assertRaises(ValueError):
            ks.tuic_links_from_page(html, "bob")

    def test_disabled_expired_and_depleted_aggregate(self):
        for state in ({"enabled": False}, {"enabled": "true"}, {"expire": 10},
                      {"totalByte": 10, "downloadByte": 7, "uploadByte": 3}):
            with self.subTest(state=state):
                self.assertEqual(ks.tuic_links_from_page(page(**state), "alice", now=10), [])
        self.assertEqual(ks.tuic_links_from_page(page(expire=11), "alice", now=10), [LINK])

    def test_excluded_or_host_filtered_link_is_not_reconstructed(self):
        # The HTML uses the panel's own exclude/host binding filter; KIT must never invent credentials.
        self.assertEqual(ks.tuic_links_from_page(page(links=[]), "alice"), [])
        self.assertEqual(ks.tuic_links_from_page(page(links=["vless://only@host:443"]), "alice"), [])

    def test_bad_payload_is_refused(self):
        for html in (b"<html>custom theme</html>", b"<script>window.__SUB_PAGE_DATA__={bad};</script>",
                     page() + page(), page(links="not-list"), page(expire=True), page(totalByte=-1),
                     page(links=[None]), b"x" * (ks.JSON_FIX_MAX + 1),
                     page().replace(b";</script>", b";runSomething();</script>")):
            with self.subTest(html=html[:45]), self.assertRaises((ValueError, UnicodeError)):
                ks.tuic_links_from_page(html, "alice")

    def test_bad_tuic_credentials_or_endpoint_are_ignored(self):
        invalid = ["tuic://not-a-uuid:p@host:1", f"tuic://{ID_A}@host:1", f"tuic://{ID_A}:p@host:0",
                   f"tuic://{ID_A}:p@host:99999", f"tuic://{ID_A}:p%0Ainjected@host:1", LINK + "\nextra"]
        self.assertEqual(ks.tuic_links_from_page(page(links=invalid), "alice"), [])


class Restore(unittest.TestCase):
    def restore(self, body, html=None):
        with mock.patch.object(ks, "fetch_tuic_page", return_value=page() if html is None else html):
            return ks.restore_tuic_links(body, "alice", "Happ/4.8.0", "server.example")

    def test_restores_plain_and_base64_without_changing_encoding(self):
        plain = self.restore(RAW)
        self.assertTrue(plain.startswith(b"vless://"))
        self.assertIn(LINK.encode(), plain)
        encoded = self.restore(base64.b64encode(RAW))
        self.assertNotIn(b"://", encoded)
        self.assertEqual(base64.b64decode(encoded), plain)

    def test_tuic_only_empty_body_is_restored(self):
        self.assertEqual(base64.b64decode(self.restore(b"")), LINK.encode())

    def test_native_link_not_duplicated_when_upstream_is_fixed(self):
        native = LINK.rsplit("#", 1)[0] + "#Other%20remark"
        body = RAW + native.encode() + b"\n"
        self.assertEqual(self.restore(body), body)
        out = self.restore(RAW, page(links=[LINK, LINK.rsplit("#", 1)[0] + "#Duplicate"]))
        self.assertEqual(out.count(b"tuic://"), 1)

    def test_different_credentials_on_same_endpoint_are_preserved(self):
        out = self.restore(RAW + LINK.encode(), page(links=[LINK, OTHER_LINK]))
        self.assertEqual(out.count(b"tuic://"), 2)

    def test_missing_endpoint_restores_all_distinct_host_sni_profiles(self):
        first = LINK.replace("alpn=h3", "alpn=h3&sni=first.example")
        second = LINK.replace("alpn=h3", "alpn=h3&sni=second.example")
        out = self.restore(RAW, page(links=[first, second]))
        self.assertEqual(out.count(b"tuic://"), 2)
        self.assertIn(first.encode(), out)
        self.assertIn(second.encode(), out)

    def test_native_endpoint_wins_over_different_random_sni_from_html(self):
        native = LINK.replace("alpn=h3", "alpn=h3&sni=native-random.example")
        html_link = LINK.replace("alpn=h3", "alpn=h3&sni=html-random.example")
        body = RAW + native.encode() + b"\n"
        self.assertEqual(self.restore(body, page(links=[html_link])), body)

    def test_html_profile_dedup_sorts_query_keeps_repeats_and_ignores_fragment(self):
        prefix = LINK.split("?", 1)[0]
        first = prefix + "?alpn=h3&sni=one.example&tag=a&tag=b&empty=#First"
        reordered = prefix + "?tag=b&empty=&sni=one.example&tag=a&alpn=h3#Other%20remark"
        fewer_values = prefix + "?sni=one.example&alpn=h3&tag=a&empty=#Distinct"
        out = self.restore(RAW, page(links=[first, reordered, fewer_values]))
        self.assertEqual(out.count(b"tuic://"), 2)
        self.assertIn(first.encode(), out)
        self.assertIn(fewer_values.encode(), out)
        self.assertNotIn(reordered.encode(), out)

    def test_no_cross_subscriber_fallback(self):
        self.assertEqual(self.restore(RAW, page(sub_id="bob", links=[OTHER_LINK])), RAW)

    def test_error_html_or_json_is_not_treated_as_uri_list(self):
        with mock.patch.object(ks, "fetch_tuic_page") as fetch:
            for raw in (b"not authorized", b"<html>error</html>", b'{"error":"https://private"}', b"\xff", b"%%%"):
                self.assertEqual(ks.restore_tuic_links(raw, "alice", "Happ", "host"), raw)
            fetch.assert_not_called()

    def test_fallback_failure_keeps_original_and_redacts_logs(self):
        err = io.StringIO()
        with mock.patch.object(ks, "fetch_tuic_page", side_effect=urllib.error.URLError("https://secret-token")), contextlib.redirect_stderr(err):
            self.assertEqual(ks.restore_tuic_links(RAW, "alice", "Happ", "host"), RAW)
        self.assertIn("TUIC", err.getvalue())
        self.assertNotIn("secret-token", err.getvalue())


class LocalFetch(unittest.TestCase):
    def test_refuses_non_loopback_before_any_request(self):
        invalid = ("https://example.com", "http://127.0.0.1@evil.example", "http://localhost:1234",
                   "file:///etc/passwd", "http://127.0.0.1:1234?token=x", "http://127.0.0.1:1234#fragment")
        with mock.patch.object(ks.urllib.request, "build_opener") as opener:
            for upstream in invalid:
                with self.subTest(upstream=upstream), mock.patch.dict(ks.CONF, {"upstream": upstream}), self.assertRaises(ValueError):
                    ks.fetch_tuic_page("alice", "Happ", "server.example")
            opener.assert_not_called()

    def test_refuses_bad_id_host_and_extra_path_before_any_request(self):
        with mock.patch.object(ks.urllib.request, "build_opener") as opener:
            for sid, host, prefix in (("alice\n", "host", None), ("../bob", "host", None),
                                      ("alice", "evil\r\nheader: x", None), ("alice", "x/path", None),
                                      ("alice", "host", "/json/")):
                with self.subTest(sid=sid, host=host), self.assertRaises(ValueError):
                    ks.fetch_tuic_page(sid, "Happ", host, prefix)
            opener.assert_not_called()

    def test_loopback_request_has_no_auth_or_redirects_or_env_proxy(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.headers = {"Content-Type": "text/html; charset=utf-8"}
        response.read.return_value = page()
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(ks.urllib.request, "build_opener", return_value=opener) as build:
            self.assertEqual(ks.fetch_tuic_page("alice", "Happ/4.8.0", "server.example"), page())
        req = opener.open.call_args.args[0]
        self.assertEqual(req.full_url, "http://127.0.0.1:1/sub/alice")
        self.assertEqual(req.get_header("Accept"), "text/html")
        self.assertEqual(req.get_header("Host"), "server.example")
        self.assertIsNone(req.get_header("Authorization"))
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsNone(build.call_args.args[1].redirect_request(None, None, 302, "", {}, "http://evil"))
        response.read.assert_called_once_with(ks.JSON_FIX_MAX + 1)


class HandlerAndCLI(unittest.TestCase):
    def test_handler_restores_base64_and_preserves_happ_headers(self):
        with mock.patch.object(ks, "fetch_tuic_page", return_value=page()) as fetch:
            headers, body = handled(200, "text/plain; charset=utf-8", base64.b64encode(RAW),
                                    extra_headers={"routing": "happ://routing/onadd/fixture", "subscription-userinfo": "upload=0; expire=0"})
        self.assertIn(LINK.encode(), base64.b64decode(body))
        self.assertIn(b"Routing: happ://routing/onadd/fixture", headers)
        self.assertNotIn(b"expire=0", headers)
        fetch.assert_called_once_with("alice", "Happ/4.8.0", "server.example", "/sub/")

    def test_handler_never_restores_failed_html_assets_or_json(self):
        fixtures = ((403, "text/plain", RAW, "/sub/alice"), (200, "text/html", page(), "/sub/alice"),
                    (200, "application/json", b'{"outbounds":[]}', "/sub/alice"),
                    (200, "text/plain", b'const uri="tuic://literal";', "/sub/assets/app.js"))
        with mock.patch.object(ks, "fetch_tuic_page") as fetch:
            for status, ctype, body, path in fixtures:
                with self.subTest(status=status, ctype=ctype, path=path):
                    self.assertEqual(handled(status, ctype, body, path=path)[1], body)
            fetch.assert_not_called()

    def test_cli_uses_shared_fallback_but_keeps_vpn_and_tg(self):
        raw = RAW + b"vpn://fixture\ntg://proxy?server=fixture\n"
        with mock.patch.object(ks, "local_subscription_body", side_effect=lambda sid, ua, host, accept, prefix=None: page() if accept == "text/html" else base64.b64encode(raw)), \
             mock.patch.object(ks, "Server", side_effect=AssertionError("must not start server")), \
             mock.patch.object(sys, "argv", ["kit-sub.py", "--links", "alice", "server.example"]), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as result:
                ks.main()
        self.assertEqual(result.exception.code, 0)
        text = out.getvalue()
        self.assertIn(LINK, text)
        self.assertIn("vpn://fixture", text)
        self.assertIn("tg://proxy", text)
        self.assertIn("fp=chrome", text)
        self.assertIn("support-x25519mlkem768=true", text)

    def test_cli_failure_or_wrong_arguments_is_nonzero_without_token_output(self):
        with mock.patch.object(ks, "local_subscription_body", side_effect=urllib.error.URLError("secret-token")), \
             contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(ks.cli_links("alice", "server.example"), 1)
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn("secret-token", err.getvalue())
        with mock.patch.object(sys, "argv", ["kit-sub.py", "--links"]), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
            ks.main()
        self.assertEqual(result.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
