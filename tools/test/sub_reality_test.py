"""REALITY subscription normalization without network: python3 tools/test/sub_reality_test.py."""

import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.parse

import yaml


ROOT = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory() as tmp:
    config = Path(tmp) / "config.json"
    config.write_text(json.dumps({"path": "/sub/", "upstream": "http://127.0.0.1:1"}))
    with mock.patch.dict(os.environ, {"KIT_SUB_CONFIG": str(config)}):
        spec = importlib.util.spec_from_file_location("kit_sub_reality", ROOT / "scripts/kit-sub.py")
        ks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ks)


class Reality(unittest.TestCase):
    def test_raw_reality_chrome_mlkem_and_other_query_values(self):
        link = "vless://id@host:443?security=reality&fp=ios&pbk=key&sid=ab&sni=old.example&encryption=mlkem.native&pcs=ABC#Name"
        fixed = ks.strip_links(link.encode(), {"old.example": "new.example"}).decode()
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(fixed).query))
        self.assertEqual(query["fp"], "chrome")
        self.assertEqual(query["support-x25519mlkem768"], "true")
        self.assertEqual(query["encryption"], "mlkem.native")
        self.assertEqual(query["pcs"], "ABC")
        self.assertEqual(query["sni"], "new.example")
        self.assertEqual(query["pbk"], "key")
        self.assertEqual(ks.strip_links(fixed.encode()), fixed.encode())

    def test_base64_reality_and_hysteria_tls_left_alone(self):
        reality = "vless://id@host:443?security=reality&pbk=key"
        hy = "hysteria2://p@host:443?fp=safari&pinSHA256=AB&obfs=salamander"
        tls = "vless://id@host:443?security=tls&fp=ios&pcs=ABC"
        out = ks.strip_links(base64.b64encode((reality + "\n" + hy + "\n" + tls).encode()))
        decoded = base64.b64decode(out).decode()
        self.assertIn("fp=chrome", decoded)
        self.assertIn(hy, decoded)
        self.assertIn(tls, decoded)
        self.assertEqual(ks.reality_link(hy), hy)
        self.assertEqual(ks.reality_link(tls), tls)

    def test_json_reality_preserves_keys_pin_encryption_and_non_reality(self):
        reality = {"protocol": "vless", "settings": {"id": "id", "encryption": "mlkem.native"},
                   "streamSettings": {"security": "reality", "realitySettings": {
                       "fingerprint": "edge", "publicKey": "key", "shortId": "ab", "serverName": "old.example", "spiderX": "/"}}}
        hy = {"protocol": "hysteria", "settings": {"version": 2}, "streamSettings": {
            "security": "tls", "tlsSettings": {"fingerprint": "safari", "pinnedPeerCertSha256": "AB"}}}
        body = json.dumps([{"outbounds": [reality, hy]}]).encode()
        fixed = ks.fix_vless_encryption(body, {"old.example": "new.example"})
        obj = json.loads(fixed)[0]["outbounds"]
        self.assertEqual(obj[0]["streamSettings"]["realitySettings"]["fingerprint"], "chrome")
        self.assertEqual(obj[0]["streamSettings"]["realitySettings"]["serverName"], "new.example")
        self.assertEqual(obj[0]["settings"]["encryption"], "mlkem.native")
        self.assertEqual(obj[0]["streamSettings"]["realitySettings"]["publicKey"], "key")
        self.assertEqual(obj[1], hy)
        self.assertEqual(ks.fix_vless_encryption(fixed), fixed)

    def test_yaml_only_reality_normalized_with_pin_and_routes_preserved(self):
        reality = {"name": "Reality", "type": "vless", "server": "host", "port": 443,
                   "client-fingerprint": "ios", "reality-opts": {"public-key": "key", "short-id": "ab",
                   "support-x25519mlkem768": False}, "certificate": "pin", "skip-cert-verify": False}
        hy = {"name": "Hysteria", "type": "hysteria2", "client-fingerprint": "safari", "pin-sha256": "AB"}
        src = {"proxies": [reality, hy], "rules": ["MATCH,DIRECT"]}
        fixed = ks.fix_clash_reality(yaml.safe_dump(src).encode())
        result = yaml.safe_load(fixed)
        self.assertEqual(result["proxies"][0]["client-fingerprint"], "chrome")
        self.assertIs(result["proxies"][0]["reality-opts"]["support-x25519mlkem768"], True)
        self.assertEqual(result["proxies"][0]["certificate"], "pin")
        self.assertIs(result["proxies"][0]["skip-cert-verify"], False)
        self.assertEqual(result["proxies"][1], hy)
        self.assertEqual(result["rules"], src["rules"])
        self.assertEqual(ks.fix_clash_reality(fixed), fixed)

    def test_yaml_without_reality_is_byte_identical(self):
        for body in (b"proxies: []\n", b"proxies:\n - name: Hysteria\n   type: hysteria2\n", b"null\n"):
            self.assertEqual(ks.fix_clash_reality(body), body)


if __name__ == "__main__":
    unittest.main()
