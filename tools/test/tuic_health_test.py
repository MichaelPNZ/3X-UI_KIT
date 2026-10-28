"""CLI health/deep probe: проверяем именно наличие TUIC подписчика, без сетевых запросов."""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "scripts/kit.sh").read_text()
BASH = os.environ.get("KIT_TEST_BASH") or (
    "/opt/homebrew/bin/bash" if Path("/opt/homebrew/bin/bash").is_file() else shutil.which("bash"))
UID = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"


def function(name):
    return re.search(r"^%s\(\) \{.*?^\}\n" % name, SOURCE, re.M | re.S)[0]


def inbound(**fields):
    client = dict(uuid=UID, id=UID, subId="fixture-sub", email="fixture", enable=True)
    client.update(fields)
    return dict(protocol="tuic", enable=True, excludeFromSub=False, settings={"clients": [client]}, clientStats=[])


class TuicHealth(unittest.TestCase):
    def check(self, rows, body, public=False, **extra):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            config = p / "etc/kit-sub/config.json"
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(dict(port=12345 if public else 0, path="/sub/")))
            code = "\n".join(function(n) for n in ("tuic_expected", "tuic_link_present", "tuic_subscription_healthy"))
            code = code.replace("/etc/kit-sub/config.json", str(config))
            code = r'''
set -Eeuo pipefail
SUB_PATH=/sub/; HOST=example.org
warn() { printf 'WARN: %s\n' "$*" >&2; }
api() { [[ $TEST_API_FAIL != yes ]] || return 1; printf '%s' "$TEST_INBOUNDS"; }
subscription_links() { printf '%s' "$TEST_BODY"; }
curl() {
  local out
  while (($#)); do if [[ $1 == -o ]]; then out=$2; shift; fi; shift; done
  printf '%s' "$TEST_BODY" >"$out"
  printf '%s' "$TEST_HTTP"
}
''' + code + "\nSUB_TUIC_CHECKED=0\ntuic_subscription_healthy\necho checked=$SUB_TUIC_CHECKED\n"
            env = dict(os.environ, TEST_INBOUNDS=json.dumps(rows), TEST_BODY=body,
                       TEST_API_FAIL="no", TEST_HTTP="200")
            env.update(extra)
            return subprocess.run([BASH, "-c", code], env=env, capture_output=True, text=True, timeout=5)

    def test_raw_and_base64_for_actual_subscriber(self):
        raw = f"vless://fixture\ntuic://{UID}:password@example.org:8444#TUIC"
        for body in (raw, base64.b64encode(raw.encode()).decode()):
            for public in (False, True):
                with self.subTest(public=public, encoded=body != raw):
                    r = self.check([inbound()], body, public=public)
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                    self.assertIn("checked=1", r.stdout)

    def test_missing_or_another_clients_tuic_fails(self):
        for body in ("vless://fixture", f"tuic://{OTHER}:password@example.org:8444", "not a subscription"):
            with self.subTest(body=body):
                r = self.check([inbound()], body, public=True)
                self.assertNotEqual(r.returncode, 0)
                self.assertNotIn(UID, r.stderr)

    def test_disabled_expired_depleted_and_excluded_do_not_require_links(self):
        cases = [inbound(enable=False), inbound(expiryTime=int(time.time()*1000)-1000)]
        disabled = inbound(); disabled["enable"] = False; cases.append(disabled)
        excluded = inbound(); excluded["excludeFromSub"] = True; cases.append(excluded)
        depleted = inbound(totalGB=10)
        depleted["clientStats"] = [{"email": "fixture", "up": 5, "down": 5}]
        cases.append(depleted)
        for row in cases:
            with self.subTest(row=row):
                r = self.check([row], "vless://fixture")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("checked=0", r.stdout)

    def test_every_eligible_tuic_client_is_checked(self):
        row = inbound()
        row["settings"]["clients"].append(dict(uuid=OTHER, subId="fixture-sub", email="second", enable=True))
        r = self.check([row], f"tuic://{UID}:password@example.org:8444", public=True)
        self.assertNotEqual(r.returncode, 0)
        r = self.check([row], f"tuic://{UID}:password@example.org:8444\ntuic://{OTHER}:password@example.org:8444", public=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("checked=2", r.stdout)

    def test_unreadable_api_or_failed_subscription_is_not_healthy(self):
        for variable in ({"TEST_API_FAIL": "yes"}, {"TEST_HTTP": "503"}):
            r = self.check([inbound()], f"tuic://{UID}:password@example.org:8444", public=True, **variable)
            self.assertNotEqual(r.returncode, 0)

    def test_deep_probe_checks_tuic_even_if_network_probe_succeeds(self):
        code = '''set -Eeuo pipefail
deep_clients() { :; }
tuic_subscription_healthy() { return 1; }
''' + function("deep_probe") + "\ndeep_probe\n"
        r = subprocess.run([BASH, "-c", code], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(r.returncode, 0)

    def test_client_host_bindings_are_an_explicit_skip_instead_of_false_failure(self):
        r = self.check([inbound(clientHostRuleIds=[123])], "vless://fixture", public=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("checked=0", r.stdout)
        self.assertIn("индивидуальные Hosts", r.stderr)

    def test_ssh_only_subscription_check_uses_cli_without_http_service(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "config.json"
            cfg.write_text(json.dumps(dict(port=0, path="/sub/", upstream="http://127.0.0.1:2096")))
            code = function("sub_body_ok") + function("check_subscription")
            code = code.replace("/etc/kit-sub/config.json", str(cfg))
            stubs = '''set -Eeuo pipefail
SINGLE=no; CHECK_BAD=0; SUB_TUIC_CHECKED=0
c_ok() { :; }; c_info() { :; }; c_bad() { CHECK_BAD=$((CHECK_BAD+1)); }
clients() { echo '[{"subId":"fixture-sub"}]'; }
api() { echo '{}'; }
subscription_links() { echo 'vless://fixture'; }
tuic_subscription_healthy() { SUB_TUIC_CHECKED=1; }
curl() { echo 'Unexpected HTTP in SSH-only mode' >&2; exit 99; }
'''
            r = subprocess.run([BASH, "-c", stubs + code + '\ncheck_subscription\n[[ $CHECK_BAD == 0 ]]\n'],
                               capture_output=True, text=True, timeout=5)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertNotIn("Unexpected HTTP", r.stderr)

    def test_ssh_only_cli_library_is_not_a_failed_public_service(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            cfg = p / "config.json"; cfg.write_text('{"port":0}')
            lib = p / "kit_sub.py"; lib.write_text("# fixture")
            code = function("check_services").replace("/etc/kit-sub/config.json", str(cfg))
            code = code.replace("/usr/local/lib/kit-sub/kit_sub.py", str(lib))
            stubs = '''set -Eeuo pipefail
SINGLE=no; CHECK_BAD=0
c_ok() { :; }; c_info() { :; }; c_bad() { CHECK_BAD=$((CHECK_BAD+1)); }
auto_enabled() { return 0; }; limit_timer_enabled() { return 0; }
api() { echo '[]'; }
systemctl() { [[ $* != *kit-sub* ]]; }
'''
            r = subprocess.run([BASH, "-c", stubs + code + '\ncheck_services\n[[ $CHECK_BAD == 0 ]]\n'],
                               capture_output=True, text=True, timeout=5)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
