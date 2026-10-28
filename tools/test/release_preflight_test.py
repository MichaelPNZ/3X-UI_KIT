"""Release preflight in a disposable fixture; no key pairs, signatures or network.

The only native ssh-keygen operation permitted by the fixture is reading a public
key fingerprint (-lf). All curl responses and git status are local stubs.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
REAL_KEYGEN = shutil.which("ssh-keygen")
# An SSH public-key blob is enough to test parsing. No private key exists for it
# in this test: these are fixed public bytes, not a generated key pair.
KEY_TYPE = b"ssh-ed25519"
PUBLIC_BLOB = struct.pack(">I", len(KEY_TYPE)) + KEY_TYPE + struct.pack(">I", 32) + bytes(range(32))
PUBLIC_KEY = "ssh-ed25519 " + base64.b64encode(PUBLIC_BLOB).decode() + " fixture-public-only"
PLACEHOLDER = "ssh-ed25519 REPLACE_WITH_FORK_RELEASE_PUBKEY fixture"
CORE = {"64": "1" * 64, "arm64-v8a": "2" * 64}
PANEL = {"amd64": "3" * 64, "arm64": "4" * 64}
INSTALL = "#!/bin/bash\necho fixture-upstream-installer\n"
MENU = "#!/bin/bash\necho fixture-upstream-menu\n"


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def array(name, values):
    return "declare -A " + name + "=(\n" + "".join(
        "  [" + k + "]=" + v + "\n" for k, v in values.items()) + ")\n"


@unittest.skipUnless(REAL_KEYGEN, "ssh-keygen is needed only to parse public fixtures")
class ReleasePreflight(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kit-release-preflight-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("scripts", "manuals", "tools", "bin"):
            (self.root / name).mkdir()
        shutil.copyfile(ROOT / "tools/release.sh", self.root / "tools/release.sh")
        self.events = self.root / "events.jsonl"
        self.responses_file = self.root / "responses.json"
        self.write("VERSION", "1.3.0\n")
        self.write("CHANGELOG.md", "## v1.3.0\n")
        self.write("NOTICE.md", "fixture fork notice\n")
        command = "https://raw.githubusercontent.com/MichaelPNZ/3X-UI_KIT/v1.3.0/scripts/3x-ui.sh\n"
        self.write("README.md", command)
        self.write("manuals/3x-ui.md", command)
        self.write("scripts/hysteria2.sh", 'KIT_VERSION="1.3.0"\n')
        self.write("scripts/kit-sub.py", "# fixture\n")
        self.write("scripts/3x-ui.sh", 'KIT_VERSION="1.3.0"\nXUI_VERSION="v3.11.0"\n'
                   'XRAY_CORE="v26.10.21"\nXUI_INSTALL_SHA256="' + digest(INSTALL) + '"\n'
                   + array("XRAY_ZIP_SHA256", CORE))
        self.write("scripts/kit.sh", 'KIT_VERSION="1.3.0"\nXUI_PIN="v3.11.0"\n'
                   'XRAY_PIN="v26.10.21"\nXUI_SH_SHA256=' + digest(MENU) + "\n"
                   + array("XUI_TARBALL_SHA256", PANEL) + array("XRAY_ZIP_SHA256", CORE)
                   + 'KIT_SIGNERS=(\n  "' + PUBLIC_KEY + '"\n)\n')
        self.responses = {
            "https://api.github.com/repos/MHSanaei/3x-ui/releases/tags/v3.11.0": json.dumps({
                "assets": [{"name": "x-ui-linux-" + a + ".tar.gz", "digest": "sha256:" + h}
                           for a, h in PANEL.items()]}),
            "https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.10.21": json.dumps({
                "assets": [{"name": "Xray-linux-" + a + ".zip", "digest": "sha256:" + h}
                           for a, h in CORE.items()]}),
            "https://raw.githubusercontent.com/MHSanaei/3x-ui/v3.11.0/install.sh": INSTALL,
            "https://raw.githubusercontent.com/MHSanaei/3x-ui/v3.11.0/x-ui.sh": MENU,
        }
        for a, h in CORE.items():
            self.responses["https://github.com/XTLS/Xray-core/releases/download/v26.10.21/"
                           "Xray-linux-" + a + ".zip.dgst"] = "SHA2-256= " + h + "\n"
        for a, h in PANEL.items():
            self.responses["https://github.com/MHSanaei/3x-ui/releases/download/v3.11.0/"
                           "x-ui-linux-" + a + ".tar.gz.sha256"] = h + "  archive.tar.gz\n"
        self.executable("git", "#!/bin/sh\nexit 0\n")
        self.executable("curl", "#!/usr/bin/env python3\n" + r'''
import json, os, sys
with open(os.environ["RELEASE_EVENTS"], "a") as f:
    f.write(json.dumps(["curl", sys.argv[-1]]) + "\n")
with open(os.environ["RELEASE_RESPONSES"]) as f:
    responses = json.load(f)
if sys.argv[-1] not in responses:
    raise SystemExit(22)
sys.stdout.write(responses[sys.argv[-1]])
''')
        self.executable("ssh-keygen", "#!/usr/bin/env python3\n" + r'''
import json, os, subprocess, sys
with open(os.environ["RELEASE_EVENTS"], "a") as f:
    f.write(json.dumps(["ssh-keygen", *sys.argv[1:]]) + "\n")
if sys.argv[1:2] != ["-lf"]:
    raise SystemExit("private-key/signing operation forbidden in fixture")
raise SystemExit(subprocess.run([os.environ["RELEASE_REAL_KEYGEN"], *sys.argv[1:]]).returncode)
''')

    def write(self, name, text):
        (self.root / name).write_text(text)

    def executable(self, name, content):
        self.write("bin/" + name, content)
        (self.root / "bin" / name).chmod(0o755)

    def set_signers(self, *keys):
        p = self.root / "scripts/kit.sh"
        before = p.read_text().split("KIT_SIGNERS=(", 1)[0]
        p.write_text(before + "KIT_SIGNERS=(\n" + "".join('  "' + key + '"\n' for key in keys) + ")\n")

    def calls(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []

    def run_release(self, *args):
        self.responses_file.write_text(json.dumps(self.responses))
        env = dict(os.environ, PATH=str(self.root / "bin") + os.pathsep + os.environ.get("PATH", ""),
                   RELEASE_EVENTS=str(self.events), RELEASE_RESPONSES=str(self.responses_file),
                   RELEASE_REAL_KEYGEN=REAL_KEYGEN, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run(["bash", str(self.root / "tools/release.sh"), *args], cwd=self.root,
                              env=env, text=True, capture_output=True, timeout=30)

    def assert_unsigned(self):
        self.assertFalse((self.root / "SHA256SUMS").exists())
        self.assertFalse((self.root / "SHA256SUMS.sig").exists())
        for call in self.calls():
            if call[0] == "ssh-keygen":
                self.assertEqual(call[1], "-lf", call)

    def assert_rejected_without_network(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(any(call[0] == "curl" for call in self.calls()))
        self.assert_unsigned()

    def test_placeholder_rejected_before_key_or_network(self):
        self.set_signers(PLACEHOLDER)
        result = self.run_release(str(self.root / "missing-private-key"))
        self.assert_rejected_without_network(result)
        self.assertIn("плейсхолдер", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_placeholder_cannot_hide_next_to_valid_public_key(self):
        self.set_signers(PUBLIC_KEY, PLACEHOLDER)
        self.assert_rejected_without_network(self.run_release("--check"))
        self.assertEqual(self.calls(), [])

    def test_empty_signers_rejected(self):
        self.set_signers()
        self.assert_rejected_without_network(self.run_release("--check"))

    def test_malformed_public_key_rejected_by_native_parser(self):
        self.set_signers("ssh-ed25519 AAAA malformed-public-fixture")
        self.assert_rejected_without_network(self.run_release("--check"))
        self.assertTrue(any(call[:2] == ["ssh-keygen", "-lf"] for call in self.calls()))

    def test_other_key_type_rejected(self):
        self.set_signers("ssh-rsa AAAA wrong-type")
        self.assert_rejected_without_network(self.run_release("--check"))

    def test_check_validates_both_official_sources_without_signing(self):
        result = self.run_release("--check", str(self.root / "never-read-private-key"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        urls = {call[1] for call in self.calls() if call[0] == "curl"}
        self.assertEqual(urls, set(self.responses))
        self.assert_unsigned()

    def test_duplicate_core_pins_must_match_before_network(self):
        p = self.root / "scripts/kit.sh"
        p.write_text(p.read_text().replace(CORE["64"], "b" * 64))
        self.assert_rejected_without_network(self.run_release("--check"))

    def test_git_status_failure_cannot_look_like_clean_files(self):
        self.executable("git", "#!/bin/sh\nexit 1\n")
        result = self.run_release("--check")
        self.assert_rejected_without_network(result)
        self.assertIn("git status", result.stderr)

    def test_uncommitted_release_files_rejected(self):
        self.executable("git", "#!/bin/sh\nprintf ' M scripts/kit.sh\\n'\n")
        result = self.run_release("--check")
        self.assert_rejected_without_network(result)
        self.assertIn("незакоммиченные", result.stderr)

    def test_sidecar_disagreement_rejected(self):
        url = "https://github.com/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-64.zip.dgst"
        self.responses[url] = "SHA2-256= " + "a" * 64 + "\n"
        result = self.run_release("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(".dgst", result.stderr)
        self.assert_unsigned()

    def test_github_digest_disagreement_rejected(self):
        url = "https://api.github.com/repos/MHSanaei/3x-ui/releases/tags/v3.11.0"
        data = json.loads(self.responses[url])
        data["assets"][0]["digest"] = "sha256:" + "a" * 64
        self.responses[url] = json.dumps(data)
        result = self.run_release("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GitHub digest", result.stderr)
        self.assert_unsigned()

    def test_missing_github_digest_rejected(self):
        url = "https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.10.21"
        data = json.loads(self.responses[url])
        data["assets"][0]["digest"] = None
        self.responses[url] = json.dumps(data)
        result = self.run_release("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("нет корректного SHA256", result.stderr)
        self.assert_unsigned()

    def test_changed_upstream_script_rejected(self):
        self.responses["https://raw.githubusercontent.com/MHSanaei/3x-ui/v3.11.0/install.sh"] += "echo changed\n"
        result = self.run_release("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("install.sh", result.stderr)
        self.assert_unsigned()

    def test_signing_mode_requires_owner_key_before_network(self):
        result = self.run_release(str(self.root / "missing-private-key"))
        self.assert_rejected_without_network(result)
        self.assertIn("Нет ключа владельца", result.stderr)


if __name__ == "__main__":
    unittest.main()
