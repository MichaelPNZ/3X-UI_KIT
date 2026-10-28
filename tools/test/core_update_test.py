"""Транзакционное обновление ядра: настоящие файлы/unzip, службы и сеть заменены stubs."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "scripts/kit.sh").read_text()
BASH = os.environ.get("KIT_TEST_BASH") or (
    "/opt/homebrew/bin/bash" if Path("/opt/homebrew/bin/bash").is_file() else shutil.which("bash"))


def function(name):
    return re.search(r"^%s\(\) \{.*?^\}\n" % name, SOURCE, re.M | re.S)[0]


def binary(version):
    return ('#!/usr/bin/env bash\nprintf "Xray %s\\n"\n' % version).encode()


class CoreUpdate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.p = Path(self.temp.name)

    def prepare(self, arch="arm64", current="26.6.27", candidate="26.10.21"):
        panel = self.p / "usr/local/x-ui"
        self.core = panel / ("bin/xray-linux-" + arch)
        self.core.parent.mkdir(parents=True, exist_ok=True)
        self.core.write_bytes(binary(current))
        self.core.chmod(0o755)
        self.original = self.core.read_bytes()
        self.config = self.core.parent / "config.json"
        self.config.write_text('{"fixture":"working config"}')
        self.database = self.p / "untouched.db"
        self.database.write_bytes(b"existing SQLite is outside a core-only update")
        (self.p / "root").mkdir(exist_ok=True)
        self.archive = self.p / "candidate.zip"
        with zipfile.ZipFile(self.archive, "w") as z:
            z.writestr("xray", binary(candidate))
        self.events = self.p / "events"
        self.events.unlink(missing_ok=True)
        helpers = "\n".join(function(n) for n in ("core_restore", "core_update_abort", "core_update"))
        for prefix in ("/usr/local/x-ui", "/root"):
            helpers = helpers.replace(prefix, str(self.p) + prefix)
        stubs = r'''
set -Eeuo pipefail
say() { printf 'SAY: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*"; }
die() { printf 'DIE: %s\n' "$*"; exit 1; }
update_lock() { :; }
newer() { [[ $TEST_NEWER == yes ]]; }
uname() { [[ $TEST_ARCH == amd64 ]] && echo x86_64 || echo aarch64; }
xray_version() { "$TEST_CORE" version | awk 'NR==1 {print "v" $2}'; }
xray_fetch_verified() {
  echo "fetch $2" >> "$TEST_EVENTS"
  [[ $TEST_DOWNLOAD_FAIL != yes ]] || return 1
  cp "$TEST_ARCHIVE" "$1/xray.zip"
}
core_config_test() {
  echo test >> "$TEST_EVENTS"
  [[ $TEST_CONFIG_FAIL != yes ]] || return 1
  [[ $TEST_FROZEN_FAIL != yes || $2 != *config.frozen* && $2 != *xray-before-update* ]]
}
deep_probe() {
  [[ $TEST_PROBE_FAIL != yes || $(xray_version) != v26.10.21 ]]
}
panel_healthy() { [[ $TEST_HEALTH_FAIL != yes || $(xray_version) != v26.10.21 ]]; }
tuic_subscription_healthy() { [[ $TEST_TUIC_FAIL != yes ]]; }
systemctl() {
  echo "$*" >> "$TEST_EVENTS"
  if [[ $1 == start && $(xray_version) == v26.10.21 ]]; then
    if [[ $TEST_SIGNAL == yes ]]; then kill -TERM $$; fi
    if [[ $TEST_START_FAIL == yes ]]; then return 1; fi
    if [[ $TEST_CORRUPT == yes ]]; then printf 'corrupted\n' > "$TEST_CORE"; fi
  fi
}
install() {
  if [[ $TEST_BACKUP_FAIL == yes && ${!#} == *xray-before-update*/xray ]]; then return 1; fi
  if [[ $TEST_SECOND_SIGNAL == yes && $* == *xray-before-update*/xray* ]]; then
    # Только восстановление из копии, не создание копии перед stop.
    for arg in "$@"; do
      if [[ $arg == *xray-before-update*/xray && $arg != "${!#}" ]]; then kill -TERM $$; fi
    done
  fi
  command install "$@"
}
'''
        env = dict(os.environ, TEST_ARCH=arch, TEST_CORE=str(self.core), TEST_ARCHIVE=str(self.archive),
                   TEST_EVENTS=str(self.events), TEST_NEWER="no", TEST_DOWNLOAD_FAIL="no", TEST_CONFIG_FAIL="no",
                   TEST_FROZEN_FAIL="no", TEST_HEALTH_FAIL="no", TEST_TUIC_FAIL="no", TEST_START_FAIL="no",
                   TEST_PROBE_FAIL="no", TEST_CORRUPT="no", TEST_BACKUP_FAIL="no", TEST_SIGNAL="no",
                   TEST_SECOND_SIGNAL="no")
        return stubs + "\nXRAY_PIN=v26.10.21\n" + helpers, env

    def run_case(self, code, env, invoke="core_update"):
        return subprocess.run([BASH, "-c", code + "\n" + invoke + "\necho COMPLETE\n"],
                              cwd=self.p, env=env, text=True, capture_output=True, timeout=15)

    def assert_old(self):
        self.assertEqual(self.core.read_bytes(), self.original)
        self.assertEqual(self.config.read_text(), '{"fixture":"working config"}')
        self.assertEqual(self.database.read_bytes(), b"existing SQLite is outside a core-only update")

    def test_both_architectures_update_and_keep_restorable_backup(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as d:
                old = self.p
                self.p = Path(d)
                try:
                    code, env = self.prepare(arch=arch)
                    r = self.run_case(code, env)
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                    self.assertEqual(self.core.read_bytes(), binary("26.10.21"))
                    backups = list((self.p / "root").glob("xray-before-update-*"))
                    self.assertEqual(len(backups), 1)
                    self.assertEqual((backups[0] / "xray").read_bytes(), self.original)
                    self.assertEqual((backups[0] / "config.json").read_bytes(), self.config.read_bytes())
                    events = self.events.read_text()
                    self.assertIn("fetch " + ("64" if arch == "amd64" else "arm64-v8a"), events)
                    self.assertLess(events.index("fetch"), events.index("stop x-ui"))
                finally:
                    self.p = old

    def test_preflight_failures_do_not_stop_service(self):
        for flag in ("TEST_DOWNLOAD_FAIL", "TEST_CONFIG_FAIL"):
            with self.subTest(flag=flag):
                code, env = self.prepare()
                self.events.unlink(missing_ok=True)
                env[flag] = "yes"
                r = self.run_case(code, env)
                self.assertNotEqual(r.returncode, 0)
                self.assertNotIn("stop x-ui", self.events.read_text())
                self.assert_old()

    def test_wrong_binary_version_is_rejected_before_stop(self):
        code, env = self.prepare(candidate="26.9.9")
        r = self.run_case(code, env)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("stop x-ui", self.events.read_text())
        self.assert_old()

    def test_backup_failure_is_safe_even_from_menu_conditional(self):
        code, env = self.prepare()
        env["TEST_BACKUP_FAIL"] = "yes"
        r = self.run_case(code, env, "( core_update ) || true")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("копию", r.stdout)
        self.assertNotIn("stop x-ui", self.events.read_text())
        self.assert_old()

    def test_start_health_tuic_config_probe_and_hash_failures_restore(self):
        for flag in ("TEST_START_FAIL", "TEST_HEALTH_FAIL", "TEST_TUIC_FAIL", "TEST_FROZEN_FAIL",
                     "TEST_PROBE_FAIL", "TEST_CORRUPT"):
            with self.subTest(flag=flag):
                code, env = self.prepare()
                env[flag] = "yes"
                r = self.run_case(code, env)
                self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("восстановлены", r.stdout)
                self.assert_old()

    def test_signal_after_replacement_restores_even_with_repeated_signal(self):
        code, env = self.prepare()
        env.update(TEST_SIGNAL="yes", TEST_SECOND_SIGNAL="yes")
        r = self.run_case(code, env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Прежнее ядро восстановлено", r.stdout + r.stderr)
        self.assert_old()

    def test_already_pinned_skips_download_and_stop(self):
        code, env = self.prepare(current="26.10.21")
        r = self.run_case(code, env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(self.events.exists())

    def test_newer_custom_core_requires_force(self):
        code, env = self.prepare(current="27.1.1")
        env["TEST_NEWER"] = "yes"
        r = self.run_case(code, env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--force", r.stdout)
        self.assert_old()


class ArchiveVerification(unittest.TestCase):
    def test_actual_fetch_rejects_bad_sha_and_accepts_matching_sha(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            archive = p / "input.zip"
            archive.write_bytes(b"fixture official archive")
            for correct in (True, False):
                want = hashlib.sha256(archive.read_bytes()).hexdigest() if correct else "0" * 64
                code = '''set -Eeuo pipefail
warn() { :; }
XRAY_PIN=v26.10.21
XRAY_MIRRORS=(https://fixture)
XRAY_ZIP_SHA256[64]=$TEST_SHA
curl() { local out; while (($#)); do if [[ $1 == -o ]]; then out=$2; shift; fi; shift; done; cp "$TEST_INPUT" "$out"; }
''' + function("xray_fetch_verified") + '\nxray_fetch_verified "$TEST_DIR" 64\n'
                r = subprocess.run([BASH, "-c", code], env=dict(os.environ, TEST_SHA=want,
                                   TEST_INPUT=str(archive), TEST_DIR=d), capture_output=True, text=True, timeout=5)
                self.assertEqual(r.returncode == 0, correct, r.stdout + r.stderr)


class ConfigPaths(unittest.TestCase):
    def test_preflight_keeps_executable_relative_lua_and_asset_paths(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            panel = p / "panel"
            assets = panel / "bin"
            assets.mkdir(parents=True)
            (assets / "noise.lua").write_text("-- fixture Lua beside installed executable")
            cfg = assets / "config.json"
            cfg.write_text("{}")
            candidate = p / "downloaded-xray"
            candidate.write_text('''#!/usr/bin/env python3
from pathlib import Path
import os
assert (Path(__file__).parent / "noise.lua").is_file()
assert Path.cwd().resolve() == Path(__file__).resolve().parent.parent
assert Path(os.environ["XRAY_LOCATION_ASSET"]).resolve() == Path(__file__).resolve().parent
''')
            candidate.chmod(0o755)
            code = function("core_config_test").replace("/usr/local/x-ui", str(panel))
            code += '\ncore_config_test "$TEST_BINARY" "$TEST_CONFIG"\n'
            r = subprocess.run([BASH, "-c", code], env=dict(os.environ, TEST_BINARY=str(candidate),
                               TEST_CONFIG=str(cfg)), capture_output=True, text=True, timeout=5)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(list(assets.glob(".kit-xray-check.*")), [])


if __name__ == "__main__":
    unittest.main()
