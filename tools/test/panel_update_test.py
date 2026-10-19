"""Безопасные проверки панели: только функции со stub-командами и файлами в TemporaryDirectory.

python3 tools/test/panel_update_test.py (GNU bash, как на поддерживаемом сервере).
Официальные установщики, службы и сетевые команды не запускаются.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
INSTALL = (ROOT / "scripts/3x-ui.sh").read_text()
KIT = (ROOT / "scripts/kit.sh").read_text()


def function(src, name):
    return re.search(r"^%s\(\) \{.*?^\}\n" % name, src, re.S | re.M)[0]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def binary(version):
    return ('#!/usr/bin/env bash\nprintf "Xray %s\\n"\n' % version).encode()


STUBS = r'''
set -Eeuo pipefail
say() { echo "SAY: $*"; }
warn() { echo "WARN: $*"; }
die() { echo "DIE: $*"; exit 1; }
spin_start() { :; }; spin_stop() { :; }; sleep() { :; }
'''


class Sandbox(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.p = Path(self.tmp.name)

    def run_shell(self, script, **env):
        return subprocess.run(["bash", "-c", STUBS + script], cwd=self.p,
                              env=dict(os.environ, **{k: str(v) for k, v in env.items()}),
                              text=True, capture_output=True, timeout=15)


class Pins(unittest.TestCase):
    def test_same_panel_and_unchanged_core(self):
        self.assertIn('XUI_VERSION="v3.10.2"', INSTALL)
        self.assertIn('XUI_PIN="v3.10.2"', KIT)
        self.assertIn('XRAY_CORE="v26.6.27"', INSTALL)
        self.assertIn('XRAY_PIN="v26.6.27"', KIT)
        for sha in ('b3e5902d06d6282fe53cfa2fc426058b9aeaa429b2c812e20887cd47f26d08bf',
                    '13a251379bea366c2cf10363ad71e75734193d401f26f518bf0c25e5c8f8c931'):
            self.assertIn(sha, INSTALL)

    def test_restore_has_core_extraction_dependency(self):
        restore = function(INSTALL, "restore_main")
        packages = re.search(r"apt-get install -y -qq ([^\n>]+)", restore)[1].split()
        self.assertIn("unzip", packages)


class Health(Sandbox):
    def check(self, response):
        return self.run_shell(r'''
XUI_API_TOKEN=fixture; API=http://fixture
curl() { printf '%s' "$TEST_RESPONSE"; }
''' + function(KIT, "panel_healthy") + '\npanel_healthy\n', TEST_RESPONSE=json.dumps(response))

    def test_running_core(self):
        r = self.check({"success": True, "obj": {"xray": {"state": "running"}}})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_responding_panel_with_broken_core_is_not_healthy(self):
        for state in ("error", "stop", ""):
            self.assertNotEqual(self.check({"success": True, "obj": {"xray": {"state": state}}}).returncode, 0)

    def test_failed_auth_is_not_healthy(self):
        self.assertNotEqual(self.check({"success": False}).returncode, 0)


class FreshInstall(Sandbox):
    def prepare(self, arch="arm64", core="26.6.27", anchor=True):
        # Исполняется только этот короткий stub, с записью исключительно внутри self.p.
        self.installer = self.p / "upstream-stub.sh"
        self.installer.write_text('''#!/usr/bin/env bash
set -e
arch() { echo "$TEST_ARCH"; }
mkdir -p "$TEST_DEST/bin"
cd "$TEST_DEST"
printf '#!/usr/bin/env bash\\necho Xray 26.10.10\\n' > "bin/xray-linux-$(arch)"
chmod +x "bin/xray-linux-$(arch)"
config_after_install() {
  "bin/xray-linux-$(arch)" version > "$TEST_DEST/started-version"
}
''' + ('    config_after_install\n' if anchor else 'config_after_install\n'))
        self.zip = self.p / "core.zip"
        with zipfile.ZipFile(self.zip, "w") as z:
            f = zipfile.ZipInfo("xray")
            f.external_attr = 0o100755 << 16
            z.writestr(f, binary(core))
        self.dest = self.p / "destination"
        src = function(INSTALL, "install_xui").replace('/var/log/3x-ui-install.log', str(self.p / "install.log"))
        script = r'''
curl() { local out; while (($#)); do if [[ $1 == -o ]]; then out=$2; shift; fi; shift; done; cp "$TEST_INSTALLER" "$out"; }
xray_fetch_verified() { [[ $TEST_DOWNLOAD_FAIL != yes ]] || return 1; cp "$TEST_ZIP" "$1/xray.zip"; }
PANEL_SSL=none; HOST=127.0.0.1; XUI_REPO=MHSanaei/3x-ui; XUI_VERSION=v3.10.2; XRAY_CORE=v26.6.27
''' + src + '\ninstall_xui 12345 testpath user password\necho COMPLETE\n'
        return script, dict(TEST_ARCH=arch, TEST_INSTALLER=self.installer, TEST_ZIP=self.zip, TEST_DEST=self.dest,
                            TEST_DOWNLOAD_FAIL="no", XUI_INSTALL_SHA256=digest(self.installer.read_bytes()))

    def test_pinned_core_before_any_panel_start_both_arches(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch):
                script, env = self.prepare(arch=arch)
                r = self.run_shell(script, **env)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertEqual((self.dest / "started-version").read_text().strip(), "Xray 26.6.27")

    def test_refuse_bad_installer_checksum(self):
        script, env = self.prepare()
        env["XUI_INSTALL_SHA256"] = "0" * 64
        self.assert_refused(script, env)

    def test_refuse_unavailable_pinned_core(self):
        script, env = self.prepare()
        env["TEST_DOWNLOAD_FAIL"] = "yes"
        self.assert_refused(script, env)

    def test_refuse_wrong_core_version(self):
        self.assert_refused(*self.prepare(core="26.10.10"))

    def test_refuse_changed_installer_order(self):
        self.assert_refused(*self.prepare(anchor=False))

    def assert_refused(self, script, env):
        r = self.run_shell(script, **env)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("COMPLETE", r.stdout)
        self.assertFalse((self.dest / "started-version").exists())


class CoreFallback(Sandbox):
    def check(self, initial="26.10.10", api="no", fallback="no"):
        state = self.p / "state"
        state.write_text(initial)
        exe = self.p / "xray"
        exe.write_text('#!/usr/bin/env bash\necho "Xray $(cat "$TEST_STATE")"\n')
        exe.chmod(0o755)
        src = function(INSTALL, "set_xray_core").replace('/usr/local/x-ui/bin/xray-linux-*', '"$TEST_EXE"')
        script = r'''
XRAY_CORE=v26.6.27
api() { echo "$*"; [[ $TEST_API != yes ]] || echo 26.6.27 > "$TEST_STATE"; return 1; }
xray_install_fallback() { [[ $TEST_FALLBACK != yes ]] || echo 26.6.27 > "$TEST_STATE"; }
''' + src + '\nset_xray_core\necho COMPLETE\n'
        return self.run_shell(script, TEST_STATE=state, TEST_EXE=exe, TEST_API=api, TEST_FALLBACK=fallback)

    def test_failed_api_response_but_core_pinned(self):
        r = self.check(api="yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_verified_fallback(self):
        r = self.check(fallback="yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_no_success_with_bundled_core(self):
        r = self.check()
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("COMPLETE", r.stdout)

    def test_already_pinned(self):
        r = self.check(initial="26.6.27")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("WARN:", r.stdout)


class PanelUpdate(Sandbox):
    def prepare(self, arch="arm64", initial_core="26.6.27"):
        self.panel = self.p / "usr/local/x-ui"
        self.core = self.panel / ("bin/xray-linux-" + arch)
        self.core.parent.mkdir(parents=True)
        self.core.write_bytes(binary(initial_core))
        self.core.chmod(0o755)
        self.original = self.core.read_bytes()
        (self.core.parent / "custom.dat").write_text("custom data")
        (self.panel / "x-ui").write_text('#!/usr/bin/env bash\necho 3.9.0\n')
        (self.panel / "x-ui").chmod(0o755)
        for d in ("etc/x-ui", "etc/systemd/system", "usr/bin", "root"):
            (self.p / d).mkdir(parents=True, exist_ok=True)
        self.db = self.p / "etc/x-ui/x-ui.db"
        with sqlite3.connect(self.db) as db:
            db.execute("CREATE TABLE fixture (value TEXT)")
            db.execute("INSERT INTO fixture VALUES ('old settings')")
        (self.p / "etc/os-release").write_text("ID=debian\n")
        self.tar = self.p / "release.tar.gz"
        with tarfile.open(self.tar, "w:gz") as t:
            for name, data in (("x-ui/x-ui", b'#!/usr/bin/env bash\nif [[ $1 == -v ]]; then echo 3.10.2; fi\n'),
                               ("x-ui/bin/xray-linux-" + arch, binary("26.10.10")),
                               ("x-ui/bin/geosite.dat", b"new geosite"), ("x-ui/x-ui.service.debian", b"fixture unit")):
                f = tarfile.TarInfo(name)
                f.size = len(data)
                f.mode = 0o755
                t.addfile(f, io.BytesIO(data))
        menu = self.p / "menu.sh"
        menu.write_text("# fixture menu\n")
        src = function(KIT, "panel_update")
        # Все абсолютные пути и команды управления хостом заменены до выполнения.
        for prefix in ("/usr/local/x-ui", "/etc/systemd/system", "/etc/x-ui", "/usr/bin", "/root", "/etc/os-release"):
            src = src.replace(prefix, str(self.p) + prefix)
        script = r'''
XUI_PIN=v3.10.2; XUI_API_TOKEN=fixture; API=fixture; B=; N=
declare -A XUI_TARBALL_SHA256=([$TEST_ARCH]="$TEST_SHA")
XUI_SH_SHA256=$TEST_MENU_SHA
uname() { [[ $TEST_ARCH == amd64 ]] && echo x86_64 || echo aarch64; }
newer() { return 1; }
curl() {
  local out url=${!#}
  echo "$url" >> "$TEST_URLS"
  while (($#)); do if [[ $1 == -o ]]; then out=$2; shift; fi; shift; done
  case $url in *.tar.gz) cp "$TEST_TAR" "$out" ;; */x-ui.sh) cp "$TEST_MENU" "$out" ;; *) return 1 ;; esac
}
deep_probe() { [[ $TEST_POST_FAIL != yes || $("$TEST_PANEL/x-ui" -v) != 3.10.2 ]]; }
panel_healthy() { [[ $TEST_HEALTH_FAIL != yes ]]; }
xray_version() { "$TEST_CORE" version | awk 'NR==1 {print "v" $2}'; }
chown() { :; }; pkill() { :; }
systemctl() {
  echo "$*" >> "$TEST_EVENTS"
  if [[ $1 == start && $("$TEST_PANEL/x-ui" -v) == 3.10.2 ]]; then
    if [[ $TEST_CORRUPT == yes ]]; then echo corrupted > "$TEST_CORE"; fi
    if [[ $TEST_NEW_WAL == yes ]]; then
      echo stale > "$TEST_DB-wal"; echo stale > "$TEST_DB-shm"
    fi
    [[ $TEST_START_FAIL != yes ]] || return 1
  fi
}
python3() {
  if [[ $TEST_SNAPSHOT_WRITE == yes ]]; then
    command python3 -c 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute("INSERT INTO fixture VALUES (?)", ("committed before SQLite snapshot",)); c.commit(); c.close()' "$TEST_DB"
  fi
  command python3 "$@"
}
''' + src + '\npanel_update\necho COMPLETE\n'
        return script, dict(TEST_ARCH=arch, TEST_SHA=digest(self.tar.read_bytes()), TEST_TAR=self.tar,
                            TEST_MENU=menu, TEST_MENU_SHA=digest(menu.read_bytes()), TEST_PANEL=self.panel,
                            TEST_CORE=self.core, TEST_URLS=self.p / "urls", TEST_EVENTS=self.p / "events",
                            TEST_CORRUPT="no", TEST_POST_FAIL="no", TEST_HEALTH_FAIL="no", TEST_START_FAIL="no",
                            TEST_SNAPSHOT_WRITE="no", TEST_NEW_WAL="no", TEST_DB=self.db)

    def test_preserve_exact_core_and_custom_assets_both_arches(self):
        script, env = self.prepare()
        r = self.run_shell(script, **env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.core.read_bytes(), self.original)
        self.assertEqual((self.core.parent / "custom.dat").read_text(), "custom data")
        self.assertNotIn("install.sh", (self.p / "urls").read_text())
        self.assertIn("v26.6.27", r.stdout)

    def test_amd64_custom_core_is_preserved_instead_of_replaced_with_pin(self):
        script, env = self.prepare(arch="amd64", initial_core="26.6.1")
        r = self.run_shell(script, **env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.core.read_bytes(), self.original)
        self.assertIn("v26.6.1", r.stdout)

    def test_bad_archive_sha_leaves_installation_untouched(self):
        script, env = self.prepare()
        env["TEST_SHA"] = "0" * 64
        r = self.run_shell(script, **env)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse((self.p / "events").exists())
        self.assertEqual(self.core.read_bytes(), self.original)

    def test_bad_menu_sha_leaves_installation_untouched(self):
        script, env = self.prepare()
        env["TEST_MENU_SHA"] = "0" * 64
        r = self.run_shell(script, **env)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse((self.p / "events").exists())
        self.assertEqual(self.core.read_bytes(), self.original)

    def test_rollback_on_core_change_health_or_connectivity_failure(self):
        # Каждый сценарий получает отдельную копию установки.
        for key in ("TEST_CORRUPT", "TEST_POST_FAIL", "TEST_HEALTH_FAIL", "TEST_START_FAIL"):
            with self.subTest(failure=key), tempfile.TemporaryDirectory() as d:
                old_p, self.p = self.p, Path(d)
                try:
                    script, env = self.prepare()
                    env[key] = "yes"
                    r = self.run_shell(script, **env)
                    self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                    self.assertIn("восстановлена", r.stdout)
                    self.assertEqual(self.core.read_bytes(), self.original)
                    self.assertEqual(subprocess.check_output([self.panel / "x-ui", "-v"], text=True).strip(), "3.9.0")
                    with sqlite3.connect(self.db) as db:
                        self.assertEqual(db.execute("SELECT value FROM fixture").fetchone()[0], "old settings")
                finally:
                    self.p = old_p

    def test_rollback_uses_sqlite_snapshot_and_discards_new_wal(self):
        script, env = self.prepare()
        env.update(TEST_SNAPSHOT_WRITE="yes", TEST_NEW_WAL="yes", TEST_START_FAIL="yes")
        r = self.run_shell(script, **env)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("восстановлена", r.stdout)
        self.assertFalse(Path(str(self.db) + "-wal").exists())
        self.assertFalse(Path(str(self.db) + "-shm").exists())
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT value FROM fixture ORDER BY rowid").fetchall(),
                             [("old settings",), ("committed before SQLite snapshot",)])


if __name__ == "__main__":
    unittest.main()
