"""Безопасные проверки панели: только функции со stub-командами и файлами в TemporaryDirectory.

python3 tools/test/panel_update_test.py (GNU Bash/sed, как на поддерживаемом сервере).
KIT_TEST_BASH задаёт Bash явно. В fixture macOS Bash 3.2 два фиксированных ключа
таблицы SHA представлены indexed array; CI проверяет настоящую associative array.
Это не поддержка macOS самим KIT. Недоступные GNU sed-сценарии отмечаются skipped.
Официальные установщики, службы и сетевые команды не запускаются.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
INSTALL = (ROOT / "scripts/3x-ui.sh").read_text()
KIT = (ROOT / "scripts/kit.sh").read_text()


def select_bash():
    requested = os.environ.get("KIT_TEST_BASH")
    if requested:
        resolved = shutil.which(requested)
        if not resolved:
            raise RuntimeError("KIT_TEST_BASH не найден: " + requested)
        return resolved
    preferred = Path("/opt/homebrew/bin/bash")
    if preferred.is_file() and os.access(preferred, os.X_OK):
        return str(preferred)
    return shutil.which("bash") or "/bin/bash"


BASH = select_bash()
SED = shutil.which("sed")
HAS_GNU_SED = bool(SED) and b"GNU sed" in subprocess.run(
    [SED, "--version"], capture_output=True).stdout
GNU_SED_REASON = "требуется GNU sed: install_xui использует sed -i"


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
        return subprocess.run([BASH, "-c", STUBS + script], cwd=self.p,
                              env=dict(os.environ, **{k: str(v) for k, v in env.items()}),
                              text=True, capture_output=True, timeout=15)


class Pins(unittest.TestCase):
    def test_release_panel_and_core_pins(self):
        self.assertIn('KIT_VERSION="1.3.0"', INSTALL)
        self.assertIn('KIT_VERSION="1.3.0"', KIT)
        self.assertEqual((ROOT / "VERSION").read_text().strip(), "1.3.0")
        self.assertIn('XUI_VERSION="v3.11.0"', INSTALL)
        self.assertIn('XUI_PIN="v3.11.0"', KIT)
        self.assertIn('XRAY_CORE="v26.10.21"', INSTALL)
        self.assertIn('XRAY_PIN="v26.10.21"', KIT)
        self.assertIn('9684bae4f769b2127fcceceb4f200045657381311867529e6ba76c6b58e2825d', INSTALL)
        for sha in ('0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978',
                    'd1304946c486d98e6b886e9b931eaaaebb23835b30e217638037b7f2721d4e9c'):
            for src in (INSTALL, KIT):
                self.assertIn(sha, src)
        for sha in ('0ddfa4702f595442e2962acd81addc768fdacaa4ff2672c971a0463dae744916',
                    'f50b4c30fd919d018f2f4c3d8db53a4ca027503d581328727770afb116a79d90',
                    '26c229d5fb3b184e81581b4b223b801582ca7cf5908aaedeb8d1c7c70ad4cc25'):
            self.assertIn(sha, KIT)

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
    def prepare(self, arch="arm64", core="26.10.21", anchor=True):
        # Исполняется только этот короткий stub, с записью исключительно внутри self.p.
        self.installer = self.p / "upstream-stub.sh"
        self.installer.write_text('''#!/usr/bin/env bash
set -e
arch() { echo "$TEST_ARCH"; }
mkdir -p "$TEST_DEST/bin"
cd "$TEST_DEST"
printf '#!/usr/bin/env bash\\necho Xray 26.10.21\\n' > "bin/xray-linux-$(arch)"
chmod +x "bin/xray-linux-$(arch)"
config_after_install() {
  "bin/xray-linux-$(arch)" version > "$TEST_DEST/started-version"
  cp "bin/xray-linux-$(arch)" "$TEST_DEST/started-core"
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
PANEL_SSL=none; HOST=127.0.0.1; XUI_REPO=MHSanaei/3x-ui; XUI_VERSION=v3.11.0; XRAY_CORE=v26.10.21
''' + src + '\ninstall_xui 12345 testpath user password\necho COMPLETE\n'
        return script, dict(TEST_ARCH=arch, TEST_INSTALLER=self.installer, TEST_ZIP=self.zip, TEST_DEST=self.dest,
                            TEST_DOWNLOAD_FAIL="no", XUI_INSTALL_SHA256=digest(self.installer.read_bytes()))

    @unittest.skipUnless(HAS_GNU_SED, GNU_SED_REASON)
    def test_pinned_core_before_any_panel_start_both_arches(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch):
                script, env = self.prepare(arch=arch)
                r = self.run_shell(script, **env)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertEqual((self.dest / "started-version").read_text().strip(), "Xray 26.10.21")
                self.assertEqual((self.dest / "started-core").read_bytes(), binary("26.10.21"))

    def test_refuse_bad_installer_checksum(self):
        script, env = self.prepare()
        env["XUI_INSTALL_SHA256"] = "0" * 64
        self.assert_refused(script, env)

    def test_refuse_unavailable_pinned_core(self):
        script, env = self.prepare()
        env["TEST_DOWNLOAD_FAIL"] = "yes"
        self.assert_refused(script, env)

    @unittest.skipUnless(HAS_GNU_SED, GNU_SED_REASON)
    def test_refuse_wrong_core_version(self):
        self.assert_refused(*self.prepare(core="26.6.27"))

    def test_refuse_changed_installer_order(self):
        self.assert_refused(*self.prepare(anchor=False))

    def assert_refused(self, script, env):
        r = self.run_shell(script, **env)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("COMPLETE", r.stdout)
        self.assertFalse((self.dest / "started-version").exists())


class CoreFallback(Sandbox):
    def check(self, initial="26.6.27", api="no", fallback="no"):
        state = self.p / "state"
        state.write_text(initial)
        exe = self.p / "xray"
        exe.write_text('#!/usr/bin/env bash\necho "Xray $(cat "$TEST_STATE")"\n')
        exe.chmod(0o755)
        src = function(INSTALL, "set_xray_core").replace('/usr/local/x-ui/bin/xray-linux-*', '"$TEST_EXE"')
        script = r'''
XRAY_CORE=v26.10.21
api() { echo "$*"; [[ $TEST_API != yes ]] || echo 26.10.21 > "$TEST_STATE"; return 1; }
xray_install_fallback() { [[ $TEST_FALLBACK != yes ]] || echo 26.10.21 > "$TEST_STATE"; }
''' + src + '\nset_xray_core\necho COMPLETE\n'
        return self.run_shell(script, TEST_STATE=state, TEST_EXE=exe, TEST_API=api, TEST_FALLBACK=fallback)

    def test_failed_api_response_but_core_pinned(self):
        r = self.check(api="yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_verified_fallback(self):
        r = self.check(fallback="yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_no_success_with_old_core(self):
        r = self.check()
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("COMPLETE", r.stdout)

    def test_already_pinned(self):
        r = self.check(initial="26.10.21")
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
        (self.panel / "x-ui").write_text('#!/usr/bin/env bash\necho 3.10.2\n')
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
            for name, data in (("x-ui/x-ui", b'''#!/usr/bin/env bash
if [[ $1 == -v ]]; then
  echo 3.11.0
elif [[ $1 == migrate ]]; then
  echo 'migrate panel=3.11.0' >> "$TEST_EVENTS"
  if [[ $TEST_MIGRATE_FAIL == yes ]]; then
    python3 - "$TEST_DB" <<'PY'
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as db:
    db.execute("UPDATE fixture SET value = 'partial migration'")
PY
    echo stale > "$TEST_DB-wal"; echo stale > "$TEST_DB-shm"
    exit 1
  fi
fi
'''),
                               ("x-ui/bin/xray-linux-" + arch, binary("26.10.21")),
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
XUI_PIN=v3.11.0; XUI_API_TOKEN=fixture; API=fixture; B=; N=
if ((BASH_VERSINFO[0] >= 4)); then
  declare -A XUI_TARBALL_SHA256=([$TEST_ARCH]="$TEST_SHA")
else
  # Fixture only: arithmetic array indexing resolves these two fixed arch names.
  amd64=0; arm64=1
  declare -a XUI_TARBALL_SHA256=("$TEST_SHA" "$TEST_SHA")
fi
XUI_SH_SHA256=$TEST_MENU_SHA
uname() { [[ $TEST_ARCH == amd64 ]] && echo x86_64 || echo aarch64; }
newer() { return 1; }
curl() {
  local out url=${!#}
  echo "$url" >> "$TEST_URLS"
  while (($#)); do if [[ $1 == -o ]]; then out=$2; shift; fi; shift; done
  case $url in *.tar.gz) cp "$TEST_TAR" "$out" ;; */x-ui.sh) cp "$TEST_MENU" "$out" ;; *) return 1 ;; esac
}
deep_probe() { [[ $TEST_POST_FAIL != yes || $("$TEST_PANEL/x-ui" -v) != 3.11.0 ]]; }
panel_healthy() { [[ $TEST_HEALTH_FAIL != yes || $("$TEST_PANEL/x-ui" -v) != 3.11.0 ]]; }
tuic_subscription_healthy() { [[ $TEST_TUIC_FAIL != yes ]]; }
update_lock() { :; }
xray_version() { "$TEST_CORE" version | awk 'NR==1 {print "v" $2}'; }
chown() { :; }; pkill() { :; }
systemctl() {
  echo "$* panel=$("$TEST_PANEL/x-ui" -v)" >> "$TEST_EVENTS"
  if [[ $1 == start && $("$TEST_PANEL/x-ui" -v) == 3.11.0 ]]; then
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
                            TEST_SNAPSHOT_WRITE="no", TEST_NEW_WAL="no", TEST_DB=self.db,
                            TEST_MIGRATE_FAIL="no", TEST_TUIC_FAIL="no")

    def test_preserve_exact_core_and_custom_assets_both_arches(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as d:
                old_p, self.p = self.p, Path(d)
                try:
                    script, env = self.prepare(arch=arch)
                    r = self.run_shell(script, **env)
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                    self.assertEqual(self.core.read_bytes(), self.original)
                    self.assertEqual((self.core.parent / "custom.dat").read_text(), "custom data")
                    self.assertNotIn("install.sh", (self.p / "urls").read_text())
                    self.assertIn("v26.6.27", r.stdout)
                    self.assertEqual(subprocess.check_output([self.panel / "x-ui", "-v"], text=True).strip(), "3.11.0")
                finally:
                    self.p = old_p

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

    def test_backup_failure_refuses_update_even_in_menu_conditional(self):
        script, env = self.prepare()
        cp_stub = r'''
cp() {
  [[ ${!#} != */usr-local-x-ui ]] || return 1
  command cp "$@"
}
'''
        script = script.replace('\npanel_update\n', cp_stub + '\n( panel_update ) || true\n')
        r = self.run_shell(script, **env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Сервер не тронут", r.stdout)
        self.assertFalse((self.p / "events").exists())
        self.assertEqual(self.core.read_bytes(), self.original)
        self.assertEqual(subprocess.check_output([self.panel / "x-ui", "-v"], text=True).strip(), "3.10.2")

    def test_asset_copy_failure_restores_old_panel_without_migrating(self):
        script, env = self.prepare()
        cp_stub = r'''
cp() {
  [[ $1 != -af || $2 != */x-ui/bin/geosite.dat ]] || return 1
  command cp "$@"
}
'''
        script = script.replace('\npanel_update\n', cp_stub + '\npanel_update\n')
        r = self.run_shell(script, **env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("восстановлена", r.stdout)
        self.assertEqual(self.core.read_bytes(), self.original)
        self.assertEqual(subprocess.check_output([self.panel / "x-ui", "-v"], text=True).strip(), "3.10.2")
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT value FROM fixture").fetchone()[0], "old settings")

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
                    self.assertEqual(subprocess.check_output([self.panel / "x-ui", "-v"], text=True).strip(), "3.10.2")
                    with sqlite3.connect(self.db) as db:
                        self.assertEqual(db.execute("SELECT value FROM fixture").fetchone()[0], "old settings")
                finally:
                    self.p = old_p

    def test_migrate_failure_restores_snapshot_without_starting_new_panel(self):
        script, env = self.prepare()
        env["TEST_MIGRATE_FAIL"] = "yes"
        r = self.run_shell(script, **env)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("восстановлена", r.stdout)
        self.assertEqual(self.core.read_bytes(), self.original)
        self.assertEqual(subprocess.check_output([self.panel / "x-ui", "-v"], text=True).strip(), "3.10.2")
        events = (self.p / "events").read_text()
        self.assertIn("migrate panel=3.11.0", events)
        self.assertNotIn("start x-ui panel=3.11.0", events)
        self.assertIn("start x-ui panel=3.10.2", events)
        self.assertFalse(Path(str(self.db) + "-wal").exists())
        self.assertFalse(Path(str(self.db) + "-shm").exists())
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT value FROM fixture").fetchone()[0], "old settings")

    def test_tuic_subscription_failure_rolls_back_responding_panel(self):
        script, env = self.prepare()
        env["TEST_TUIC_FAIL"] = "yes"
        r = self.run_shell(script, **env)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("восстановлена", r.stdout)
        self.assertEqual(self.core.read_bytes(), self.original)
        self.assertEqual(subprocess.check_output([self.panel / "x-ui", "-v"], text=True).strip(), "3.10.2")

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
