#!/usr/bin/env bash
# Проверка и подпись релиза самостоятельного форка. Запускает только владелец:
#
#   tools/release.sh --check                 # без приватного ключа и файлов подписи
#   tools/release.sh [~/.ssh/3x-ui-kit-release]
#
# KIT_SIGNERS сначала проверяются как публичные ed25519-ключи. Плейсхолдер запрещает
# даже сетевую проверку. Обычный запуск после всех проверок читает ключ владельца,
# создаёт SHA256SUMS и подписывает его; приватный ключ никуда не отправляется.

set -euo pipefail
umask 077
cd "$(dirname "$0")/.."

die() { printf '✗  %s\n' "$*" >&2; exit 1; }
ok() { printf '✓  %s\n' "$*"; }
sha() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
get() {
  curl -fsSL --connect-timeout 15 --max-time 120 --retry 5 --retry-all-errors --retry-delay 3 "$1" \
    || { printf '✗  Не скачалось с GitHub: %s\n' "$1" >&2; return 1; }
}
signers() {
  awk '/^KIT_SIGNERS=\(/ {on = 1; next} on && /^\)/ {exit} on && /^ *"/ {sub(/^ *"/, ""); sub(/" *$/, ""); print}' "$1"
}
map_hash() { # файл имя-массива ключ; исходники не исполняются
  awk -v declaration="declare -A $2=(" -v key="[$3]=" '
    $0 == declaration {inside = 1; next}
    inside && /^\)/ {exit}
    inside && index($1, key) == 1 {print substr($1, length(key) + 1)}' "$1"
}
valid_sha() { [[ $1 =~ ^[0-9a-f]{64}$ ]]; }
asset_digest() { # JSON релиза, точное имя файла
  python3 - "$1" "$2" <<'PY'
import json, re, sys
with open(sys.argv[1], encoding="utf-8") as f:
    release = json.load(f)
assets = release.get("assets", [])
found = [a for a in assets if isinstance(a, dict) and a.get("name") == sys.argv[2]]
if len(found) != 1:
    raise SystemExit("GitHub release: ожидается ровно один asset " + sys.argv[2])
digest = found[0].get("digest", "")
if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit("GitHub release: нет корректного SHA256 digest для " + sys.argv[2])
print(digest.removeprefix("sha256:"))
PY
}

check_only=no
if [[ ${1:-} == --check ]]; then check_only=yes; shift; fi
(($# <= 1)) || die "Использование: tools/release.sh [--check] [путь-к-ключу]"
[[ ${1:-} != --* ]] || die "Неизвестный параметр: $1"
key=${1:-$HOME/.ssh/3x-ui-kit-release}
NS="3x-ui-kit-release"
ID="releases@3x-ui-kit"
FILES=(scripts/3x-ui.sh scripts/hysteria2.sh scripts/kit.sh scripts/kit-sub.py VERSION)

# До сети и любых операций с приватным ключом: только публичные строки доверия.
release_signers=$(signers scripts/kit.sh)
[[ -n $release_signers ]] || die "KIT_SIGNERS пуст: владелец должен добавить свой публичный ed25519-ключ."
[[ $release_signers != *REPLACE_WITH_* && $release_signers != *PLACEHOLDER* ]] \
  || die "KIT_SIGNERS содержит плейсхолдер. Сначала замените его публичным ed25519-ключом владельца форка."
command -v ssh-keygen >/dev/null || die "Для проверки публичного ключа нужен ssh-keygen."
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
: >"$work/allowed_signers"
while IFS= read -r signer; do
  [[ $signer =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]].*)?$ ]] \
    || die "KIT_SIGNERS: разрешены только полные публичные ssh-ed25519-ключи."
  printf '%s\n' "$signer" >"$work/public_key"
  ssh-keygen -lf "$work/public_key" >/dev/null 2>&1 || die "KIT_SIGNERS: некорректный публичный ed25519-ключ."
  printf '%s namespaces="%s" %s\n' "$ID" "$NS" "$signer" >>"$work/allowed_signers"
done <<<"$release_signers"
if [[ $check_only == no ]]; then
  [[ -f $key ]] || die "Нет ключа владельца: $key. Порядок подготовки: manuals/release.md."
fi
ok "Публичные ключи форка корректны; ключ оригинального проекта не используется"

v=$(tr -d '[:space:]' <VERSION)
[[ $v =~ ^[0-9]+(\.[0-9]+)+$ ]] || die "VERSION: $v"
for f in scripts/3x-ui.sh scripts/hysteria2.sh scripts/kit.sh; do
  grep -Fxq "KIT_VERSION=\"$v\"" "$f" || die "$f: KIT_VERSION не $v"
done
grep -qE "^## v${v//./\\.}([: ]|$)" CHANGELOG.md || die "В CHANGELOG.md нет раздела ## v$v"
for f in README.md manuals/3x-ui.md; do
  grep -Fq "https://raw.githubusercontent.com/MichaelPNZ/3X-UI_KIT/v${v}/scripts/3x-ui.sh" "$f" \
    || die "$f: команда установки не закреплена за тегом форка v$v"
done
release_status=$(git status --porcelain -- "${FILES[@]}" CHANGELOG.md README.md NOTICE.md manuals tools/release.sh .github/workflows) \
  || die "Не удалось проверить git status файлов выпуска."
[[ -z $release_status ]] \
  || die "Есть незакоммиченные изменения в файлах выпуска: сначала проверка и коммит владельцем."
ok "Версия $v и ссылки форка согласованы; файлы выпуска чистые"

xv=$(sed -n 's/^XUI_VERSION="\(.*\)"/\1/p' scripts/3x-ui.sh)
xc=$(sed -n 's/^XRAY_CORE="\(.*\)"/\1/p' scripts/3x-ui.sh)
kp=$(sed -n 's/^XUI_PIN="\(.*\)"/\1/p' scripts/kit.sh)
kx=$(sed -n 's/^XRAY_PIN="\(.*\)"/\1/p' scripts/kit.sh)
[[ $xv =~ ^v[0-9]+(\.[0-9]+)+$ && $xc =~ ^v[0-9]+(\.[0-9]+)+$ ]] || die "Некорректные теги панели или Xray."
[[ $kp == "$xv" && $kx == "$xc" ]] || die "Версии панели/Xray в kit.sh и 3x-ui.sh не совпадают."
for a in 64 arm64-v8a; do
  pin=$(map_hash scripts/3x-ui.sh XRAY_ZIP_SHA256 "$a")
  kit_pin=$(map_hash scripts/kit.sh XRAY_ZIP_SHA256 "$a")
  valid_sha "$pin" && [[ $kit_pin == "$pin" ]] || die "SHA256 Xray ($a) в kit.sh и 3x-ui.sh не совпадают или некорректны."
done
ok "Пины панели/Xray и дублируемые суммы ядра совпадают"

# API digest — отдельная проверка от текстового sidecar; отсутствие digest запрещает выпуск.
get "https://api.github.com/repos/MHSanaei/3x-ui/releases/tags/$xv" >"$work/panel-release.json"
get "https://api.github.com/repos/XTLS/Xray-core/releases/tags/$xc" >"$work/xray-release.json"
for a in 64 arm64-v8a; do
  name="Xray-linux-$a.zip"
  pin=$(map_hash scripts/3x-ui.sh XRAY_ZIP_SHA256 "$a")
  off=$(get "https://github.com/XTLS/Xray-core/releases/download/$xc/$name.dgst" | awk '/^SHA2-256=/ {print $2}')
  api_sha=$(asset_digest "$work/xray-release.json" "$name")
  valid_sha "$off" && [[ $pin == "$off" && $pin == "$api_sha" ]] \
    || die "SHA256 Xray $xc ($a) не совпал с .dgst и GitHub digest."
done
for a in amd64 arm64; do
  name="x-ui-linux-$a.tar.gz"
  pin=$(map_hash scripts/kit.sh XUI_TARBALL_SHA256 "$a")
  off=$(get "https://github.com/MHSanaei/3x-ui/releases/download/$kp/$name.sha256" | awk 'NR == 1 {print $1}')
  api_sha=$(asset_digest "$work/panel-release.json" "$name")
  valid_sha "$pin" && valid_sha "$off" && [[ $pin == "$off" && $pin == "$api_sha" ]] \
    || die "SHA256 панели $kp ($a) не совпал с .sha256 и GitHub digest."
done
xs=$(sed -n 's/^XUI_INSTALL_SHA256="\(.*\)"/\1/p' scripts/3x-ui.sh)
got=$(get "https://raw.githubusercontent.com/MHSanaei/3x-ui/$xv/install.sh" | sha | awk '{print $1}')
valid_sha "$xs" && [[ $got == "$xs" ]] || die "SHA256 install.sh панели $xv не совпал с проверенным."
shs=$(sed -n 's/^XUI_SH_SHA256=\(.*\)/\1/p' scripts/kit.sh)
got=$(get "https://raw.githubusercontent.com/MHSanaei/3x-ui/$kp/x-ui.sh" | sha | awk '{print $1}')
valid_sha "$shs" && [[ $got == "$shs" ]] || die "SHA256 x-ui.sh панели $kp не совпал с проверенным."
ok "Официальные sidecar, GitHub digests и SHA256 скриптов совпадают с пинами"

if [[ $check_only == yes ]]; then
  ok "Проверки пройдены. Приватный ключ не читался; manifest и подпись не создавались."
  exit 0
fi

pub=$(ssh-keygen -y -f "$key" | awk '{print $1, $2}')
printf '%s\n' "$release_signers" | awk '{print $1, $2}' | grep -qxF "$pub" \
  || die "Приватный ключ не соответствует публичному KIT_SIGNERS."
# Сначала полностью подписываем и проверяем во временном каталоге: отказ подписи
# не должен затирать прежние файлы manifest в рабочем дереве.
{ printf '# 3X-UI KIT %s\n' "$v"; sha "${FILES[@]}"; } >"$work/SHA256SUMS"
ssh-keygen -Y sign -f "$key" -n "$NS" "$work/SHA256SUMS" >/dev/null
ssh-keygen -Y verify -f "$work/allowed_signers" -I "$ID" -n "$NS" -s "$work/SHA256SUMS.sig" \
  <"$work/SHA256SUMS" >/dev/null || die "Подпись не прошла проверку."
install -m 644 "$work/SHA256SUMS" SHA256SUMS
install -m 644 "$work/SHA256SUMS.sig" SHA256SUMS.sig
ok "SHA256SUMS для KIT $v подписан и проверен ключом владельца форка"
printf '\nВладелец проверяет diff и коммитит manifest/подпись, затем создаёт тег v%s и GitHub Release.\n' "$v"
printf 'Порядок публикации и GitHub Pages: manuals/release.md\n'
