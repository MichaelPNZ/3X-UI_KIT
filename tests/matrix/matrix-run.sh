#!/usr/bin/env bash
# Прогон матрицы: каждый конфиг – отдельный клиент, через него открываем сайт.
cd /lab/cases
t() { # client port cmd...
  local port=$1; shift
  ("$@" >/tmp/c.log 2>&1 &)
  local code=000
  for i in 1 2 3 4 5 6; do
    sleep 1
    code=$(curl -s -m 8 -x socks5h://127.0.0.1:$port -o /dev/null -w '%{http_code}' https://www.google.com/generate_204)
    [[ $code == 204 ]] && break
  done
  pkill -x xray; pkill -x mihomo; pkill -x sing-box; sleep 0.5
  if [[ $code == 204 ]]; then echo "✓"; else echo "✗ $(grep -i -m1 -E 'error|fail|fatal|invalid' /tmp/c.log | cut -c1-90)"; fi
}
xray_label=$(/cl/xray version | awk 'NR == 1 {print $1 " " $2}')
printf '%-32s %-40s %-40s %s\n' "протокол" "${xray_label:-Xray (версия неизвестна)}" "Mihomo" "sing-box"
for d in */; do
  d=${d%/}
  x='–'; m='–'; s='–'
  [[ -f $d/xray.json ]] && x=$(t 1080 /cl/xray run -c $d/xray.json)
  [[ -f $d/mihomo.yaml ]] && m=$(t 1081 /cl/mihomo -d /tmp/mh -f $d/mihomo.yaml)
  [[ -f $d/singbox.json ]] && s=$(t 1082 /cl/sing-box run -c $d/singbox.json)
  printf '%-32s %-40s %-40s %s\n' "$d" "$x" "$m" "$s"
done
