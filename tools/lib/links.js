// Разбор ссылок vless:// vmess:// trojan:// ss:// hy2:// в общий формат.
// Работает в браузере (window.PM) и в Node (module.exports). Всё локально –
// ссылки никуда не отправляются.
(function (root) {
  'use strict';

  function b64decode(s) {
    s = s.trim().replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
    while (s.length % 4) s += '=';
    const bin = typeof atob === 'function' ? atob(s) : Buffer.from(s, 'base64').toString('binary');
    // UTF-8 из бинарной строки
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  }

  function looksBase64(s) {
    return /^[A-Za-z0-9+/=_\-\s]+$/.test(s) && s.replace(/\s/g, '').length >= 16;
  }

  function dec(s) {
    try { return decodeURIComponent(s); } catch (e) { return s; }
  }

  function int(v, what) {
    const n = Number(v);
    if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error('неверный ' + what + ': ' + v);
    return n;
  }

  function splitList(v) {
    return v ? dec(v).split(',').map((x) => x.trim()).filter(Boolean) : [];
  }

  function truthy(v) {
    return v === '1' || v === 'true' || v === 'True';
  }

  // Разбор адреса «хост:порт» из URL: поддерживает IPv6 в квадратных скобках.
  function hostPort(u) {
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (!host) throw new Error('нет адреса сервера');
    return { server: host, port: int(u.port || '443', 'порт') };
  }

  // Общие параметры транспорта и шифрования из query (формат Xray share link).
  function transportFromQuery(q, fallbackHost) {
    let network = (q.get('type') || 'tcp').toLowerCase();
    if (network === 'raw') network = 'tcp';
    if (network === 'http' && q.get('headerType') !== 'http') network = 'xhttp';
    const t = { network };
    const path = q.get('path') ? dec(q.get('path')) : '';
    const host = q.get('host') ? dec(q.get('host')) : '';
    if (network === 'ws' || network === 'httpupgrade') {
      t.path = path || '/';
      if (host) t.host = host;
    } else if (network === 'grpc') {
      t.serviceName = dec(q.get('serviceName') || q.get('path') || '');
      t.multiMode = q.get('mode') === 'multi';
    } else if (network === 'xhttp' || network === 'splithttp') {
      t.network = 'xhttp';
      t.path = path || '/';
      if (host) t.host = host;
      t.mode = q.get('mode') || 'auto';
    } else if (network === 'tcp') {
      if (q.get('headerType') === 'http') {
        t.headerType = 'http';
        t.path = path || '/';
        if (host) t.host = host;
      }
    } else {
      throw new Error('транспорт «' + network + '» не поддерживается');
    }

    const security = (q.get('security') || 'none').toLowerCase();
    const s = { security };
    if (security === 'tls' || security === 'reality') {
      s.sni = dec(q.get('sni') || q.get('peer') || '') || host || fallbackHost;
      s.fp = q.get('fp') || (security === 'reality' ? 'chrome' : '');
      s.alpn = splitList(q.get('alpn'));
      s.insecure = truthy(q.get('allowInsecure')) || truthy(q.get('insecure'));
      // Отпечаток сертификата: pcs – имя параметра в ссылках Xray 26, pinSHA256 – в ссылках Hysteria.
      s.pin = (q.get('pcs') || q.get('pinSHA256') || '').replace(/:/g, '').toLowerCase();
    }
    if (security === 'reality') {
      // KIT 1.3.0 / Xray 26.10.21 requires a hybrid ML-KEM ClientHello. Older
      // presets and an explicit false hint must not survive into generated configs.
      s.fp = 'chrome';
      s.mlkem = true;
      s.pbk = q.get('pbk') || '';
      if (!s.pbk) throw new Error('в ссылке REALITY нет публичного ключа (pbk)');
      s.sid = q.get('sid') || '';
      s.spx = q.get('spx') ? dec(q.get('spx')) : '';
    } else if (security !== 'tls' && security !== 'none') {
      throw new Error('шифрование «' + security + '» не поддерживается');
    }
    return { transport: t, tls: s };
  }

  function parseVless(link) {
    const u = new URL(link);
    const id = dec(u.username);
    if (!id) throw new Error('нет UUID');
    const hp = hostPort(u);
    const q = u.searchParams;
    const enc = q.get('encryption');
    if (enc && enc !== 'none') throw new Error('шифрование VLESS «' + enc + '» не поддерживается');
    return Object.assign({
      type: 'vless', name: dec(u.hash.slice(1)), uuid: id, flow: q.get('flow') || '',
    }, hp, transportFromQuery(q, hp.server));
  }

  function parseTrojan(link) {
    const u = new URL(link);
    const pw = dec(u.username);
    if (!pw) throw new Error('нет пароля');
    const hp = hostPort(u);
    const q = u.searchParams;
    if (!q.get('security')) q.set('security', 'tls');
    return Object.assign({ type: 'trojan', name: dec(u.hash.slice(1)), password: pw }, hp, transportFromQuery(q, hp.server));
  }

  function parseVmess(link) {
    const raw = b64decode(link.slice('vmess://'.length).split('#')[0]);
    let j;
    try { j = JSON.parse(raw); } catch (e) { throw new Error('ссылка vmess повреждена'); }
    if (!j.id || !j.add) throw new Error('в ссылке vmess нет адреса или UUID');
    const q = new URLSearchParams();
    q.set('type', j.net || 'tcp');
    if (j.type && j.type !== 'none') q.set(j.net === 'grpc' ? 'mode' : 'headerType', j.type);
    if (j.path) q.set(j.net === 'grpc' ? 'serviceName' : 'path', j.path);
    if (j.host) q.set('host', j.host);
    q.set('security', j.tls === 'tls' || j.tls === 'reality' ? j.tls : 'none');
    if (j.sni) q.set('sni', j.sni);
    if (j.alpn) q.set('alpn', j.alpn);
    if (j.fp) q.set('fp', j.fp);
    if (j.pbk) q.set('pbk', j.pbk);
    if (j.sid) q.set('sid', j.sid);
    return Object.assign({
      type: 'vmess', name: j.ps || '', uuid: j.id, alterId: Number(j.aid || 0),
      cipher: j.scy || 'auto', server: String(j.add), port: int(j.port, 'порт'),
    }, transportFromQuery(q, String(j.add)));
  }

  const SS_METHODS = [
    'aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305', 'chacha20-ietf-poly1305',
    'xchacha20-poly1305', 'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305',
  ];

  function parseSs(link) {
    let body = link.slice('ss://'.length);
    let name = '';
    const h = body.indexOf('#');
    if (h >= 0) { name = dec(body.slice(h + 1)); body = body.slice(0, h); }
    const qi = body.indexOf('?');
    let query = '';
    if (qi >= 0) { query = body.slice(qi + 1); body = body.slice(0, qi); }
    body = body.replace(/\/$/, '');
    if (new URLSearchParams(query).get('plugin')) throw new Error('плагины Shadowsocks не поддерживаются');
    let userinfo, hostport;
    const at = body.lastIndexOf('@');
    if (at >= 0) {
      userinfo = body.slice(0, at);
      hostport = body.slice(at + 1);
      userinfo = userinfo.includes(':') ? dec(userinfo) : b64decode(dec(userinfo));
    } else {
      const d = b64decode(body);
      const a = d.lastIndexOf('@');
      if (a < 0) throw new Error('ссылка ss повреждена');
      userinfo = d.slice(0, a);
      hostport = d.slice(a + 1);
    }
    const c = userinfo.indexOf(':');
    if (c < 0) throw new Error('в ссылке ss нет метода или пароля');
    const method = userinfo.slice(0, c).toLowerCase();
    const password = userinfo.slice(c + 1);
    if (!SS_METHODS.includes(method)) throw new Error('метод Shadowsocks «' + method + '» не поддерживается');
    const u = new URL('ss://x@' + hostport);
    return Object.assign({ type: 'ss', name, method, password }, hostPort(u));
  }

  function parseHy2(link) {
    const authority = link.replace(/^[a-z0-9]+:\/\//i, '').split(/[/?#]/)[0];
    if (/:\d+[-,]/.test(authority)) throw new Error('диапазоны портов Hysteria2 не поддерживаются');
    const u = new URL(link.replace(/^hysteria2:/, 'hy2:'));
    let auth = dec(u.username);
    if (u.password) auth += ':' + dec(u.password);
    if (!auth) throw new Error('нет пароля');
    const q = u.searchParams;
    const hp = hostPort(u);
    const obfs = q.get('obfs') || '';
    if (obfs && obfs !== 'salamander') throw new Error('обфускация «' + obfs + '» не поддерживается');
    return Object.assign({
      type: 'hysteria2', name: dec(u.hash.slice(1)), password: auth,
      sni: dec(q.get('sni') || '') || hp.server,
      insecure: truthy(q.get('insecure')),
      pinSHA256: (q.get('pinSHA256') || '').replace(/:/g, '').toLowerCase(),
      obfs, obfsPassword: dec(q.get('obfs-password') || ''),
      alpn: splitList(q.get('alpn')),
    }, hp);
  }

  function parseTuic(link) {
    const u = new URL(link);
    const uuid = dec(u.username), password = dec(u.password);
    if (!uuid || !password) throw new Error('в ссылке TUIC нет UUID или пароля');
    const q = u.searchParams, hp = hostPort(u);
    return Object.assign({
      type: 'tuic', name: dec(u.hash.slice(1)), uuid, password,
      sni: dec(q.get('sni') || '') || hp.server,
      alpn: splitList(q.get('alpn')).length ? splitList(q.get('alpn')) : ['h3'],
      congestion: q.get('congestion_control') || 'bbr',
      udpRelay: q.get('udp_relay_mode') || 'native',
      insecure: truthy(q.get('allow_insecure')) || truthy(q.get('insecure')),
    }, hp);
  }

  function wgAddr(v) {
    return splitList(v).map((a) => a.replace(/\/\d+$/, ''));
  }

  function parseWireguard(link) {
    const u = new URL(link.replace(/^wg:/, 'wireguard:'));
    const q = u.searchParams, hp = hostPort(u);
    const priv = dec(u.username);
    const pub = dec(q.get('publickey') || q.get('publicKey') || '');
    if (!priv || !pub) throw new Error('в ссылке WireGuard нет ключей');
    return Object.assign({
      type: 'wireguard', name: dec(u.hash.slice(1)), privateKey: priv, publicKey: pub,
      preSharedKey: dec(q.get('presharedkey') || ''), address: wgAddr(q.get('address') || q.get('ip') || ''),
      mtu: Number(q.get('mtu') || 1420), reserved: q.get('reserved') ? splitList(q.get('reserved')).map(Number) : null,
    }, hp);
  }

  // Конфиг wg-quick / AmneziaWG: [Interface] + [Peer]. Параметры Jc…H4 – обфускация AmneziaWG.
  function parseWgConf(text, name) {
    const sec = {};
    let cur = null;
    text.split(/\r?\n/).forEach((line) => {
      const l = line.trim();
      const m = /^\[(\w+)\]$/.exec(l);
      if (m) { cur = m[1].toLowerCase(); sec[cur] = sec[cur] || {}; return; }
      const kv = /^([A-Za-z0-9]+)\s*=\s*(.*)$/.exec(l);
      if (kv && cur) sec[cur][kv[1].toLowerCase()] = kv[2].trim();
      const c = /^#\s*(.+)$/.exec(l);
      if (c && !name) name = c[1];
    });
    const i = sec.interface || {}, p = sec.peer || {};
    if (!i.privatekey || !p.publickey || !p.endpoint) throw new Error('конфиг WireGuard неполный');
    const ep = /^\[?([^\]]+?)\]?:(\d+)$/.exec(p.endpoint);
    if (!ep) throw new Error('в конфиге WireGuard неверный Endpoint');
    const awgKeys = ['jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4', 'h1', 'h2', 'h3', 'h4', 'i1', 'i2', 'i3', 'i4', 'i5',
      'headerprotectionkey', 'contentpaddingaddition', 'rekeyaftertime', 'rejectaftertime', 'rekeytimeout', 'keepalivetimeout', 'maxhandshakeattempts'];
    const awg = {};
    awgKeys.forEach((k) => { if (i[k] !== undefined && i[k] !== '') awg[k] = /^\d+$/.test(i[k]) ? Number(i[k]) : i[k]; });
    const isAwg = Object.keys(awg).length > 0;
    return {
      type: isAwg ? 'amneziawg' : 'wireguard', name: name || (isAwg ? 'amneziawg' : 'wireguard') + '-' + ep[1],
      server: ep[1], port: int(ep[2], 'порт'), privateKey: i.privatekey, publicKey: p.publickey,
      preSharedKey: p.presharedkey || '', address: wgAddr(i.address || ''), mtu: Number(i.mtu || 1420),
      dns: splitList(i.dns || ''), awg: isAwg ? awg : null, reserved: null,
    };
  }

  function parseVpn(link) {
    let text;
    try { text = b64decode(link.slice('vpn://'.length).split('#')[0]); } catch (e) { throw new Error('ссылка vpn:// повреждена'); }
    if (!/\[Interface\]/.test(text)) throw new Error('формат vpn:// не поддерживается – нужен конфиг AmneziaWG');
    return parseWgConf(text, dec(link.split('#')[1] || ''));
  }

  function parseTg(link) {
    const u = new URL(link.replace(/^https:\/\/t\.me\/proxy/, 'tg://proxy'));
    const q = u.searchParams;
    if (!q.get('server') || !q.get('secret')) throw new Error('в ссылке MTProto нет сервера или секрета');
    return { type: 'mtproto', name: 'mtproto-' + q.get('server'), server: q.get('server'), port: int(q.get('port') || '443', 'порт'), secret: q.get('secret') };
  }

  const PARSERS = {
    'vless': parseVless, 'vmess': parseVmess, 'trojan': parseTrojan, 'ss': parseSs, 'hy2': parseHy2, 'hysteria2': parseHy2,
    'tuic': parseTuic, 'wireguard': parseWireguard, 'wg': parseWireguard, 'vpn': parseVpn, 'tg': parseTg,
  };

  function parseLink(line) {
    if (/^https:\/\/t\.me\/proxy\?/.test(line)) line = line.replace(/^https:\/\/t\.me\/proxy/, 'tg://proxy');
    const m = /^([a-z0-9]+):\/\//i.exec(line);
    if (!m) throw new Error('это не ссылка на подключение');
    const p = PARSERS[m[1].toLowerCase()];
    if (!p) throw new Error('протокол «' + m[1] + '» не поддерживается');
    const r = p(line);
    if (!r.name) r.name = r.type + '-' + r.server;
    return r;
  }

  // Разбирает текст: ссылки по одной на строку или base64-подписку целиком.
  function parseText(text) {
    let t = (text || '').trim();
    if (t && !/:\/\//.test(t) && looksBase64(t)) {
      try { t = b64decode(t); } catch (e) { /* не base64 – разберём как есть */ }
    }
    const ok = [];
    const errors = [];
    t.split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith('#')).forEach((line, i) => {
      try {
        ok.push(parseLink(line));
      } catch (e) {
        errors.push({ line: i + 1, text: line.length > 60 ? line.slice(0, 57) + '…' : line, error: e.message });
      }
    });
    // Уникальные имена – клиенты требуют.
    const seen = {};
    ok.forEach((p) => {
      const base = p.name;
      let n = base, k = 2;
      while (seen[n]) n = base + ' ' + k++;
      seen[n] = true;
      p.name = n;
    });
    return { proxies: ok, errors };
  }

  const api = { parseLink, parseText, parseWgConf, b64decode };
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.PM = Object.assign(root.PM || {}, api);
})(typeof window !== 'undefined' ? window : globalThis);
