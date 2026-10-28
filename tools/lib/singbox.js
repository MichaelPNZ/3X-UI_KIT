// Сборка конфига sing-box (Hiddify, Karing, NekoBox, sing-box) из разобранных ссылок.
(function (root) {
  'use strict';

  function clean(o) {
    Object.keys(o).forEach((k) => (o[k] === undefined || o[k] === '' || (Array.isArray(o[k]) && !o[k].length)) && delete o[k]);
    return o;
  }

  function tls(p) {
    const s = p.tls;
    if (!s || s.security === 'none') return undefined;
    // certificate_public_key_sha256 is an SPKI hash, not the certificate-DER
    // SHA256 carried by Xray's pcs. Silently dropping this pin is unsafe.
    if (s.pin) throw new Error('sing-box не поддерживает SHA256-отпечаток сертификата из ссылки — используйте Xray или Mihomo');
    const t = clean({ enabled: true, server_name: s.sni, alpn: s.alpn, insecure: s.insecure || undefined });
    if (s.security === 'reality' || s.fp) t.utls = { enabled: true, fingerprint: s.security === 'reality' ? 'chrome' : s.fp };
    if (s.security === 'reality') t.reality = clean({ enabled: true, public_key: s.pbk, short_id: s.sid });
    return t;
  }

  function transport(p) {
    const t = p.transport;
    if (!t || t.network === 'tcp') {
      if (t && t.headerType === 'http') return clean({ type: 'http', path: t.path, host: t.host ? [t.host] : undefined });
      return undefined;
    }
    if (t.network === 'ws') {
      const o = { type: 'ws', path: t.path };
      if (t.host) o.headers = { Host: t.host };
      return o;
    }
    if (t.network === 'httpupgrade') return clean({ type: 'httpupgrade', path: t.path, host: t.host });
    if (t.network === 'grpc') return { type: 'grpc', service_name: t.serviceName };
    throw new Error('sing-box не поддерживает транспорт ' + t.network);
  }

  // Возвращает { outbound } или { endpoint } (WireGuard в sing-box – endpoint).
  function convert(p) {
    const base = { tag: p.name, server: p.server, server_port: p.port };
    switch (p.type) {
      case 'vless':
        return { outbound: clean(Object.assign(base, { type: 'vless', uuid: p.uuid, flow: p.flow, tls: tls(p), transport: transport(p) })) };
      case 'vmess':
        return { outbound: clean(Object.assign(base, { type: 'vmess', uuid: p.uuid, security: p.cipher, alter_id: p.alterId, tls: tls(p), transport: transport(p) })) };
      case 'trojan':
        return { outbound: clean(Object.assign(base, { type: 'trojan', password: p.password, tls: tls(p), transport: transport(p) })) };
      case 'ss':
        return { outbound: Object.assign(base, { type: 'shadowsocks', method: p.method, password: p.password }) };
      case 'hysteria2': {
        if (p.pinSHA256) throw new Error('sing-box не поддерживает SHA256-отпечаток сертификата Hysteria2 — используйте Xray или Mihomo');
        const t = clean({ enabled: true, server_name: p.sni, alpn: p.alpn, insecure: p.insecure || undefined });
        const o = clean(Object.assign(base, { type: 'hysteria2', password: p.password, tls: t }));
        if (p.obfs) o.obfs = { type: p.obfs, password: p.obfsPassword };
        return { outbound: o };
      }
      case 'tuic':
        return { outbound: clean(Object.assign(base, { type: 'tuic', uuid: p.uuid, password: p.password, congestion_control: p.congestion,
          udp_relay_mode: p.udpRelay, tls: clean({ enabled: true, server_name: p.sni, alpn: p.alpn, insecure: p.insecure || undefined }) })) };
      case 'wireguard':
        return { endpoint: clean({ type: 'wireguard', tag: p.name, address: p.address.map((a) => a + (a.includes(':') ? '/128' : '/32')),
          private_key: p.privateKey, mtu: p.mtu,
          peers: [clean({ address: p.server, port: p.port, public_key: p.publicKey, pre_shared_key: p.preSharedKey, allowed_ips: ['0.0.0.0/0', '::/0'], reserved: p.reserved || undefined })] }) };
      case 'amneziawg':
        throw new Error('sing-box не поддерживает AmneziaWG');
      default:
        throw new Error('sing-box не поддерживает ' + p.type);
    }
  }

  // opts: { inbound: {type:'mixed', port} } – для тестов и десктопных клиентов.
  function build(proxies, opts) {
    opts = opts || {};
    const outbounds = [], endpoints = [], skipped = [];
    proxies.filter((p) => p.type !== 'mtproto').forEach((p) => {
      try {
        const r = convert(p);
        if (r.outbound) outbounds.push(r.outbound); else endpoints.push(r.endpoint);
      } catch (e) { skipped.push({ name: p.name, error: e.message }); }
    });
    const tags = outbounds.map((o) => o.tag).concat(endpoints.map((e) => e.tag));
    if (!tags.length) throw new Error(skipped.length ? skipped[0].error : 'Нет подходящих серверов для sing-box.');
    const cfg = { log: { level: 'warn' } };
    if (opts.inbound) cfg.inbounds = [{ type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: opts.inbound.port }];
    cfg.outbounds = [{ type: 'selector', tag: 'Прокси', outbounds: ['Авто'].concat(tags) },
      { type: 'urltest', tag: 'Авто', outbounds: tags, url: 'https://www.gstatic.com/generate_204', interval: '5m' }]
      .concat(outbounds, [{ type: 'direct', tag: 'direct' }]);
    if (endpoints.length) cfg.endpoints = endpoints;
    cfg.route = { final: opts.final || 'Прокси', auto_detect_interface: true };
    return { config: cfg, skipped, count: tags.length };
  }

  const api = { buildSingbox: build, singboxConvert: convert };
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.PM = Object.assign(root.PM || {}, api);
})(typeof window !== 'undefined' ? window : globalThis);
