/* Arpam CDN Config Optimizer — vanilla JS, no dependencies, no backend. */
(function () {
  'use strict';

  /* ───────────── Defaults ───────────── */

  var DEFAULTS = {
    cdnIp: '188.114.97.6',
    fp: 'unsafe',
    cs: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    fm: JSON.stringify({
      tcp: [
        { type: 'fragment', settings: { packets: 'tlshello', lengths: ['5', '94', '1'], delays: ['0'], maxSplit: '0' } },
        { type: 'fragment', settings: { packets: '1-1', lengths: ['109', '1'], delays: ['1'], maxSplit: '355' } }
      ]
    }, null, 2)
  };

  var PARAM_ORDER = ['cs', 'path', 'security', 'alpn', 'encryption', 'fm', 'insecure', 'host', 'fp', 'type', 'allowInsecure', 'sni'];
  var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  var STORE_KEY = 'arpam_optimizer_settings';
  var THEME_KEY = 'arpam_theme';

  function VlessError(message) { this.name = 'VlessError'; this.message = message; }
  VlessError.prototype = Object.create(Error.prototype);

  /* ───────────── Core: parse / build / optimize ───────────── */

  function safeDecode(v) { try { return decodeURIComponent(v); } catch (e) { return v; } }

  function parseQuery(query) {
    var out = [];
    if (!query) return out;
    var parts = query.split('&');
    for (var i = 0; i < parts.length; i++) {
      var piece = parts[i];
      if (!piece) continue;
      var eq = piece.indexOf('=');
      var key = safeDecode(eq < 0 ? piece : piece.slice(0, eq)).trim();
      var val = eq < 0 ? '' : safeDecode(piece.slice(eq + 1).replace(/\+/g, ' '));
      if (key) out.push({ key: key, value: val });
    }
    return out;
  }

  function normalizeParams(params) {
    var seen = Object.create(null), order = [], out = [], i;
    for (i = 0; i < params.length; i++) {
      var k = params[i].key;
      if (!(k in seen)) order.push(k);
      seen[k] = params[i].value;
    }
    for (i = 0; i < order.length; i++) out.push({ key: order[i], value: seen[order[i]] });
    return out;
  }

  function sortParams(params) {
    var known = [], unknown = [], i, j;
    for (i = 0; i < PARAM_ORDER.length; i++) {
      for (j = 0; j < params.length; j++) if (params[j].key === PARAM_ORDER[i]) { known.push(params[j]); break; }
    }
    for (j = 0; j < params.length; j++) if (PARAM_ORDER.indexOf(params[j].key) === -1) unknown.push(params[j]);
    return known.concat(unknown);
  }

  function getParam(params, key) {
    for (var i = 0; i < params.length; i++) if (params[i].key === key) return params[i].value;
    return null;
  }

  function setParam(params, key, value) {
    for (var i = 0; i < params.length; i++) if (params[i].key === key) { params[i].value = value; return 'updated'; }
    params.push({ key: key, value: value });
    return 'added';
  }

  function parseVless(url) {
    var raw = String(url == null ? '' : url).trim();
    if (!raw) throw new VlessError('Empty line');
    if (!/^vless:\/\//i.test(raw)) throw new VlessError('URL must start with vless://');

    var rest = raw.slice(raw.indexOf('//') + 2), name = '';
    var hash = rest.indexOf('#');
    if (hash > -1) { name = safeDecode(rest.slice(hash + 1)); rest = rest.slice(0, hash); }

    var query = '', qm = rest.indexOf('?');
    if (qm > -1) { query = rest.slice(qm + 1); rest = rest.slice(0, qm); }

    var at = rest.lastIndexOf('@');
    if (at < 0) throw new VlessError('Missing "@" separator between UUID and address');

    var uuid = safeDecode(rest.slice(0, at)).trim();
    var authority = rest.slice(at + 1).trim();
    if (!authority) throw new VlessError('Missing destination address');

    var address = '', port = '';
    if (authority.charAt(0) === '[') {
      var end = authority.indexOf(']');
      if (end < 0) throw new VlessError('Malformed IPv6 address');
      address = authority.slice(0, end + 1);
      var tail = authority.slice(end + 1);
      port = tail.charAt(0) === ':' ? tail.slice(1) : '';
    } else {
      var colon = authority.lastIndexOf(':');
      if (colon < 0) { address = authority; } else { address = authority.slice(0, colon); port = authority.slice(colon + 1); }
    }

    return { uuid: uuid, address: address, port: port, params: normalizeParams(parseQuery(query)), name: name, raw: raw };
  }

  function validateVless(url) {
    var cfg = parseVless(url);
    if (!UUID_RE.test(cfg.uuid)) throw new VlessError('Invalid UUID');
    if (!cfg.address) throw new VlessError('Missing destination address');
    var port = parseInt(cfg.port, 10);
    if (!cfg.port || isNaN(port) || port < 1 || port > 65535) throw new VlessError('Invalid port');
    return cfg;
  }

  function encodeFinalMask(json) {
    var text = typeof json === 'string' ? json : JSON.stringify(json);
    try { return JSON.stringify(JSON.parse(text)); }
    catch (e) { throw new VlessError('FinalMask is not valid JSON'); }
  }

  function buildVless(config) {
    var pairs = [], params = sortParams(normalizeParams(config.params || []));
    for (var i = 0; i < params.length; i++) {
      pairs.push(encodeURIComponent(params[i].key) + '=' + encodeURIComponent(params[i].value));
    }
    var out = 'vless://' + encodeURIComponent(config.uuid).replace(/%3A/gi, ':') +
              '@' + config.address + (config.port ? ':' + config.port : '');
    if (pairs.length) out += '?' + pairs.join('&');
    if (config.name) out += '#' + encodeURIComponent(config.name);
    return out;
  }

  function optimizeVless(config, options) {
    var opts = options || {}, changes = [];
    var params = normalizeParams((config.params || []).slice());

    var newAddress = String(opts.cdnIp || '').trim(), oldAddress = config.address;
    if (newAddress && newAddress !== oldAddress) changes.push({ label: 'Address', kind: 'upd', detail: oldAddress + ' → ' + newAddress });
    else if (newAddress) changes.push({ label: 'Address', kind: 'keep', detail: 'unchanged' });

    var csValue = String(opts.cs || '').trim();
    if (csValue) {
      var csState = setParam(params, 'cs', csValue);
      changes.push({ label: 'Cipher Suites', kind: csState === 'added' ? 'add' : 'upd', detail: csState === 'added' ? 'Added' : 'Updated' });
    }

    var fmState = setParam(params, 'fm', encodeFinalMask(opts.fm || DEFAULTS.fm));
    changes.push({ label: 'FinalMask', kind: fmState === 'added' ? 'add' : 'upd', detail: fmState === 'added' ? 'Added' : 'Updated' });

    var fpValue = String(opts.fp || DEFAULTS.fp).trim(), fpBefore = getParam(params, 'fp');
    var fpState = setParam(params, 'fp', fpValue);
    changes.push({
      label: 'Fingerprint',
      kind: fpState === 'added' ? 'add' : 'upd',
      detail: fpState === 'added' ? 'Added (' + fpValue + ')' : ((fpBefore || '—') + ' → ' + fpValue)
    });

    if (getParam(params, 'host') || getParam(params, 'sni')) changes.push({ label: 'host / sni', kind: 'keep', detail: 'preserved' });

    return {
      config: { uuid: config.uuid, address: newAddress || oldAddress, port: config.port, params: sortParams(normalizeParams(params)), name: config.name },
      changes: changes
    };
  }

  function optimizeMultipleConfigs(text, options) {
    var lines = String(text == null ? '' : text).split(/[\r\n]+/), results = [], errors = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line.charAt(0) === '#' || line.slice(0, 2) === '//') continue;
      try {
        var parsed = validateVless(line), opt = optimizeVless(parsed, options);
        results.push({ input: line, output: buildVless(opt.config), name: parsed.name, changes: opt.changes });
      } catch (err) {
        errors.push({ line: i + 1, input: line, message: (err && err.message) ? err.message : 'Unknown parsing error' });
      }
    }
    return { results: results, errors: errors };
  }

  /* ───────────── App download catalogue ───────────── */

  var OS_ICONS = {
    android: '<svg viewBox="0 0 24 24" fill="#3ddc84"><path d="M17.6 9.48l1.84-3.18a.38.38 0 0 0-.14-.52.38.38 0 0 0-.52.14l-1.87 3.23a11.4 11.4 0 0 0-9.82 0L5.22 5.92a.38.38 0 0 0-.52-.14.38.38 0 0 0-.14.52L6.4 9.48A10.8 10.8 0 0 0 1 18h22a10.8 10.8 0 0 0-5.4-8.52M7 14.75a.96.96 0 1 1 .96-.96.96.96 0 0 1-.96.96m10 0a.96.96 0 1 1 .96-.96.96.96 0 0 1-.96.96"/></svg>',
    windows: '<svg viewBox="0 0 24 24" fill="#4aa8ff"><path d="M0 3.45 9.75 2.1v9.4H0zm10.95-1.5L24 0v11.4H10.95zM0 12.6h9.75V22L0 20.66zm10.95 0H24V24l-13.05-1.8z"/></svg>',
    ios: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 14.25 3.51 5.94 9.05 5.66c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.53 3.73M12.03 5.6C11.88 3.36 13.7 1.5 15.79 1.34c.29 2.58-2.34 4.5-3.76 4.26z"/></svg>',
    mac: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 14.25 3.51 5.94 9.05 5.66c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.53 3.73M12.03 5.6C11.88 3.36 13.7 1.5 15.79 1.34c.29 2.58-2.34 4.5-3.76 4.26z"/></svg>'
  };

  var GH = 'https://raw.githubusercontent.com/', MZ = 'https://is1-ssl.mzstatic.com/image/thumb/';

  var LOGO = {
    v2rayng:  { mode: 'cover', src: GH + '2dust/v2rayNG/master/V2rayNG/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png' },
    v2rayn:   { mode: 'pad', trim: 40, src: GH + '2dust/v2rayN/master/v2rayN/v2rayN.Desktop/v2rayN.png' },
    hiddify:  { mode: 'pad', trim: 12, src: GH + 'hiddify/hiddify-app/main/assets/images/source/ic_launcher_border.png' },
    karing:   { mode: 'cover', src: GH + 'KaringX/karing/main/assets/images/app_icon_256.png' },
    nekobox:  { mode: 'cover', src: GH + 'MatsuriDayo/NekoBoxForAndroid/main/app/src/main/ic_launcher-playstore.png' },
    verge:    { mode: 'pad', trim: 10, src: GH + 'clash-verge-rev/clash-verge-rev/main/src-tauri/icons/icon.png' },
    v2box:    { mode: 'cover', src: MZ + 'Purple221/v4/0d/f2/21/0df22186-8cc1-d88c-bff5-3be032cff4de/V2BoxIcon-0-0-1x_U007epad-0-1-P3-85-220.png/512x512bb.png' },
    streisand:{ mode: 'cover', src: MZ + 'Purple211/v4/fb/fd/e7/fbfde74a-55a9-6dc5-e0dc-38b927b0f46f/AppIcon-0-0-1x_U007epad-0-0-0-1-0-85-220.png/512x512bb.png' },
    shadow:   { mode: 'cover', src: MZ + 'Purple211/v4/62/1e/1d/621e1d3f-1d02-3fa5-bcbb-1c9ba6a8bd6d/AppIcon-0-0-1x_U007emarketing-0-7-0-85-220.png/512x512bb.png' },
    stash:    { mode: 'cover', src: MZ + 'Purple211/v4/54/9d/6c/549d6c39-cb15-c3b0-6bbf-4dd0f5a97b56/AppIcon-0-0-1x_U007epad-0-1-85-220.png/512x512bb.png' },
    happ:     { mode: 'cover', src: MZ + 'Purple221/v4/c4/bb/d1/c4bbd1c2-e4b0-4762-3b2e-add06ecb8415/AppIcon-0-0-1x_U007epad-0-0-0-1-0-0-sRGB-85-220.png/512x512bb.png' }
  };

  var PLATFORMS = [
    { id: 'android', label: 'Android', icon: 'android', apps: [
      { name: 'v2rayNG',  note: 'Xray core · GitHub',    logo: 'v2rayng', url: 'https://github.com/2dust/v2rayNG/releases/latest' },
      { name: 'Hiddify',  note: 'Multi-protocol · GitHub', logo: 'hiddify', url: 'https://github.com/hiddify/hiddify-app/releases/latest' },
      { name: 'Karing',   note: 'sing-box core · GitHub', logo: 'karing',  url: 'https://github.com/KaringX/karing/releases/latest' },
      { name: 'NekoBox',  note: 'SagerNet · GitHub',      logo: 'nekobox', url: 'https://github.com/MatsuriDayo/NekoBoxForAndroid/releases/latest' },
      { name: 'V2Box',    note: 'Google Play',            logo: 'v2box',   url: 'https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box' },
      { name: 'Happ',     note: 'Official site',          logo: 'happ',    url: 'https://happ.su/main/download' }
    ]},
    { id: 'windows', label: 'Windows', icon: 'windows', apps: [
      { name: 'v2rayN',      note: 'Xray core · GitHub',   logo: 'v2rayn',  url: 'https://github.com/2dust/v2rayN/releases/latest' },
      { name: 'Hiddify',     note: 'Multi-protocol · GitHub', logo: 'hiddify', url: 'https://github.com/hiddify/hiddify-app/releases/latest' },
      { name: 'Clash Verge', note: 'Mihomo core · GitHub', logo: 'verge',   url: 'https://github.com/clash-verge-rev/clash-verge-rev/releases/latest' },
      { name: 'Karing',      note: 'sing-box core · GitHub', logo: 'karing', url: 'https://github.com/KaringX/karing/releases/latest' },
      { name: 'Happ',        note: 'Official site',        logo: 'happ',    url: 'https://happ.su/main/download' }
    ]},
    { id: 'ios', label: 'iPhone', icon: 'ios', apps: [
      { name: 'Shadowrocket', note: 'App Store · paid', logo: 'shadow',    url: 'https://apps.apple.com/app/shadowrocket/id932747118' },
      { name: 'Streisand',    note: 'App Store · free', logo: 'streisand', url: 'https://apps.apple.com/app/streisand/id6450534064' },
      { name: 'V2Box',        note: 'App Store · free', logo: 'v2box',     url: 'https://apps.apple.com/app/v2box-v2ray-client/id6446814690' },
      { name: 'Stash',        note: 'App Store · paid', logo: 'stash',     url: 'https://apps.apple.com/app/stash/id1596063349' },
      { name: 'Happ',         note: 'App Store · free', logo: 'happ',      url: 'https://apps.apple.com/app/happ-proxy-utility/id6504287215' }
    ]},
    { id: 'mac', label: 'macOS', icon: 'mac', apps: [
      { name: 'Hiddify',     note: 'Multi-protocol · GitHub', logo: 'hiddify', url: 'https://github.com/hiddify/hiddify-app/releases/latest' },
      { name: 'Clash Verge', note: 'Mihomo core · GitHub',  logo: 'verge',   url: 'https://github.com/clash-verge-rev/clash-verge-rev/releases/latest' },
      { name: 'Karing',      note: 'sing-box core · GitHub', logo: 'karing', url: 'https://github.com/KaringX/karing/releases/latest' },
      { name: 'V2Box',       note: 'Mac App Store',         logo: 'v2box',   url: 'https://apps.apple.com/app/v2box-v2ray-client/id6446814690' },
      { name: 'Happ',        note: 'Official site',         logo: 'happ',    url: 'https://happ.su/main/download' }
    ]}
  ];

  var ICON_DL = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3.6v9.6"/><polyline points="8.4 9.8 12 13.4 15.6 9.8"/><path d="M4.8 16.6v1.6A2.2 2.2 0 0 0 7 20.4h10a2.2 2.2 0 0 0 2.2-2.2v-1.6"/></svg>';

  function proxy(src, mode, trim) {
    var base = 'https://wsrv.nl/?url=' + encodeURIComponent(src) + '&w=128&h=128&output=webp&q=86&n=-1';
    return mode === 'pad' ? base + '&trim=' + (trim || 20) + '&fit=contain&cbg=none' : base + '&fit=cover';
  }

  function logoChain(key) {
    var l = LOGO[key];
    if (!l) return [];
    return [proxy(l.src, l.mode, l.trim), l.src];
  }

  /* ───────────── Helpers ───────────── */

  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).catch(function () { return legacyCopy(text); });
    }
    return legacyCopy(text);
  }

  function legacyCopy(text) {
    return new Promise(function (resolve, reject) {
      try {
        var ta = document.createElement('textarea');
        ta.value = text; ta.setAttribute('readonly', '');
        ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        var ok = document.execCommand('copy');
        document.body.removeChild(ta);
        ok ? resolve() : reject(new Error('copy failed'));
      } catch (e) { reject(e); }
    });
  }

  function downloadConfigs(text, filename) {
    try {
      var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      var url = URL.createObjectURL(blob), a = document.createElement('a');
      a.href = url; a.download = filename || ('arpam-configs-' + Date.now() + '.txt');
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 1200);
      return true;
    } catch (e) { return false; }
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  }

  function closestOf(node, sel) {
    var el = (node && node.nodeType === 1) ? node : (node ? node.parentElement : null);
    while (el) { if (el.matches && el.matches(sel)) return el; el = el.parentElement; }
    return null;
  }

  function flash(btn, text, cls, ms) {
    if (!btn || btn.getAttribute('data-busy') === '1') return;
    var lbl = btn.querySelector('.lbl') || btn, old = lbl.textContent;
    btn.setAttribute('data-busy', '1');
    lbl.textContent = text;
    btn.classList.add(cls || 'done');
    setTimeout(function () {
      lbl.textContent = old;
      btn.classList.remove('done', 'bad');
      btn.setAttribute('data-busy', '0');
    }, ms || 1500);
  }

  /* ───────────── UI ───────────── */

  var $ = function (id) { return document.getElementById(id); };
  var root = document.documentElement;
  var inputArea, cdnIp, fpSelect, csArea, fmArea, fmHint, resultCard, resultList, resultSummary, errorList, advCard;
  var appsCard, seg, pill, appsPanel, tabs = [], activeTab = -1, heightTimer = null;
  var lastOutputs = [];

  function loadSettings() {
    var saved = {};
    try { saved = JSON.parse(localStorage.getItem(STORE_KEY) || '{}') || {}; } catch (e) { saved = {}; }
    cdnIp.value = saved.cdnIp || DEFAULTS.cdnIp;
    fpSelect.value = saved.fp || DEFAULTS.fp;
    if (!fpSelect.value) fpSelect.value = DEFAULTS.fp;
    csArea.value = saved.cs || DEFAULTS.cs;
    fmArea.value = saved.fm || DEFAULTS.fm;
    checkFm();
  }

  function saveSettings() {
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify({ cdnIp: cdnIp.value, fp: fpSelect.value, cs: csArea.value, fm: fmArea.value }));
    } catch (e) {}
  }

  function currentOptions() {
    return {
      cdnIp: cdnIp.value.trim() || DEFAULTS.cdnIp,
      fp: fpSelect.value || DEFAULTS.fp,
      cs: csArea.value.trim() || DEFAULTS.cs,
      fm: fmArea.value.trim() || DEFAULTS.fm
    };
  }

  function checkFm() {
    var ok = true;
    try { JSON.parse(fmArea.value); } catch (e) { ok = false; }
    fmHint.textContent = ok ? 'Valid JSON — encoded automatically into fm=' : 'Invalid JSON — fix it before optimizing';
    fmHint.className = ok ? 'hint' : 'hint bad';
    return ok;
  }

  function renderResults(data) {
    lastOutputs = [];
    var html = '', i;
    for (i = 0; i < data.results.length; i++) {
      var r = data.results[i];
      lastOutputs.push(r.output);
      var chips = '';
      for (var c = 0; c < r.changes.length; c++) {
        var ch = r.changes[c];
        chips += '<span class="chg ' + esc(ch.kind) + '"><b>' + esc(ch.label) + '</b>' + esc(ch.detail) + '</span>';
      }
      html += '<div class="res" style="--i:' + i + '"><div class="res-top">'
           +  '<span class="res-num">' + (i + 1) + '</span>'
           +  '<span class="res-name">' + esc(r.name || 'Configuration ' + (i + 1)) + '</span>'
           +  '<button type="button" class="btn btn-sm copy-one" data-idx="' + i + '"><span class="lbl">Copy</span></button>'
           +  '<button type="button" class="btn btn-sm open-one" data-idx="' + i + '"><span class="lbl">Import</span></button>'
           +  '</div><div class="res-out">' + esc(r.output) + '</div>'
           +  '<div class="changes">' + chips + '</div></div>';
    }
    resultList.innerHTML = html;

    if (data.errors.length) {
      var eh = '';
      for (i = 0; i < data.errors.length; i++) {
        var er = data.errors[i];
        eh += '<div class="err"><b>Invalid VLESS configuration — line ' + er.line + ': ' + esc(er.message) + '</b>'
           +  '<span>' + esc(er.input.length > 160 ? er.input.slice(0, 160) + '…' : er.input) + '</span></div>';
      }
      errorList.innerHTML = eh; errorList.hidden = false;
    } else { errorList.innerHTML = ''; errorList.hidden = true; }

    var n = data.results.length;
    resultSummary.textContent = n === 0
      ? 'No valid configuration found. Please check the URL and try again.'
      : (n === 1 ? 'Configuration optimized successfully' : n + ' configurations optimized successfully') +
        (data.errors.length ? ' — ' + data.errors.length + ' line(s) skipped' : '');

    resultCard.hidden = false;
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function runOptimize(btn) {
    var text = inputArea.value.trim();
    if (!text) { flash(btn, 'Paste a URL', 'bad'); return; }
    if (!checkFm()) { advCard.classList.add('open'); flash(btn, 'Invalid FinalMask', 'bad', 1800); return; }
    var data;
    try { data = optimizeMultipleConfigs(text, currentOptions()); }
    catch (e) {
      resultCard.hidden = false; resultList.innerHTML = '';
      errorList.hidden = false;
      errorList.innerHTML = '<div class="err"><b>Invalid VLESS configuration</b><span>Please check the URL and try again.</span></div>';
      resultSummary.textContent = 'Optimization failed';
      return;
    }
    saveSettings();
    renderResults(data);
  }

  /* ── Apps UI ── */

  function loadLogo(img) {
    var list;
    try { list = JSON.parse(img.getAttribute('data-srcs') || '[]'); } catch (e) { list = []; }
    var idx = 0;
    (function next() {
      if (idx >= list.length) { if (img.parentNode) img.parentNode.removeChild(img); return; }
      var url = list[idx++];
      img.onload = function () { if (img.naturalWidth < 4) { next(); return; } img.classList.add('on'); };
      img.onerror = next;
      img.src = url;
    })();
  }

  function renderApps(i) {
    var p = PLATFORMS[i], html = '<div class="rows" role="tabpanel" aria-labelledby="tab-' + p.id + '">';
    for (var k = 0; k < p.apps.length; k++) {
      var a = p.apps[k], meta = LOGO[a.logo] || { mode: 'cover' };
      html += '<a class="row" style="--i:' + k + '" href="' + esc(a.url) + '" target="_blank" rel="noopener noreferrer">'
           +  '<span class="ic ' + meta.mode + '"><span class="mono">' + esc(a.name.charAt(0)) + '</span>'
           +  '<img alt="" decoding="async" loading="lazy" referrerpolicy="no-referrer" data-srcs="' + esc(JSON.stringify(logoChain(a.logo))) + '"></span>'
           +  '<span class="nm"><b>' + esc(a.name) + '</b><span>' + esc(a.note) + '</span></span>'
           +  '<span class="dl" aria-hidden="true">' + ICON_DL + '</span></a>';
    }
    appsPanel.innerHTML = html + '</div>';
    var imgs = appsPanel.querySelectorAll('.ic img');
    for (var m = 0; m < imgs.length; m++) loadLogo(imgs[m]);
  }

  function placePill() {
    var btn = tabs[activeTab];
    if (!btn) return;
    var sr = seg.getBoundingClientRect(), br = btn.getBoundingClientRect();
    if (!br.width) return;
    var bw = parseFloat(getComputedStyle(seg).borderLeftWidth) || 0;
    pill.style.width = br.width + 'px';
    pill.style.transform = 'translate3d(' + (br.left - sr.left - bw) + 'px,0,0)';
    pill.classList.add('ready');
  }

  function selectTab(i, animate) {
    if (i === activeTab || !PLATFORMS[i]) return;
    activeTab = i;
    for (var k = 0; k < tabs.length; k++) tabs[k].setAttribute('aria-selected', String(k === i));
    placePill();
    var from = appsPanel.offsetHeight;
    renderApps(i);
    var box = appsPanel.firstElementChild, to = box ? box.offsetHeight : 0;
    if (heightTimer) { clearTimeout(heightTimer); heightTimer = null; }
    if (!animate || !from || !to) { appsPanel.classList.remove('anim'); appsPanel.style.height = 'auto'; return; }
    appsPanel.classList.add('anim');
    appsPanel.style.height = from + 'px';
    void appsPanel.offsetHeight;
    requestAnimationFrame(function () { appsPanel.style.height = to + 'px'; });
    heightTimer = setTimeout(function () { appsPanel.classList.remove('anim'); appsPanel.style.height = 'auto'; heightTimer = null; }, 360);
  }

  function initApps() {
    appsCard = $('appsCard'); seg = $('seg'); pill = $('pill'); appsPanel = $('appsPanel');
    var html = '', total = 0, i;
    for (i = 0; i < PLATFORMS.length; i++) {
      total += PLATFORMS[i].apps.length;
      html += '<button type="button" class="tab" role="tab" id="tab-' + PLATFORMS[i].id + '" data-i="' + i + '" aria-selected="' + (i === 0) + '">'
           +  '<span class="osi">' + OS_ICONS[PLATFORMS[i].icon] + '</span><span>' + PLATFORMS[i].label + '</span></button>';
    }
    seg.insertAdjacentHTML('beforeend', html);
    tabs = [].slice.call(seg.querySelectorAll('.tab'));
    $('appsTotal').textContent = total + ' apps';
    appsCard.classList.add('open');
    selectTab(0, false);

    seg.addEventListener('click', function (ev) {
      var btn = closestOf(ev.target, '.tab');
      if (!btn) return;
      selectTab(parseInt(btn.getAttribute('data-i'), 10), true);
      if (btn.blur) btn.blur();
    });
    seg.addEventListener('keydown', function (ev) {
      var d = ev.key === 'ArrowRight' ? 1 : ev.key === 'ArrowLeft' ? -1 : 0;
      if (!d) return;
      ev.preventDefault();
      var n = (activeTab + d + tabs.length) % tabs.length;
      selectTab(n, true); tabs[n].focus();
    });
    $('appsToggle').addEventListener('click', function () {
      var open = !appsCard.classList.contains('open');
      appsCard.classList.toggle('open', open);
      this.setAttribute('aria-expanded', String(open));
      if (open) requestAnimationFrame(function () { requestAnimationFrame(placePill); });
    });
    if (window.ResizeObserver) { try { new ResizeObserver(placePill).observe(seg); } catch (e) {} }
  }

  function applyTheme(next) {
    next = (next === 'light') ? 'light' : 'dark';
    root.classList.add('theming');
    root.setAttribute('data-theme', next);
    try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
    var meta = $('metaThemeColor');
    if (meta) meta.setAttribute('content', next === 'light' ? '#f1f4f9' : '#0b0b10');
    setTimeout(function () { root.classList.remove('theming'); }, 420);
  }

  function init() {
    inputArea = $('inputArea'); cdnIp = $('cdnIp'); fpSelect = $('fpSelect');
    csArea = $('csArea'); fmArea = $('fmArea'); fmHint = $('fmHint');
    resultCard = $('resultCard'); resultList = $('resultList');
    resultSummary = $('resultSummary'); errorList = $('errorList'); advCard = $('advCard');

    loadSettings();
    initApps();

    $('optimizeBtn').addEventListener('click', function () { runOptimize(this); });

    $('pasteBtn').addEventListener('click', function () {
      var btn = this;
      if (!navigator.clipboard || !navigator.clipboard.readText) { flash(btn, 'Not supported', 'bad'); return; }
      navigator.clipboard.readText().then(function (txt) {
        if (!txt) { flash(btn, 'Clipboard empty', 'bad'); return; }
        inputArea.value = inputArea.value.trim() ? inputArea.value.replace(/\s*$/, '') + '\n' + txt.trim() : txt.trim();
        flash(btn, 'Pasted');
      }).catch(function () { flash(btn, 'Blocked', 'bad'); });
    });

    $('clearBtn').addEventListener('click', function () { inputArea.value = ''; inputArea.focus(); });

    $('fileBtn').addEventListener('click', function () { $('fileInput').click(); });
    $('fileInput').addEventListener('change', function () {
      var f = this.files && this.files[0];
      if (!f) return;
      var reader = new FileReader();
      reader.onload = function () { inputArea.value = String(reader.result || ''); runOptimize($('optimizeBtn')); };
      reader.onerror = function () { flash($('fileBtn'), 'Read failed', 'bad'); };
      reader.readAsText(f);
      this.value = '';
    });

    var dz = $('dropZone'), depth = 0;
    ['dragenter', 'dragover'].forEach(function (ev) {
      dz.addEventListener(ev, function (e) { e.preventDefault(); depth++; dz.classList.add('dragging'); });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      dz.addEventListener(ev, function (e) { e.preventDefault(); depth = Math.max(0, depth - 1); if (!depth) dz.classList.remove('dragging'); });
    });
    dz.addEventListener('drop', function (e) {
      depth = 0; dz.classList.remove('dragging');
      var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (!f) return;
      var reader = new FileReader();
      reader.onload = function () { inputArea.value = String(reader.result || ''); runOptimize($('optimizeBtn')); };
      reader.readAsText(f);
    });

    $('advToggle').addEventListener('click', function () {
      var open = !advCard.classList.contains('open');
      advCard.classList.toggle('open', open);
      this.setAttribute('aria-expanded', String(open));
    });

    $('defaultIpBtn').addEventListener('click', function () { cdnIp.value = DEFAULTS.cdnIp; saveSettings(); flash(this, 'Default set'); });
    $('resetBtn').addEventListener('click', function () {
      cdnIp.value = DEFAULTS.cdnIp; fpSelect.value = DEFAULTS.fp; csArea.value = DEFAULTS.cs; fmArea.value = DEFAULTS.fm;
      checkFm(); saveSettings(); flash(this, 'Restored');
    });

    [cdnIp, fpSelect, csArea, fmArea].forEach(function (el) {
      el.addEventListener('change', saveSettings);
      el.addEventListener('input', function () { if (el === fmArea) checkFm(); saveSettings(); });
    });

    resultList.addEventListener('click', function (ev) {
      var copyBtn = closestOf(ev.target, '.copy-one');
      if (copyBtn) {
        var text = lastOutputs[parseInt(copyBtn.getAttribute('data-idx'), 10)];
        if (!text) { flash(copyBtn, 'Empty', 'bad'); return; }
        copyToClipboard(text).then(function () { flash(copyBtn, 'Copied!'); }).catch(function () { flash(copyBtn, 'Failed', 'bad'); });
        return;
      }
      var openBtn = closestOf(ev.target, '.open-one');
      if (openBtn) {
        var url = lastOutputs[parseInt(openBtn.getAttribute('data-idx'), 10)];
        if (!url) { flash(openBtn, 'Empty', 'bad'); return; }
        try { window.location.href = url; flash(openBtn, 'Opening…'); } catch (e) { flash(openBtn, 'No handler', 'bad'); }
      }
    });

    $('copyAllBtn').addEventListener('click', function () {
      var btn = this;
      if (!lastOutputs.length) { flash(btn, 'Nothing yet', 'bad'); return; }
      copyToClipboard(lastOutputs.join('\n')).then(function () { flash(btn, 'Copied!'); }).catch(function () { flash(btn, 'Failed', 'bad'); });
    });

    $('downloadBtn').addEventListener('click', function () {
      if (!lastOutputs.length) { flash(this, 'Nothing yet', 'bad'); return; }
      var ok = downloadConfigs(lastOutputs.join('\n'), 'arpam-optimized-' + Date.now() + '.txt');
      flash(this, ok ? 'Saved' : 'Failed', ok ? 'done' : 'bad');
    });

    $('clearResultBtn').addEventListener('click', function () {
      lastOutputs = []; resultList.innerHTML = ''; errorList.innerHTML = '';
      errorList.hidden = true; resultCard.hidden = true;
    });

    $('themeToggle').addEventListener('click', function () {
      applyTheme(root.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
      if (this.blur) this.blur();
    });

    inputArea.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runOptimize($('optimizeBtn')); }
    });

    var rTid = null;
    addEventListener('resize', function () {
      if (rTid) clearTimeout(rTid);
      rTid = setTimeout(function () { placePill(); if (!appsPanel.classList.contains('anim')) appsPanel.style.height = 'auto'; }, 130);
    });
    addEventListener('load', placePill);
    if (document.fonts && document.fonts.ready && document.fonts.ready.then) document.fonts.ready.then(placePill).catch(function () {});
    requestAnimationFrame(placePill);

    window.addEventListener('error', function (e) { if (e && e.preventDefault) e.preventDefault(); });
  }

  window.ArpamOptimizer = {
    DEFAULTS: DEFAULTS, PLATFORMS: PLATFORMS,
    parseVless: parseVless, validateVless: validateVless, normalizeParams: normalizeParams,
    encodeFinalMask: encodeFinalMask, optimizeVless: optimizeVless, buildVless: buildVless,
    optimizeMultipleConfigs: optimizeMultipleConfigs, copyToClipboard: copyToClipboard, downloadConfigs: downloadConfigs
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
