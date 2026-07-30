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

  function safeDecode(value) {
    try { return decodeURIComponent(value); } catch (e) { return value; }
  }

  function parseQuery(query) {
    var out = [];
    if (!query) return out;
    var parts = query.split('&');
    for (var i = 0; i < parts.length; i++) {
      var piece = parts[i];
      if (!piece) continue;
      var eq = piece.indexOf('=');
      var key = eq < 0 ? piece : piece.slice(0, eq);
      var val = eq < 0 ? '' : piece.slice(eq + 1);
      key = safeDecode(key).trim();
      if (!key) continue;
      out.push({ key: key, value: safeDecode(val.replace(/\+/g, ' ')) });
    }
    return out;
  }

  /** Removes duplicate keys (last value wins) and preserves first-seen order. */
  function normalizeParams(params) {
    var seen = Object.create(null), order = [], i;
    for (i = 0; i < params.length; i++) {
      var k = params[i].key;
      if (!(k in seen)) order.push(k);
      seen[k] = params[i].value;
    }
    var out = [];
    for (i = 0; i < order.length; i++) out.push({ key: order[i], value: seen[order[i]] });
    return out;
  }

  function sortParams(params) {
    var known = [], unknown = [], i, j;
    for (i = 0; i < PARAM_ORDER.length; i++) {
      for (j = 0; j < params.length; j++) {
        if (params[j].key === PARAM_ORDER[i]) { known.push(params[j]); break; }
      }
    }
    for (j = 0; j < params.length; j++) {
      if (PARAM_ORDER.indexOf(params[j].key) === -1) unknown.push(params[j]);
    }
    return known.concat(unknown);
  }

  function getParam(params, key) {
    for (var i = 0; i < params.length; i++) if (params[i].key === key) return params[i].value;
    return null;
  }

  function setParam(params, key, value) {
    for (var i = 0; i < params.length; i++) {
      if (params[i].key === key) { params[i].value = value; return 'updated'; }
    }
    params.push({ key: key, value: value });
    return 'added';
  }

  function parseVless(url) {
    var raw = String(url == null ? '' : url).trim();
    if (!raw) throw new VlessError('Empty line');
    if (!/^vless:\/\//i.test(raw)) throw new VlessError('URL must start with vless://');

    var rest = raw.slice(raw.indexOf('//') + 2);

    var name = '';
    var hash = rest.indexOf('#');
    if (hash > -1) { name = safeDecode(rest.slice(hash + 1)); rest = rest.slice(0, hash); }

    var query = '';
    var qm = rest.indexOf('?');
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
      if (colon < 0) { address = authority; port = ''; }
      else { address = authority.slice(0, colon); port = authority.slice(colon + 1); }
    }

    return {
      uuid: uuid,
      address: address,
      port: port,
      params: normalizeParams(parseQuery(query)),
      name: name,
      raw: raw
    };
  }

  function validateVless(url) {
    var cfg = parseVless(url); // throws VlessError with a readable message
    if (!UUID_RE.test(cfg.uuid)) throw new VlessError('Invalid UUID');
    if (!cfg.address) throw new VlessError('Missing destination address');
    var port = parseInt(cfg.port, 10);
    if (!cfg.port || isNaN(port) || port < 1 || port > 65535) throw new VlessError('Invalid port');
    return cfg;
  }

  function encodeFinalMask(json) {
    var text = typeof json === 'string' ? json : JSON.stringify(json);
    var compact;
    try { compact = JSON.stringify(JSON.parse(text)); }
    catch (e) { throw new VlessError('FinalMask is not valid JSON'); }
    return compact;
  }

  function buildVless(config) {
    var pairs = [], i;
    var params = sortParams(normalizeParams(config.params || []));
    for (i = 0; i < params.length; i++) {
      pairs.push(encodeURIComponent(params[i].key) + '=' + encodeURIComponent(params[i].value));
    }
    var out = 'vless://' + encodeURIComponent(config.uuid).replace(/%3A/gi, ':') +
              '@' + config.address + (config.port ? ':' + config.port : '');
    if (pairs.length) out += '?' + pairs.join('&');
    if (config.name) out += '#' + encodeURIComponent(config.name);
    return out;
  }

  /**
   * Applies CDN settings. Only address, cs, fm and fp are touched.
   * Everything else (path, security, alpn, host, sni, type, unknown keys, name) is preserved.
   */
  function optimizeVless(config, options) {
    var opts = options || {};
    var changes = [];
    var params = normalizeParams((config.params || []).slice());

    var newAddress = String(opts.cdnIp || '').trim();
    var oldAddress = config.address;
    if (newAddress && newAddress !== oldAddress) {
      changes.push({ label: 'Address', kind: 'upd', detail: oldAddress + ' → ' + newAddress });
    } else if (newAddress) {
      changes.push({ label: 'Address', kind: 'keep', detail: 'unchanged' });
    }

    var csValue = String(opts.cs || '').trim();
    if (csValue) {
      var csBefore = getParam(params, 'cs');
      var csState = setParam(params, 'cs', csValue);
      changes.push({
        label: 'Cipher Suites',
        kind: csState === 'added' ? 'add' : 'upd',
        detail: csState === 'added' ? 'Added' : (csBefore === csValue ? 'Updated (same value)' : 'Updated')
      });
    }

    var fmValue = encodeFinalMask(opts.fm || DEFAULTS.fm);
    var fmState = setParam(params, 'fm', fmValue);
    changes.push({ label: 'FinalMask', kind: fmState === 'added' ? 'add' : 'upd', detail: fmState === 'added' ? 'Added' : 'Updated' });

    var fpValue = String(opts.fp || DEFAULTS.fp).trim();
    var fpBefore = getParam(params, 'fp');
    var fpState = setParam(params, 'fp', fpValue);
    changes.push({
      label: 'Fingerprint',
      kind: fpState === 'added' ? 'add' : 'upd',
      detail: fpState === 'added' ? 'Added (' + fpValue + ')' : ((fpBefore || '—') + ' → ' + fpValue)
    });

    var host = getParam(params, 'host'), sni = getParam(params, 'sni');
    if (host || sni) changes.push({ label: 'host / sni', kind: 'keep', detail: 'preserved' });

    return {
      config: {
        uuid: config.uuid,
        address: newAddress || oldAddress,
        port: config.port,
        params: sortParams(normalizeParams(params)),
        name: config.name
      },
      changes: changes
    };
  }

  function optimizeMultipleConfigs(text, options) {
    var lines = String(text == null ? '' : text).split(/[\r\n]+/);
    var results = [], errors = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line.charAt(0) === '#' || line.slice(0, 2) === '//') continue;
      try {
        var parsed = validateVless(line);
        var opt = optimizeVless(parsed, options);
        results.push({ input: line, output: buildVless(opt.config), name: parsed.name, changes: opt.changes });
      } catch (err) {
        errors.push({ line: i + 1, input: line, message: (err && err.message) ? err.message : 'Unknown parsing error' });
      }
    }
    return { results: results, errors: errors };
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
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand('copy');
        document.body.removeChild(ta);
        ok ? resolve() : reject(new Error('copy failed'));
      } catch (e) { reject(e); }
    });
  }

  function downloadConfigs(text, filename) {
    try {
      var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = filename || ('arpam-configs-' + Date.now() + '.txt');
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
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

  /** Inline button feedback — no toasts anywhere. */
  function flash(btn, text, cls, ms) {
    if (!btn) return;
    var lbl = btn.querySelector('.lbl') || btn;
    if (btn.getAttribute('data-busy') === '1') return;
    btn.setAttribute('data-busy', '1');
    var old = lbl.textContent;
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
  var lastOutputs = [];

  function loadSettings() {
    var saved = {};
    try { saved = JSON.parse(localStorage.getItem(STORE_KEY) || '{}') || {}; } catch (e) { saved = {}; }
    cdnIp.value   = typeof saved.cdnIp === 'string' && saved.cdnIp ? saved.cdnIp : DEFAULTS.cdnIp;
    fpSelect.value = typeof saved.fp === 'string' && saved.fp ? saved.fp : DEFAULTS.fp;
    if (!fpSelect.value) fpSelect.value = DEFAULTS.fp;
    csArea.value  = typeof saved.cs === 'string' && saved.cs ? saved.cs : DEFAULTS.cs;
    fmArea.value  = typeof saved.fm === 'string' && saved.fm ? saved.fm : DEFAULTS.fm;
    checkFm();
  }

  function saveSettings() {
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify({
        cdnIp: cdnIp.value, fp: fpSelect.value, cs: csArea.value, fm: fmArea.value
      }));
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
      html += '<div class="res" style="--i:' + i + '">'
           +  '<div class="res-top">'
           +  '<span class="res-num">' + (i + 1) + '</span>'
           +  '<span class="res-name">' + esc(r.name || 'Configuration ' + (i + 1)) + '</span>'
           +  '<button type="button" class="btn btn-sm copy-one" data-idx="' + i + '"><span class="lbl">Copy</span></button>'
           +  '<button type="button" class="btn btn-sm open-one" data-idx="' + i + '"><span class="lbl">Import</span></button>'
           +  '</div>'
           +  '<div class="res-out">' + esc(r.output) + '</div>'
           +  '<div class="changes">' + chips + '</div>'
           +  '</div>';
    }
    resultList.innerHTML = html;

    if (data.errors.length) {
      var eh = '';
      for (i = 0; i < data.errors.length; i++) {
        var er = data.errors[i];
        eh += '<div class="err"><b>Invalid VLESS configuration — line ' + er.line + ': ' + esc(er.message) + '</b>'
           +  '<span>' + esc(er.input.length > 160 ? er.input.slice(0, 160) + '…' : er.input) + '</span></div>';
      }
      errorList.innerHTML = eh;
      errorList.hidden = false;
    } else {
      errorList.innerHTML = '';
      errorList.hidden = true;
    }

    var n = data.results.length;
    if (n === 0) {
      resultSummary.textContent = 'No valid configuration found. Please check the URL and try again.';
    } else if (n === 1) {
      resultSummary.textContent = 'Configuration optimized successfully' + (data.errors.length ? ' — ' + data.errors.length + ' line(s) skipped' : '');
    } else {
      resultSummary.textContent = n + ' configurations optimized successfully' + (data.errors.length ? ' — ' + data.errors.length + ' line(s) skipped' : '');
    }

    resultCard.hidden = false;
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function runOptimize(btn) {
    var text = inputArea.value.trim();
    if (!text) { flash(btn, 'Paste a URL', 'bad'); return; }
    if (!checkFm()) {
      if (!advCard.classList.contains('open')) advCard.classList.add('open');
      flash(btn, 'Invalid FinalMask', 'bad', 1800);
      return;
    }
    var data;
    try { data = optimizeMultipleConfigs(text, currentOptions()); }
    catch (e) {
      resultCard.hidden = false;
      resultList.innerHTML = '';
      errorList.hidden = false;
      errorList.innerHTML = '<div class="err"><b>Invalid VLESS configuration</b><span>Please check the URL and try again.</span></div>';
      resultSummary.textContent = 'Optimization failed';
      return;
    }
    saveSettings();
    renderResults(data);
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

    $('clearBtn').addEventListener('click', function () {
      inputArea.value = '';
      inputArea.focus();
    });

    $('fileBtn').addEventListener('click', function () { $('fileInput').click(); });
    $('fileInput').addEventListener('change', function () {
      var f = this.files && this.files[0];
      if (!f) return;
      var reader = new FileReader();
      reader.onload = function () {
        inputArea.value = String(reader.result || '');
        runOptimize($('optimizeBtn'));
      };
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
        var ci = parseInt(copyBtn.getAttribute('data-idx'), 10);
        var text = lastOutputs[ci];
        if (!text) { flash(copyBtn, 'Empty', 'bad'); return; }
        copyToClipboard(text).then(function () { flash(copyBtn, 'Copied!'); }).catch(function () { flash(copyBtn, 'Failed', 'bad'); });
        return;
      }
      var openBtn = closestOf(ev.target, '.open-one');
      if (openBtn) {
        var oi = parseInt(openBtn.getAttribute('data-idx'), 10);
        var url = lastOutputs[oi];
        if (!url) { flash(openBtn, 'Empty', 'bad'); return; }
        try { window.location.href = url; flash(openBtn, 'Opening…'); }
        catch (e) { flash(openBtn, 'No handler', 'bad'); }
      }
    });

    $('copyAllBtn').addEventListener('click', function () {
      var btn = this;
      if (!lastOutputs.length) { flash(btn, 'Nothing yet', 'bad'); return; }
      copyToClipboard(lastOutputs.join('\n')).then(function () { flash(btn, 'Copied!'); }).catch(function () { flash(btn, 'Failed', 'bad'); });
    });

    $('downloadBtn').addEventListener('click', function () {
      var btn = this;
      if (!lastOutputs.length) { flash(btn, 'Nothing yet', 'bad'); return; }
      var ok = downloadConfigs(lastOutputs.join('\n'), 'arpam-optimized-' + Date.now() + '.txt');
      flash(btn, ok ? 'Saved' : 'Failed', ok ? 'done' : 'bad');
    });

    $('clearResultBtn').addEventListener('click', function () {
      lastOutputs = [];
      resultList.innerHTML = '';
      errorList.innerHTML = '';
      errorList.hidden = true;
      resultCard.hidden = true;
    });

    $('themeToggle').addEventListener('click', function () {
      applyTheme(root.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
      if (this.blur) this.blur();
    });

    inputArea.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runOptimize($('optimizeBtn')); }
    });

    window.addEventListener('error', function (e) { if (e && e.preventDefault) e.preventDefault(); });
  }

  /* Exposed for testing in the browser console. */
  window.ArpamOptimizer = {
    DEFAULTS: DEFAULTS,
    parseVless: parseVless,
    validateVless: validateVless,
    normalizeParams: normalizeParams,
    encodeFinalMask: encodeFinalMask,
    optimizeVless: optimizeVless,
    buildVless: buildVless,
    optimizeMultipleConfigs: optimizeMultipleConfigs,
    copyToClipboard: copyToClipboard,
    downloadConfigs: downloadConfigs
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
