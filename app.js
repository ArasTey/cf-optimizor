/* ═══════════════════════════════════════════════════════════
   ARPAM · CDN CONFIG OPTIMIZER — app.js
   100% client-side. No network calls at all.
   ═══════════════════════════════════════════════════════════ */
(function () {
'use strict';

/* ───────── 1. DEFAULTS ───────── */
var FM_DEFAULT = {
  tcp: [
    { fragment: "tlshello", lengths: ["5", "94", "1"], delays: ["0"], maxSplit: "0" },
    { fragment: "1-1", lengths: ["109", "1"], delays: ["1"], maxSplit: "355" }
  ]
};

var CS_DEFAULT = [
  'TLS_AES_256_GCM_SHA384','TLS_CHACHA20_POLY1305_SHA256','TLS_AES_128_GCM_SHA256',
  'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384','TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256','TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256','TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA','TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256','TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'
].join(':');

var DEFAULTS = {
  cdnIp: '188.114.97.6',
  fp: 'unsafe',
  cs: CS_DEFAULT,
  fm: JSON.stringify(FM_DEFAULT, null, 2)
};

var PARAM_ORDER = ['cs','path','security','alpn','encryption','fm','insecure','host','fp','type','allowInsecure','sni'];
var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
var SETTINGS_KEY = 'arpam_optimizer_settings';
var THEME_KEY = 'arpam_theme';

/* ───────── 2. HELPERS ───────── */
function $(id){ return document.getElementById(id); }
function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g, function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
function safeDecode(s){ try { return decodeURIComponent(s); } catch(e){ return s; } }
function closestOf(el, sel){ while(el && el.nodeType===1){ if(el.matches&&el.matches(sel)) return el; el=el.parentElement; } return null; }
function VlessError(msg, detail){ this.name='VlessError'; this.message=msg; this.detail=detail||''; }
VlessError.prototype = Object.create(Error.prototype);

function flash(btn, text, cls, ms){
  if(!btn) return;
  var label = btn.querySelector('span'), old = label ? label.textContent : btn.textContent;
  if(label) label.textContent = text; else btn.textContent = text;
  btn.classList.add(cls || 'done');
  clearTimeout(btn._t);
  btn._t = setTimeout(function(){
    if(label) label.textContent = old; else btn.textContent = old;
    btn.classList.remove('done','bad');
  }, ms || 1400);
}

/* ───────── 3. PARSE ───────── */
function parseQuery(qs){
  var out = [];
  if(!qs) return out;
  qs.split('&').forEach(function(pair){
    if(!pair) return;
    var i = pair.indexOf('=');
    var k = i < 0 ? pair : pair.slice(0, i);
    var v = i < 0 ? '' : pair.slice(i + 1);
    out.push({ key: safeDecode(k), value: safeDecode(v.replace(/\+/g,' ')) });
  });
  return out;
}

function parseVless(raw){
  var line = String(raw || '').trim();
  if(!line) throw new VlessError('Empty configuration');
  if(!/^vless:\/\//i.test(line)) throw new VlessError('Invalid VLESS configuration', 'URL must start with vless://');

  var body = line.slice(8);
  var frag = '', h = body.indexOf('#');
  if(h >= 0){ frag = body.slice(h + 1); body = body.slice(0, h); }

  var query = '', q = body.indexOf('?');
  if(q >= 0){ query = body.slice(q + 1); body = body.slice(0, q); }

  var at = body.lastIndexOf('@');
  if(at < 0) throw new VlessError('Invalid VLESS configuration', 'Missing "@" separator');

  var uuid = safeDecode(body.slice(0, at)).trim();
  var authority = body.slice(at + 1).trim();
  if(!uuid) throw new VlessError('Invalid VLESS configuration', 'Missing UUID');
  if(!UUID_RE.test(uuid)) throw new VlessError('Invalid VLESS configuration', 'UUID is not valid: ' + uuid);
  if(!authority) throw new VlessError('Invalid VLESS configuration', 'Missing host');

  var host = authority, port = '';
  if(authority.charAt(0) === '['){                    // IPv6
    var close = authority.indexOf(']');
    if(close < 0) throw new VlessError('Invalid VLESS configuration', 'Malformed IPv6 host');
    host = authority.slice(0, close + 1);
    if(authority.charAt(close + 1) === ':') port = authority.slice(close + 2);
  } else {
    var c = authority.lastIndexOf(':');
    if(c > 0){ host = authority.slice(0, c); port = authority.slice(c + 1); }
  }
  if(!host) throw new VlessError('Invalid VLESS configuration', 'Missing host');
  if(port && !/^\d{1,5}$/.test(port)) throw new VlessError('Invalid VLESS configuration', 'Invalid port: ' + port);

  return { uuid: uuid, host: host, port: port, params: parseQuery(query), fragment: frag, raw: line };
}

function validateVless(raw){
  try { parseVless(raw); return { valid: true, error: null }; }
  catch(e){ return { valid: false, error: e.message + (e.detail ? ' — ' + e.detail : '') }; }
}

/* ───────── 4. PARAM UTILS ───────── */
function getParam(params, key){
  var k = key.toLowerCase();
  for(var i = 0; i < params.length; i++) if(params[i].key.toLowerCase() === k) return params[i].value;
  return null;
}
function setParam(params, key, value){
  var k = key.toLowerCase(), found = false;
  for(var i = params.length - 1; i >= 0; i--){
    if(params[i].key.toLowerCase() === k){
      if(found){ params.splice(i, 1); continue; }   // dedupe
      params[i].key = key; params[i].value = value; found = true;
    }
  }
  if(!found) params.push({ key: key, value: value });
  return params;
}
function normalizeParams(params){
  var seen = {}, out = [];
  params.forEach(function(p){
    if(!p.key) return;
    var k = p.key.toLowerCase();
    if(seen[k] !== undefined){ out[seen[k]] = { key: p.key, value: p.value }; return; }
    seen[k] = out.length; out.push({ key: p.key, value: p.value });
  });
  return out;
}
function sortParams(params){
  var idx = {}; PARAM_ORDER.forEach(function(k, i){ idx[k] = i; });
  var known = [], unknown = [];
  params.forEach(function(p){ (idx[p.key.toLowerCase()] !== undefined ? known : unknown).push(p); });
  known.sort(function(a, b){ return idx[a.key.toLowerCase()] - idx[b.key.toLowerCase()]; });
  return known.concat(unknown);                      // unknown params preserved
}
function encodeFinalMask(fmValue){
  var text = typeof fmValue === 'string' ? fmValue : JSON.stringify(fmValue);
  var obj;
  try { obj = JSON.parse(text); } catch(e){ throw new VlessError('Invalid FinalMask JSON', e.message); }
  return JSON.stringify(obj);
}

/* ───────── 5. BUILD ───────── */
function buildVless(cfg){
  var params = sortParams(normalizeParams(cfg.params || []));
  var qs = params.map(function(p){
    return encodeURIComponent(p.key) + '=' + encodeURIComponent(p.value);
  }).join('&');
  var authority = cfg.host + (cfg.port ? ':' + cfg.port : '');
  var url = 'vless://' + cfg.uuid + '@' + authority;
  if(qs) url += '?' + qs;
  if(cfg.fragment) url += '#' + cfg.fragment;        // preserved byte-for-byte
  return url;
}

/* ───────── 6. OPTIMIZE ───────── */
function optimizeVless(raw, opts){
  var o = opts || {};
  var cdnIp = (o.cdnIp || DEFAULTS.cdnIp).trim();
  var fp = (o.fp || DEFAULTS.fp).trim();
  var cs = (o.cs !== undefined && o.cs !== null && String(o.cs).trim() !== '') ? String(o.cs).trim() : DEFAULTS.cs;
  var fmRaw = (o.fm !== undefined && o.fm !== null && String(o.fm).trim() !== '') ? o.fm : DEFAULTS.fm;
  var fm = encodeFinalMask(fmRaw);

  var cfg = parseVless(raw);
  var changes = [];

  var oldHost = cfg.host;
  if(oldHost !== cdnIp){
    cfg.host = cdnIp;
    changes.push({ type: 'upd', label: 'Address', from: oldHost, to: cdnIp });
  } else {
    changes.push({ type: 'keep', label: 'Address', to: cdnIp });
  }

  var oldFp = getParam(cfg.params, 'fp');
  setParam(cfg.params, 'fp', fp);
  if(oldFp === null) changes.push({ type: 'add', label: 'Fingerprint', to: fp });
  else if(oldFp !== fp) changes.push({ type: 'upd', label: 'Fingerprint', from: oldFp, to: fp });
  else changes.push({ type: 'keep', label: 'Fingerprint', to: fp });

  var oldCs = getParam(cfg.params, 'cs');
  setParam(cfg.params, 'cs', cs);
  changes.push(oldCs === null ? { type: 'add', label: 'Cipher Suites' }
             : (oldCs !== cs ? { type: 'upd', label: 'Cipher Suites' } : { type: 'keep', label: 'Cipher Suites' }));

  var oldFm = getParam(cfg.params, 'fm');
  setParam(cfg.params, 'fm', fm);
  changes.push(oldFm === null ? { type: 'add', label: 'FinalMask' }
             : (oldFm !== fm ? { type: 'upd', label: 'FinalMask' } : { type: 'keep', label: 'FinalMask' }));

  return { url: buildVless(cfg), name: cfg.fragment ? safeDecode(cfg.fragment) : '', changes: changes, config: cfg };
}

function optimizeMultipleConfigs(text, opts){
  var lines = String(text || '').split(/\r?\n/).map(function(l){ return l.trim(); }).filter(Boolean);
  var results = [], errors = [];
  lines.forEach(function(line, i){
    try { results.push(optimizeVless(line, opts)); }
    catch(e){ errors.push({ line: i + 1, message: e.message || 'Invalid configuration', detail: e.detail || line.slice(0, 90) }); }
  });
  return { results: results, errors: errors, total: lines.length };
}

/* ───────── 7. CLIPBOARD / DOWNLOAD ───────── */
function legacyCopy(text){
  var ta = document.createElement('textarea');
  ta.value = text; ta.setAttribute('readonly',''); ta.style.cssText = 'position:fixed;top:-9999px;opacity:0';
  document.body.appendChild(ta); ta.select();
  var ok = false; try { ok = document.execCommand('copy'); } catch(e){}
  document.body.removeChild(ta); return ok;
}
function copyToClipboard(text){
  if(navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext){
    return navigator.clipboard.writeText(text).then(function(){ return true; })
      .catch(function(){ return legacyCopy(text); });
  }
  return Promise.resolve(legacyCopy(text));
}
function downloadConfigs(list, filename){
  var blob = new Blob([list.join('\n') + '\n'], { type: 'text/plain;charset=utf-8' });
  var url = URL.createObjectURL(blob), a = document.createElement('a');
  a.href = url; a.download = filename || ('arpam-optimized-' + Date.now() + '.txt');
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(function(){ URL.revokeObjectURL(url); }, 1500);
}

/* ───────── 8. SETTINGS ───────── */
function loadSettings(){
  var s = {};
  try { s = JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') || {}; } catch(e){ s = {}; }
  return {
    cdnIp: typeof s.cdnIp === 'string' && s.cdnIp ? s.cdnIp : DEFAULTS.cdnIp,
    fp: typeof s.fp === 'string' && s.fp ? s.fp : DEFAULTS.fp,
    cs: typeof s.cs === 'string' && s.cs ? s.cs : DEFAULTS.cs,
    fm: typeof s.fm === 'string' && s.fm ? s.fm : DEFAULTS.fm
  };
}
function saveSettings(s){ try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(s)); } catch(e){} }

/* ───────── 9. THEME ───────── */
function applyTheme(next){
  var html = document.documentElement;
  html.classList.add('theming');
  html.setAttribute('data-theme', next);
  var m = $('metaThemeColor'); if(m) m.setAttribute('content', next === 'light' ? '#f1f4f9' : '#0b0b10');
  try { localStorage.setItem(THEME_KEY, next); } catch(e){}
  clearTimeout(applyTheme._t);
  applyTheme._t = setTimeout(function(){ html.classList.remove('theming'); }, 460);
}

/* ───────── 10. UI ───────── */
function init(){
  var settings = loadSettings();

  var themeToggle=$('themeToggle'), dropZone=$('dropZone'), inputArea=$('inputArea'),
      optimizeBtn=$('optimizeBtn'), pasteBtn=$('pasteBtn'), fileBtn=$('fileBtn'), fileInput=$('fileInput'),
      clearBtn=$('clearBtn'), advCard=$('advCard'), advToggle=$('advToggle'), cdnIp=$('cdnIp'),
      defaultIpBtn=$('defaultIpBtn'), fpSelect=$('fpSelect'), csArea=$('csArea'), fmArea=$('fmArea'),
      fmHint=$('fmHint'), resetBtn=$('resetBtn'), resultCard=$('resultCard'), resultSummary=$('resultSummary'),
      copyAllBtn=$('copyAllBtn'), downloadBtn=$('downloadBtn'), clearResultBtn=$('clearResultBtn'),
      errorList=$('errorList'), resultList=$('resultList');

  if(!inputArea || !optimizeBtn) return;

  var lastResults = [];

  /* theme */
  if(themeToggle) themeToggle.addEventListener('click', function(){
    applyTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
  });

  /* settings fields */
  cdnIp.value = settings.cdnIp; fpSelect.value = settings.fp;
  csArea.value = settings.cs;   fmArea.value = settings.fm;

  function currentOpts(){
    return { cdnIp: cdnIp.value.trim() || DEFAULTS.cdnIp, fp: fpSelect.value,
             cs: csArea.value.trim() || DEFAULTS.cs, fm: fmArea.value.trim() || DEFAULTS.fm };
  }
  function persist(){ saveSettings(currentOpts()); }
  function checkFm(){
    var v = fmArea.value.trim();
    if(!v){ fmHint.textContent = 'Empty — default FinalMask will be used'; fmHint.classList.remove('bad'); return true; }
    try { JSON.parse(v); fmHint.textContent = 'Valid JSON'; fmHint.classList.remove('bad'); return true; }
    catch(e){ fmHint.textContent = 'Invalid JSON — ' + e.message; fmHint.classList.add('bad'); return false; }
  }
  [cdnIp, csArea].forEach(function(el){ el.addEventListener('input', persist); });
  fpSelect.addEventListener('change', persist);
  fmArea.addEventListener('input', function(){ checkFm(); persist(); });
  checkFm();

  defaultIpBtn.addEventListener('click', function(){ cdnIp.value = DEFAULTS.cdnIp; persist(); flash(defaultIpBtn,'Set','done',1100); });
  resetBtn.addEventListener('click', function(){
    cdnIp.value = DEFAULTS.cdnIp; fpSelect.value = DEFAULTS.fp; csArea.value = DEFAULTS.cs; fmArea.value = DEFAULTS.fm;
    checkFm(); persist(); flash(resetBtn, 'Reset', 'done', 1200);
  });

  /* accordion */
  function toggleAcc(card, btn){
    var open = card.classList.toggle('open');
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    return open;
  }
  advToggle.addEventListener('click', function(){ toggleAcc(advCard, advToggle); });

  /* input actions */
  pasteBtn.addEventListener('click', function(){
    if(navigator.clipboard && navigator.clipboard.readText){
      navigator.clipboard.readText().then(function(t){
        if(t){ inputArea.value = (inputArea.value.trim() ? inputArea.value.trim() + '\n' : '') + t.trim(); flash(pasteBtn,'Pasted'); }
        else flash(pasteBtn,'Empty','bad');
      }).catch(function(){ inputArea.focus(); flash(pasteBtn,'Use Ctrl+V','bad',1800); });
    } else { inputArea.focus(); flash(pasteBtn,'Use Ctrl+V','bad',1800); }
  });
  clearBtn.addEventListener('click', function(){ inputArea.value=''; inputArea.focus(); flash(clearBtn,'Cleared'); });
  fileBtn.addEventListener('click', function(){ fileInput.click(); });
  fileInput.addEventListener('change', function(){ if(fileInput.files && fileInput.files[0]) readFile(fileInput.files[0]); fileInput.value=''; });

  function readFile(file){
    var r = new FileReader();
    r.onload = function(){
      var t = String(r.result || '').trim();
      inputArea.value = (inputArea.value.trim() ? inputArea.value.trim() + '\n' : '') + t;
      run();
    };
    r.onerror = function(){ flash(fileBtn, 'Failed', 'bad'); };
    r.readAsText(file);
  }

  ['dragenter','dragover'].forEach(function(ev){
    dropZone.addEventListener(ev, function(e){ e.preventDefault(); dropZone.classList.add('dragging'); });
  });
  ['dragleave','drop'].forEach(function(ev){
    dropZone.addEventListener(ev, function(e){
      e.preventDefault();
      if(ev === 'dragleave' && e.relatedTarget && dropZone.contains(e.relatedTarget)) return;
      dropZone.classList.remove('dragging');
    });
  });
  dropZone.addEventListener('drop', function(e){
    var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if(f) readFile(f);
    else { var t = e.dataTransfer && e.dataTransfer.getData('text'); if(t){ inputArea.value = t.trim(); run(); } }
  });

  inputArea.addEventListener('keydown', function(e){
    if((e.ctrlKey || e.metaKey) && e.key === 'Enter'){ e.preventDefault(); run(); }
  });
  optimizeBtn.addEventListener('click', run);

  /* render */
  function chgChip(c){
    var txt = c.label;
    if(c.type === 'upd' && c.from) txt += ': <b>' + esc(c.from) + '</b> → <b>' + esc(c.to) + '</b>';
    else if(c.type === 'add') txt += ' Added';
    else if(c.type === 'upd') txt += ' Updated';
    else txt += c.to ? ': <b>' + esc(c.to) + '</b>' : ' Unchanged';
    return '<span class="chg ' + c.type + '">' + txt + '</span>';
  }

  function render(out){
    lastResults = out.results.map(function(r){ return r.url; });

    errorList.innerHTML = out.errors.map(function(e){
      return '<div class="err"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"></circle><path d="M12 7.5v5.2M12 16.2v.1"></path></svg>'
           + '<div><b>Line ' + e.line + ' — ' + esc(e.message) + '</b><span>' + esc(e.detail || 'Please check the URL and try again.') + '</span></div></div>';
    }).join('');

    resultList.innerHTML = out.results.map(function(r, i){
      return '<div class="res">'
        + '<div class="res-top">'
          + '<span class="res-num">' + (i + 1) + '</span>'
          + '<span class="res-name">' + esc(r.name || 'Configuration ' + (i + 1)) + '</span>'
          + '<button type="button" class="btn btn-soft btn-sm copy-one" data-i="' + i + '"><span>Copy</span></button>'
          + '<button type="button" class="btn btn-soft btn-sm open-one" data-i="' + i + '"><span>Import</span></button>'
        + '</div>'
        + '<div class="res-out">' + esc(r.url) + '</div>'
        + '<div class="changes">' + r.changes.map(chgChip).join('') + '</div>'
      + '</div>';
    }).join('');

    var n = out.results.length;
    resultSummary.textContent = n
      ? (n + ' configuration' + (n > 1 ? 's' : '') + ' optimized successfully' + (out.errors.length ? ' · ' + out.errors.length + ' failed' : ''))
      : (out.errors.length + ' configuration' + (out.errors.length > 1 ? 's' : '') + ' failed');

    resultCard.hidden = false;
    copyAllBtn.disabled = downloadBtn.disabled = n === 0;
    if(n || out.errors.length) resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function run(){
    var text = inputArea.value.trim();
    if(!text){ flash(optimizeBtn, 'Paste a config', 'bad', 1600); inputArea.focus(); return; }
    if(!checkFm()){ if(!advCard.classList.contains('open')) toggleAcc(advCard, advToggle); fmArea.focus(); return; }
    var out;
    try { out = optimizeMultipleConfigs(text, currentOpts()); }
    catch(e){
      errorList.innerHTML = '<div class="err"><div><b>' + esc(e.message || 'Unexpected error') + '</b><span>' + esc(e.detail || '') + '</span></div></div>';
      resultCard.hidden = false; return;
    }
    render(out);
  }

  resultList.addEventListener('click', function(e){
    var c = closestOf(e.target, '.copy-one'), o = closestOf(e.target, '.open-one');
    if(c){ var i = +c.dataset.i; copyToClipboard(lastResults[i]).then(function(ok){ flash(c, ok ? 'Copied' : 'Failed', ok ? 'done' : 'bad'); }); }
    else if(o){ var j = +o.dataset.i; try { window.location.href = lastResults[j]; flash(o, 'Opening'); } catch(err){ flash(o, 'Failed', 'bad'); } }
  });

  copyAllBtn.addEventListener('click', function(){
    if(!lastResults.length) return;
    copyToClipboard(lastResults.join('\n')).then(function(ok){ flash(copyAllBtn, ok ? 'Copied' : 'Failed', ok ? 'done' : 'bad'); });
  });
  downloadBtn.addEventListener('click', function(){
    if(!lastResults.length) return;
    downloadConfigs(lastResults); flash(downloadBtn, 'Saved');
  });
  clearResultBtn.addEventListener('click', function(){
    lastResults = []; resultList.innerHTML = ''; errorList.innerHTML = '';
    resultSummary.textContent = '—'; resultCard.hidden = true;
  });

  /* public test API */
  window.ArpamOptimizer = {
    DEFAULTS: DEFAULTS,
    parseVless: parseVless, validateVless: validateVless, normalizeParams: normalizeParams,
    sortParams: sortParams, getParam: getParam, setParam: setParam, encodeFinalMask: encodeFinalMask,
    optimizeVless: optimizeVless, buildVless: buildVless, optimizeMultipleConfigs: optimizeMultipleConfigs,
    copyToClipboard: copyToClipboard, legacyCopy: legacyCopy, downloadConfigs: downloadConfigs
  };
}

if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();

})();
