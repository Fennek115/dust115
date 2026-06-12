// APT115 CODEX ARCANUM — URL / Domain Inspector
// quod est superius est sicut quod inferius
//
// Pegás una o varias URLs/dominios (uno por línea) y los descompone + evalúa el riesgo:
//   · Descomposición (scheme/userinfo/host/puerto/path/query) vía la URL API.
//   · Punycode (xn--) → Unicode (RFC 3492 propio) + homógrafo IDN por MEZCLA DE SCRIPTS
//     (а/е/о cirílicas o griegas haciéndose pasar por latinas — IDN homograph attack).
//   · Typosquatting: distancia de Levenshtein a marcas conocidas + marca en subdominio
//     cuando el dominio registrado NO es de la marca (paypal.com.evil.ru → evil.ru).
//   · DGA heurístico: entropía Shannon, ratio de vocales, corrida de consonantes, dígitos.
//   · TLDs abusados, IP como host (decimal/hex), credenciales en URL, sobre-encoding, etc.
// 100% local: ningún lookup se dispara solo (los botones sólo abren un link al click).

export const urlinsp = (function () {
  'use strict';

  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

  // ── Refang ──────────────────────────────────────────────────────────────────
  function refang(t) {
    return String(t).replace(/h(?:tt|xx)ps/gi, 'https').replace(/h(?:tt|xx)p/gi, 'http')
      .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)/g, '.').replace(/\[\s*dot\s*\]/gi, '.').replace(/\[\s*:\s*\]/g, ':').replace(/\[\s*:?\/\/\s*\]/g, '://');
  }

  // ── Punycode decode (RFC 3492) ──────────────────────────────────────────────
  const B = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, IBIAS = 72, IN = 128;
  function adapt(delta, n, first) {
    delta = first ? Math.floor(delta / DAMP) : delta >> 1;
    delta += Math.floor(delta / n);
    let k = 0;
    for (; delta > ((B - TMIN) * TMAX) >> 1; k += B) delta = Math.floor(delta / (B - TMIN));
    return Math.floor(k + (B - TMIN + 1) * delta / (delta + SKEW));
  }
  function punyDecode(input) {
    const out = [];
    let n = IN, bias = IBIAS, i = 0;
    const b = input.lastIndexOf('-');
    for (let j = 0; j < Math.max(0, b); j++) { if (input.charCodeAt(j) >= 0x80) throw new Error('non-basic'); out.push(input.charCodeAt(j)); }
    let idx = b < 0 ? 0 : b + 1;
    while (idx < input.length) {
      const oldi = i;
      let w = 1;
      for (let k = B; ; k += B) {
        if (idx >= input.length) throw new Error('bad input');
        const cp = input.charCodeAt(idx++);
        let digit;
        if (cp - 48 < 10 && cp >= 48) digit = cp - 22;
        else if (cp - 65 < 26 && cp >= 65) digit = cp - 65;
        else if (cp - 97 < 26 && cp >= 97) digit = cp - 97;
        else throw new Error('bad digit');
        i += digit * w;
        const t = k <= bias ? TMIN : (k >= bias + TMAX ? TMAX : k - bias);
        if (digit < t) break;
        w *= B - t;
      }
      const outLen = out.length + 1;
      bias = adapt(i - oldi, outLen, oldi === 0);
      n += Math.floor(i / outLen);
      i %= outLen;
      out.splice(i, 0, n);
      i++;
    }
    return String.fromCodePoint(...out);
  }
  // Decodifica un hostname con labels xn-- a Unicode (lo demás intacto).
  function idnToUnicode(host) {
    return host.split('.').map(l => {
      if (/^xn--/i.test(l)) { try { return punyDecode(l.slice(4)); } catch (e) { return l; } }
      return l;
    }).join('.');
  }

  // ── Script de un código (para detectar mezcla / homógrafos) ─────────────────
  function scriptOf(cp) {
    if ((cp >= 0x41 && cp <= 0x5A) || (cp >= 0x61 && cp <= 0x7A) || (cp >= 0xC0 && cp <= 0x24F)) return 'Latin';
    if (cp >= 0x0400 && cp <= 0x04FF) return 'Cyrillic';
    if (cp >= 0x0370 && cp <= 0x03FF) return 'Greek';
    if (cp >= 0x0530 && cp <= 0x058F) return 'Armenian';
    if (cp >= 0x0590 && cp <= 0x05FF) return 'Hebrew';
    if (cp >= 0x0600 && cp <= 0x06FF) return 'Arabic';
    if (cp >= 0x4E00 && cp <= 0x9FFF) return 'Han';
    if ((cp >= 0x30 && cp <= 0x39) || cp === 0x2D || cp === 0x2E) return 'common';
    return 'other';
  }
  function scriptsOf(str) {
    const set = new Set();
    for (const ch of str) { const s = scriptOf(ch.codePointAt(0)); if (s !== 'common') set.add(s); }
    return [...set];
  }

  // ── Levenshtein + marcas ────────────────────────────────────────────────────
  function lev(a, b) {
    const m = a.length, n = b.length;
    if (!m) return n; if (!n) return m;
    let prev = Array.from({ length: n + 1 }, (_, i) => i);
    for (let i = 1; i <= m; i++) {
      let cur = [i];
      for (let j = 1; j <= n; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
    return prev[n];
  }
  const BRANDS = ['paypal', 'microsoft', 'apple', 'amazon', 'google', 'facebook', 'instagram',
    'netflix', 'linkedin', 'twitter', 'whatsapp', 'outlook', 'office365', 'gmail', 'yahoo',
    'chase', 'wellsfargo', 'citibank', 'coinbase', 'binance', 'metamask', 'dhl', 'fedex',
    'ups', 'usps', 'docusign', 'dropbox', 'adobe', 'steam', 'discord', 'roblox', 'spotify'];

  const ABUSED_TLD = new Set(('tk ml ga cf gq top xyz zip mov country gdn work click link rest ' +
    'fit loan men review download stream science party racing date faith cricket win bid').split(' '));
  const MULTI_TLD = new Set(('co.uk org.uk gov.uk ac.uk com.au net.au com.br com.mx co.jp co.in com.cn com.tr co.za').split(' '));

  function registeredDomain(host) {
    const p = host.split('.');
    if (p.length <= 2) return host;
    const last2 = p.slice(-2).join('.');
    if (MULTI_TLD.has(last2)) return p.slice(-3).join('.');
    return last2;
  }

  // ── DGA heurístico sobre el label principal ─────────────────────────────────
  function entropy(s) {
    const f = {}; for (const c of s) f[c] = (f[c] || 0) + 1;
    let h = 0; for (const k in f) { const p = f[k] / s.length; h -= p * Math.log2(p); }
    return h;
  }
  function dgaScore(label) {
    label = label.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (label.length < 7) return { score: 0, verdict: 'corto' };
    const vowels = (label.match(/[aeiou]/g) || []).length;
    const digits = (label.match(/[0-9]/g) || []).length;
    const vowelRatio = vowels / label.length;
    const digitRatio = digits / label.length;
    let maxCons = 0, cur = 0;
    for (const c of label) { if (/[bcdfghjklmnpqrstvwxz]/.test(c)) { cur++; maxCons = Math.max(maxCons, cur); } else cur = 0; }
    const h = entropy(label);
    let score = 0;
    if (h > 3.6) score += 30; else if (h > 3.2) score += 18;
    if (vowelRatio < 0.25) score += 25; else if (vowelRatio < 0.32) score += 12;
    if (maxCons >= 5) score += 25; else if (maxCons >= 4) score += 12;
    if (digitRatio > 0.25) score += 15;
    if (label.length > 14) score += 10;
    score = Math.min(100, score);
    return { score, h, vowelRatio, digitRatio, maxCons, verdict: score >= 60 ? 'probable DGA' : score >= 35 ? 'sospechoso' : 'normal' };
  }

  // ── Análisis de un objetivo ─────────────────────────────────────────────────
  function analyzeOne(raw) {
    raw = refang(raw.trim());
    if (!raw) return null;
    let u;
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : ('http://' + raw);
    try { u = new URL(withScheme); } catch (e) { return { raw, error: 'no se pudo parsear como URL/dominio' }; }

    const host = u.hostname;
    const unicode = idnToUnicode(host);
    const hasPuny = /(^|\.)xn--/i.test(host);
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    const regDom = isIp ? host : registeredDomain(host);
    const tld = host.split('.').pop().toLowerCase();
    const labels = host.split('.');
    // DGA sobre el label principal en UNICODE (un label xn-- decodificado de otro script
    // queda sin chars a-z y no puntúa; sólo los aleatorios latinos disparan).
    const mainLabel = isIp ? '' : idnToUnicode(regDom).split('.')[0];
    const dga = isIp ? { score: 0, verdict: 'ip' } : dgaScore(mainLabel);

    // Scripts POR LABEL. La mezcla relevante es DENTRO de un label; un label no-latino
    // sólo "imita latino" si el TLD es de otro script (аррӏе.com sí; пример.рф no).
    const uniLabels = unicode.split('.');
    const tldScript = scriptsOf(uniLabels[uniLabels.length - 1])[0] || 'Latin';
    let mixedLabel = false, nonLatinLabel = '';
    for (let i = 0; i < uniLabels.length - 1; i++) { // excluye el TLD
      const sc = scriptsOf(uniLabels[i]);
      if (sc.length > 1) mixedLabel = true;
      else if (sc.length === 1 && sc[0] !== 'Latin') nonLatinLabel = sc[0];
    }
    const scripts = scriptsOf(unicode);
    const flags = [];

    if (hasPuny) flags.push(['med', 'dominio punycode (IDN): ' + esc(host) + ' → ' + esc(unicode)]);
    if (mixedLabel) flags.push(['high', 'MEZCLA DE SCRIPTS dentro de un label del host — ataque homógrafo IDN (letras que imitan latinas)']);
    else if (nonLatinLabel && nonLatinLabel !== tldScript) flags.push([hasPuny ? 'high' : 'med', 'label del host en script ' + nonLatinLabel + ' bajo un TLD ' + tldScript + ' — homógrafo imitando un dominio latino']);

    // Typosquat: look-alike (leet/typo) por token, luego marca correcta fuera del dominio.
    const hostLo = host.toLowerCase();
    const leet = (s) => s.replace(/[1|!]/g, 'l').replace(/0/g, 'o').replace(/3/g, 'e').replace(/[5$]/g, 's').replace(/[4@]/g, 'a').replace(/7/g, 't');
    let brandFlag = false;
    for (const tok of hostLo.split(/[.\-_]/)) {
      if (tok.length < 4) continue;
      const norm = leet(tok);
      for (const brand of BRANDS) {
        const d = lev(norm, brand);
        if ((d === 0 && tok !== brand) || (d === 1 && Math.abs(norm.length - brand.length) <= 1)) {
          flags.push(['high', 'look-alike de "' + brand + '" en "' + esc(tok) + '" → dominio registrado ' + esc(regDom)]);
          brandFlag = true; break;
        }
      }
      if (brandFlag) break;
    }
    if (!brandFlag) for (const brand of BRANDS) {
      if (hostLo.includes(brand) && !regDom.toLowerCase().startsWith(brand)) {
        flags.push(['high', 'la marca "' + brand + '" aparece en el host pero el dominio registrado es ' + esc(regDom) + ' — no pertenece a la marca']); break;
      }
    }

    if (isIp) flags.push(['med', 'host es una IP literal (' + host + ') — evita el DNS / oculta el dominio']);
    else if (/^\d+$/.test(host) || /^0x/i.test(host)) flags.push(['high', 'host numérico (IP ofuscada decimal/hex)']);
    if (u.username || u.password || raw.includes('@') && !u.username && /@/.test(raw.split('//').pop().split('/')[0]))
      flags.push(['high', 'credenciales / "@" en la URL (' + esc(u.username || '') + ') — truco para ocultar el host real']);
    if (ABUSED_TLD.has(tld)) flags.push(['med', 'TLD frecuentemente abusado (.' + tld + ')']);
    if (labels.length > 4) flags.push(['low', labels.length + ' subdominios — host largo, posible camuflaje']);
    if ((raw.match(/%[0-9a-f]{2}/gi) || []).length > 6) flags.push(['med', 'percent-encoding excesivo — posible ofuscación']);
    if (u.port && !['80', '443', '8080', '8443'].includes(u.port)) flags.push(['low', 'puerto no estándar (' + u.port + ')']);
    if (/^(data|javascript|file|vbscript):/i.test(raw)) flags.push(['high', 'esquema peligroso (' + raw.split(':')[0] + ':)']);
    if (dga.score >= 35) flags.push([dga.score >= 60 ? 'high' : 'med', 'label "' + esc(mainLabel) + '" parece ' + dga.verdict +
      ' (entropía ' + dga.h.toFixed(2) + ', vocales ' + (dga.vowelRatio * 100).toFixed(0) + '%, consonantes seguidas ' + dga.maxCons + ')']);

    const risk = flags.some(f => f[0] === 'high') ? 'high' : flags.some(f => f[0] === 'med') ? 'med' : flags.length ? 'low' : 'clean';
    return { raw, url: u, host, unicode, hasPuny, scripts, regDom, tld, isIp, dga, flags, risk };
  }

  // ── Render ──────────────────────────────────────────────────────────────────
  function riskBadge(r) {
    const map = { high: ['hi', 'ALTO'], med: ['mid', 'MEDIO'], low: ['lo', 'BAJO'], clean: ['lo', 'sin señales'] };
    const m = map[r] || map.clean;
    return '<span class="lab-ent ' + m[0] + '">' + m[1] + '</span>';
  }
  function kv(rows) { return '<table class="lab-kv mono"><tbody>' + rows.map(r => '<tr><th>' + r[0] + '</th><td>' + r[1] + '</td></tr>').join('') + '</tbody></table>'; }

  function renderOne(res) {
    if (!res) return '';
    if (res.error) return '<div class="lab-panel"><div class="lab-panel-b"><div class="lab-err">' + esc(res.raw) + ' — ' + esc(res.error) + '</div></div></div>';
    const u = res.url;
    let html = '<div class="lab-panel"><div class="lab-panel-h">' + riskBadge(res.risk) + ' <code>' + esc(res.raw.slice(0, 120)) + '</code><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">';
    const rows = [
      ['scheme', esc(u.protocol.replace(':', ''))],
      ['host', '<code>' + esc(res.host) + '</code>' + (res.hasPuny ? ' → <b>' + esc(res.unicode) + '</b>' : '')],
      ['dominio registrado', '<code>' + esc(res.regDom) + '</code>'],
    ];
    if (u.port) rows.push(['puerto', esc(u.port)]);
    if (u.username) rows.push(['userinfo', '<span class="ds-warn">' + esc(u.username) + (u.password ? ':***' : '') + '</span>']);
    if (u.pathname && u.pathname !== '/') rows.push(['path', '<code>' + esc(u.pathname.slice(0, 200)) + '</code>']);
    if (u.search) rows.push(['query', '<code>' + esc(u.search.slice(0, 200)) + '</code>']);
    html += kv(rows);

    if (res.flags.length) {
      html += '<div class="lab-sub">Señales (' + res.flags.length + ')</div><div class="lab-note">' +
        res.flags.map(f => (f[0] === 'high' ? '⚠ ' : f[0] === 'med' ? '• ' : '· ') + esc(f[1])).join('<br>') + '</div>';
    } else {
      html += '<div class="lab-note">Sin señales de riesgo evidentes. No es prueba de inocuidad.</div>';
    }

    // Lookups opt-in (sólo abren el link al click)
    const enc = encodeURIComponent(res.raw);
    const domEnc = encodeURIComponent(res.regDom);
    html += '<div class="lab-actions">' +
      ext('VirusTotal', 'https://www.virustotal.com/gui/search/' + enc) +
      ext('urlscan.io', 'https://urlscan.io/search/#' + domEnc) +
      ext('Whois', 'https://who.is/whois/' + domEnc) +
      '<span class="lab-dim">— opt-in: nada se consulta hasta que hagas click</span></div>';
    html += '</div></div>';
    return html;
  }
  function ext(label, href) { return '<a class="lab-ext" href="' + href + '" target="_blank" rel="noopener noreferrer">↗ ' + label + '</a>'; }

  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🔎 URL / Domain Inspector</div>' +
      '<span class="sec-cmds-badge" id="uiBadge">0</span></div>' +
      '<div class="lab-intro">Pegá URLs o dominios (uno por línea). Descompone, decodifica punycode, ' +
      'detecta homógrafos IDN, typosquatting, DGA y trucos de ofuscación. 100% local — los lookups son opt-in.</div>' +
      '<textarea class="cv-io" id="uiIn" style="min-height:90px" spellcheck="false" ' +
        'placeholder="hxxps://paypa1-secure[.]com/login&#10;xn--80ak6aa92e.com&#10;http://0x7f000001/&#10;kq3v9z7x1la8b2.top"></textarea>' +
      '<div class="ioc-bar"><span class="lab-dim" id="uiHint">— escribí o pegá arriba</span></div>' +
      '<div id="uiOut"></div>';
    const inp = container.querySelector('#uiIn');
    let t;
    inp.oninput = () => { clearTimeout(t); t = setTimeout(() => renderOut(container), 200); };
  }

  function renderOut(container) {
    const lines = container.querySelector('#uiIn').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const out = container.querySelector('#uiOut');
    const badge = container.querySelector('#uiBadge');
    const hint = container.querySelector('#uiHint');
    if (!lines.length) { out.innerHTML = ''; badge.textContent = '0'; if (hint) hint.textContent = '— escribí o pegá arriba'; return; }
    const results = lines.slice(0, 100).map(analyzeOne).filter(Boolean);
    const risky = results.filter(r => r.risk === 'high' || r.risk === 'med').length;
    badge.textContent = results.length + (risky ? ' · ' + risky + ' ⚠' : '');
    if (hint) hint.textContent = '';
    out.innerHTML = results.map(renderOne).join('');
    out.querySelectorAll('.lab-panel-h').forEach(h => h.onclick = () => h.parentElement.classList.toggle('collapsed'));
  }

  if (typeof window !== 'undefined' && window.LAB) {
    LAB.registerTool({ id: 'urlinsp', label: 'URL / Domain Inspector', icon: '🔎', group: '🧪 LAB / TOOLS', render });
  }
  return { analyzeOne, punyDecode, idnToUnicode, scriptsOf, lev, dgaScore, registeredDomain, refang };
})();
