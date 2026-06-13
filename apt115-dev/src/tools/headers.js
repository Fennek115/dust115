// APT115 CODEX ARCANUM — Security Headers & CSP Analyzer
// quod est superius est sicut quod inferius
//
// Pegás los headers de una respuesta HTTP (o el bloque crudo con la status line)
// y los califico: HSTS (max-age/subdominios/preload), CSP (unsafe-inline/eval,
// comodines, directivas faltantes), X-Frame-Options / frame-ancestors,
// X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookies
// (Secure/HttpOnly/SameSite) y fuga de info (Server/X-Powered-By). Da una nota
// A+..F con hallazgos por severidad. 100% local, sin red — no hace requests.

export const headers = (function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ── Parsing ───────────────────────────────────────────────────────────
  /** Bloque crudo de headers → mapa (lowercase), cookies y lista ordenada. */
  function parseHeaders(raw) {
    /** @type {Record<string,string>} */
    const map = {};
    /** @type {string[]} */
    const cookies = [];
    /** @type {[string,string][]} */
    const all = [];
    for (const line of String(raw == null ? '' : raw).split(/\r?\n/)) {
      if (!line.trim()) continue;
      if (/^HTTP\/\d/i.test(line.trim())) continue;       // status line
      const i = line.indexOf(':');
      if (i <= 0) continue;
      const name = line.slice(0, i).trim();
      const val = line.slice(i + 1).trim();
      if (!name) continue;
      const lc = name.toLowerCase();
      all.push([name, val]);
      if (lc === 'set-cookie') cookies.push(val);
      else map[lc] = (lc in map) ? map[lc] + ', ' + val : val;
    }
    return { map, cookies, all };
  }

  /** Valor de CSP → mapa directiva→fuentes (lowercase la directiva). */
  function parseCsp(value) {
    /** @type {Record<string,string[]>} */
    const dirs = {};
    for (const part of String(value).split(';')) {
      const toks = part.trim().split(/\s+/).filter(Boolean);
      if (!toks.length) continue;
      dirs[toks[0].toLowerCase()] = toks.slice(1);
    }
    return dirs;
  }

  /** Un Set-Cookie crudo → flags relevantes. */
  function parseCookie(raw) {
    const segs = String(raw).split(';').map(s => s.trim());
    const name = (segs[0] || '').split('=')[0].trim();
    const rest = segs.slice(1);
    const ss = rest.find(s => /^samesite=/i.test(s));
    return {
      name,
      secure: rest.some(a => /^secure$/i.test(a)),
      httpOnly: rest.some(a => /^httponly$/i.test(a)),
      sameSite: ss ? ss.split('=')[1] : null,
    };
  }

  // ── Análisis / scoring ────────────────────────────────────────────────
  const GRADES = [[95, 'A+'], [85, 'A'], [75, 'B'], [65, 'C'], [50, 'D'], [0, 'F']];
  function gradeOf(score) {
    for (const [min, g] of GRADES) if (score >= min) return g;
    return 'F';
  }

  /**
   * Analiza un bloque de headers. @param {string} raw
   * @returns {{ok:boolean, error?:string, parsed?:any, findings?:any[], cookies?:any[], csp?:any, score?:number, grade?:string}}
   */
  function analyze(raw) {
    const parsed = parseHeaders(raw);
    if (!parsed.all.length) return { ok: false, error: 'No se reconoció ningún header (formato "Nombre: valor").' };
    const m = parsed.map;
    /** @type {{level:string, header:string, msg:string}[]} */
    const findings = [];
    let score = 100;
    const add = (level, header, msg, pts) => { findings.push({ level, header, msg }); score -= (pts || 0); };

    // HSTS
    if (!m['strict-transport-security']) add('bad', 'Strict-Transport-Security', 'Ausente: el navegador no fuerza HTTPS (riesgo de downgrade/SSL-strip).', 20);
    else {
      const v = m['strict-transport-security'];
      const ma = /max-age\s*=\s*(\d+)/i.exec(v);
      const age = ma ? parseInt(ma[1], 10) : 0;
      if (age < 15552000) add('warn', 'Strict-Transport-Security', 'max-age bajo (' + age + 's < 180 días).', 8);
      else add('ok', 'Strict-Transport-Security', 'Presente (max-age=' + age + ').', 0);
      if (!/includesubdomains/i.test(v)) add('info', 'Strict-Transport-Security', 'Sin includeSubDomains.', 2);
      if (/preload/i.test(v)) add('ok', 'Strict-Transport-Security', 'preload activado.', 0);
    }

    // CSP
    let csp = null;
    if (!m['content-security-policy']) add('bad', 'Content-Security-Policy', 'Ausente: sin defensa contra XSS/inyección de recursos.', 25);
    else {
      csp = parseCsp(m['content-security-policy']);
      const script = csp['script-src'] || csp['default-src'] || [];
      const def = csp['default-src'];
      if (script.some(s => /^'unsafe-inline'$/i.test(s))) add('bad', 'Content-Security-Policy', "script-src permite 'unsafe-inline' (anula gran parte de la protección XSS).", 15);
      if (script.some(s => /^'unsafe-eval'$/i.test(s))) add('warn', 'Content-Security-Policy', "script-src permite 'unsafe-eval'.", 6);
      if (script.some(s => s === '*' || s === 'http:' || s === 'https:')) add('bad', 'Content-Security-Policy', 'script-src usa comodín (* / http: / https:).', 12);
      if (!csp['default-src'] && !csp['script-src']) add('warn', 'Content-Security-Policy', 'Sin default-src ni script-src.', 8);
      if (!csp['object-src'] && !(def && def.length === 1 && /^'none'$/i.test(def[0]))) add('info', 'Content-Security-Policy', "Sin object-src 'none' (plugins legacy).", 2);
      if (!csp['frame-ancestors']) add('info', 'Content-Security-Policy', 'Sin frame-ancestors (clickjacking depende de X-Frame-Options).', 2);
      if (!csp['base-uri']) add('info', 'Content-Security-Policy', 'Sin base-uri (permite reescribir <base>).', 2);
      if (findings.filter(f => f.header === 'Content-Security-Policy' && (f.level === 'bad' || f.level === 'warn')).length === 0)
        add('ok', 'Content-Security-Policy', 'Presente, sin debilidades obvias.', 0);
    }

    // X-Frame-Options / frame-ancestors
    const hasFA = csp && csp['frame-ancestors'];
    if (!m['x-frame-options'] && !hasFA) add('warn', 'X-Frame-Options', 'Ausente y sin frame-ancestors: riesgo de clickjacking.', 10);
    else if (m['x-frame-options']) {
      if (/^(deny|sameorigin)$/i.test(m['x-frame-options'].trim())) add('ok', 'X-Frame-Options', m['x-frame-options'] + '.', 0);
      else add('warn', 'X-Frame-Options', 'Valor no estándar (' + m['x-frame-options'] + ').', 4);
    }

    // X-Content-Type-Options
    if (!m['x-content-type-options']) add('warn', 'X-Content-Type-Options', 'Ausente: el navegador puede hacer MIME-sniffing.', 5);
    else if (/nosniff/i.test(m['x-content-type-options'])) add('ok', 'X-Content-Type-Options', 'nosniff.', 0);

    // Referrer-Policy
    if (!m['referrer-policy']) add('info', 'Referrer-Policy', 'Ausente (se usa el default del navegador).', 2);
    else if (/unsafe-url/i.test(m['referrer-policy'])) add('warn', 'Referrer-Policy', 'unsafe-url filtra el referer completo.', 4);
    else add('ok', 'Referrer-Policy', m['referrer-policy'] + '.', 0);

    // Permissions-Policy
    if (!m['permissions-policy'] && !m['feature-policy']) add('info', 'Permissions-Policy', 'Ausente: no restringe APIs del navegador (cámara/geo/etc.).', 2);

    // Cookies
    const cookies = parsed.cookies.map(parseCookie);
    for (const c of cookies) {
      if (!c.secure) add('warn', 'Set-Cookie', 'Cookie "' + c.name + '" sin Secure.', 5);
      if (!c.httpOnly) add('warn', 'Set-Cookie', 'Cookie "' + c.name + '" sin HttpOnly (accesible por JS).', 5);
      if (!c.sameSite) add('info', 'Set-Cookie', 'Cookie "' + c.name + '" sin SameSite.', 2);
    }

    // Fuga de info
    if (m['server'] && /\d/.test(m['server'])) add('info', 'Server', 'Revela producto/versión (' + m['server'] + ').', 1);
    if (m['x-powered-by']) add('info', 'X-Powered-By', 'Revela tecnología (' + m['x-powered-by'] + ').', 1);

    if (score < 0) score = 0;
    if (score > 100) score = 100;
    return { ok: true, parsed, findings, cookies, csp, score, grade: gradeOf(score) };
  }

  // ── Render ────────────────────────────────────────────────────────────
  const LEVEL_ORDER = { bad: 0, warn: 1, info: 2, ok: 3 };
  const LEVEL_ICON = { bad: '✖', warn: '⚠', info: 'ℹ', ok: '✓' };

  function render(container) {
    container.innerHTML =
      '<div class="lab-sec">' +
      '<div class="lab-intro"><b>Security Headers & CSP.</b> Pegá los headers de respuesta ' +
      '(p.ej. la salida de <code>curl -I</code> o la pestaña Network) y los califico: HSTS, CSP, ' +
      'X-Frame-Options, cookies y más. Todo local — no hago ningún request.</div>' +
      '<textarea id="hdIn" class="cv-io" spellcheck="false" style="min-height:150px" ' +
      'placeholder="content-security-policy: default-src &#39;self&#39;&#10;strict-transport-security: max-age=63072000; includeSubDomains&#10;set-cookie: sid=abc; HttpOnly; Secure; SameSite=Lax"></textarea>' +
      '<div class="x5-actions"><button id="hdGo" class="cv-btn">Analizar</button></div>' +
      '<div id="hdOut"></div></div>';
    const out = container.querySelector('#hdOut');
    const ta = container.querySelector('#hdIn');
    container.querySelector('#hdGo').onclick = () => renderOut(out, analyze(ta.value));
  }

  function renderOut(out, res) {
    if (!res.ok) { out.innerHTML = '<div class="lab-note">' + esc(res.error) + '</div>'; return; }
    const counts = { bad: 0, warn: 0, info: 0, ok: 0 };
    res.findings.forEach(f => { counts[f.level]++; });
    const sorted = res.findings.slice().sort((a, b) => LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level]);

    let html = '<div class="hd-grade hd-g-' + res.grade.replace('+', 'p') + '">' +
      '<span class="hd-letter">' + esc(res.grade) + '</span>' +
      '<span class="hd-score">' + res.score + '/100</span>' +
      '<span class="hd-sum">' + counts.bad + ' críticos · ' + counts.warn + ' avisos · ' + counts.info + ' info</span></div>';

    html += '<div class="lab-panel"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
      '<span>🔎 Hallazgos (' + res.findings.length + ')</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' +
      '<table class="lab-table"><tbody>' +
      sorted.map(f => '<tr><td class="hd-lvl hd-' + f.level + '">' + LEVEL_ICON[f.level] + '</td>' +
        '<td><code>' + esc(f.header) + '</code></td><td>' + esc(f.msg) + '</td></tr>').join('') +
      '</tbody></table></div></div>';

    if (res.csp) {
      html += '<div class="lab-panel collapsed"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
        '<span>🛡 CSP desglosada</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' +
        '<table class="lab-kv"><tbody>' +
        Object.keys(res.csp).map(d => '<tr><th>' + esc(d) + '</th><td><code>' + esc(res.csp[d].join(' ') || "''") + '</code></td></tr>').join('') +
        '</tbody></table></div></div>';
    }

    html += '<div class="lab-panel collapsed"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
      '<span>📋 Headers recibidos (' + res.parsed.all.length + ')</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' +
      '<table class="lab-kv mono"><tbody>' +
      res.parsed.all.map(h => '<tr><th>' + esc(h[0]) + '</th><td>' + esc(h[1]) + '</td></tr>').join('') +
      '</tbody></table></div></div>';

    out.innerHTML = html;
  }

  if (typeof window !== 'undefined' && window.LAB) {
    window.LAB.registerTool({ id: 'headers', label: 'Sec Headers / CSP', icon: '🛡', group: '🧪 LAB / TOOLS', render });
  }
  return { parseHeaders, parseCsp, parseCookie, analyze, gradeOf };
})();
