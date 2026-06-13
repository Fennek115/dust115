// APT115 CODEX ARCANUM — CVSS Calculator (v3.1 + v4.0)
// quod est superius est sicut quod inferius
//
// Vector ↔ score para CVSS v3.1 y v4.0. La v3.1 es la fórmula cerrada oficial
// de FIRST (Base + Temporal + Environmental). La v4.0 es un PORT FIEL de la
// implementación de referencia de FIRST (macroVector + búsqueda en tabla +
// interpolación por distancia de severidad); las tablas `cvssLookup_global`,
// `maxComposed` y `maxSeverity` están vendorizadas tal cual desde el calculador
// oficial. 100% local, sin red.
//
// Datos y algoritmo v4.0: github.com/FIRSTdotorg/cvss-v4-calculator
//   Copyright FIRST, Red Hat, and contributors — SPDX: BSD-2-Clause
// La fórmula v3.1 es la especificación pública de FIRST (CVSS v3.1, §7).

export const cvss = (function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function rating(x) {
    if (x <= 0) return 'None';
    if (x < 4) return 'Low';
    if (x < 7) return 'Medium';
    if (x < 9) return 'High';
    return 'Critical';
  }

  // ═══════════════════ CVSS v3.1 (y v3.0) ═══════════════════
  const V3 = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    UI: { N: 0.85, R: 0.62 },
    PR_U: { N: 0.85, L: 0.62, H: 0.27 },
    PR_C: { N: 0.85, L: 0.68, H: 0.50 },
    CIA: { H: 0.56, L: 0.22, N: 0.0 },
    E: { X: 1, U: 0.91, P: 0.94, F: 0.97, H: 1 },
    RL: { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1 },
    RC: { X: 1, U: 0.92, R: 0.96, C: 1 },
    REQ: { X: 1, L: 0.5, M: 1, H: 1.5 },
  };
  // Valores válidos por métrica (para validar el vector v3).
  const V3_VALID = {
    AV: 'NALP', AC: 'LH', PR: 'NLH', UI: 'NR', S: 'UC', C: 'HLN', I: 'HLN', A: 'HLN',
    E: 'XUPFH', RL: 'XOTWU', RC: 'XURC',
    CR: 'XLMH', IR: 'XLMH', AR: 'XLMH',
    MAV: 'XNALP', MAC: 'XLH', MPR: 'XNLH', MUI: 'XNR', MS: 'XUC',
    MC: 'XHLN', MI: 'XHLN', MA: 'XHLN',
  };
  const V3_REQUIRED = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

  // Redondeo "hacia arriba" oficial de v3.1 (evita el error de punto flotante).
  function roundup31(x) {
    const i = Math.round(x * 100000);
    if (i % 10000 === 0) return i / 100000;
    return (Math.floor(i / 10000) + 1) / 10;
  }
  function roundup30(x) { return Math.ceil(Number((x * 10).toFixed(4))) / 10; }

  function v3mod(s, key) { const mk = 'M' + key; return (s[mk] && s[mk] !== 'X') ? s[mk] : s[key]; }

  function scoreV3(s, version) {
    const ru = version === '3.0' ? roundup30 : roundup31;
    const changed = s.S === 'C';
    const pr = (changed ? V3.PR_C : V3.PR_U)[s.PR];
    const iss = 1 - (1 - V3.CIA[s.C]) * (1 - V3.CIA[s.I]) * (1 - V3.CIA[s.A]);
    const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    const expl = 8.22 * V3.AV[s.AV] * V3.AC[s.AC] * pr * V3.UI[s.UI];
    let base;
    if (impact <= 0) base = 0;
    else base = ru(Math.min((changed ? 1.08 : 1) * (impact + expl), 10));

    const e = V3.E[s.E || 'X'], rl = V3.RL[s.RL || 'X'], rc = V3.RC[s.RC || 'X'];
    const temporal = base === 0 ? 0 : ru(base * e * rl * rc);

    // Environmental (métricas modificadas; X → usa la base).
    const mChanged = v3mod(s, 'S') === 'C';
    const mAV = V3.AV[v3mod(s, 'AV')], mAC = V3.AC[v3mod(s, 'AC')], mUI = V3.UI[v3mod(s, 'UI')];
    const mPR = (mChanged ? V3.PR_C : V3.PR_U)[v3mod(s, 'PR')];
    const CR = V3.REQ[s.CR || 'X'], IR = V3.REQ[s.IR || 'X'], AR = V3.REQ[s.AR || 'X'];
    const mC = V3.CIA[v3mod(s, 'C')], mI = V3.CIA[v3mod(s, 'I')], mA = V3.CIA[v3mod(s, 'A')];
    const miss = Math.min(1 - (1 - CR * mC) * (1 - IR * mI) * (1 - AR * mA), 0.915);
    const modImpact = mChanged ? 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss * 0.9731 - 0.02, 13) : 6.42 * miss;
    const modExpl = 8.22 * mAV * mAC * mPR * mUI;
    let env;
    if (modImpact <= 0) env = 0;
    else env = ru(ru(Math.min((mChanged ? 1.08 : 1) * (modImpact + modExpl), 10)) * e * rl * rc);

    return { version, base, baseSeverity: rating(base), temporal, environmental: env, severity: rating(env || temporal || base) };
  }

  // ═══════════════════ CVSS v4.0 (port fiel de FIRST) ═══════════════════
  // Datos oficiales (BSD-2-Clause). No tocar — son el oráculo del cálculo.
  const V4_LOOKUP = {
    "000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2, "000100": 10, "000101": 9.6, "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1, "000200": 9.3, "000201": 9, "000210": 8.9, "000211": 8, "000220": 8.1, "000221": 6.8, "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4, "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5, "001200": 8.8, "001201": 8, "001210": 7.8, "001211": 7, "001220": 6.9, "001221": 4.8, "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9, "002111": 6.9, "002121": 5, "002201": 6.9, "002211": 5.5, "002221": 2.7,
    "010000": 9.9, "010001": 9.7, "010010": 9.5, "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9, "010111": 8.3, "010120": 8.4, "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2, "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5, "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8, "011111": 7.2, "011120": 7, "011121": 5.9, "011200": 8.4, "011201": 7, "011210": 7.1, "011211": 5.2, "011220": 5, "011221": 3, "012001": 8.6, "012011": 7.5, "012021": 5.2, "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3, "012211": 2.9, "012221": 1.7,
    "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1, "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4, "100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9, "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7, "101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5, "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5, "102001": 8.3, "102011": 7, "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6, "102201": 5.3, "102211": 2.1, "102221": 1.3,
    "110000": 9.5, "110001": 9, "110010": 8.8, "110011": 7.6, "110020": 7.6, "110021": 7, "110100": 9, "110101": 7.7, "110110": 7.5, "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2, "110221": 3, "111000": 8.9, "111001": 7.8, "111010": 7.6, "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4, "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7, "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7, "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1, "112011": 5.9, "112021": 3, "112101": 5.8, "112111": 2.6, "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8, "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4, "200200": 7, "200201": 5.4, "200210": 5.2, "200211": 4, "200220": 4, "200221": 2.2, "201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1, "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9, "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8, "202001": 6.4, "202011": 5.1, "202021": 2, "202101": 4.7, "202111": 2.1, "202121": 1.1, "202201": 2.4, "202211": 0.9, "202221": 0.4,
    "210000": 8.8, "210001": 7.5, "210010": 7.3, "210011": 5.3, "210020": 6, "210021": 5, "210100": 7.3, "210101": 5.5, "210110": 5.9, "210111": 4, "210120": 4.1, "210121": 2, "210200": 5.4, "210201": 4.3, "210210": 4.5, "210211": 2.2, "210220": 2, "210221": 1.1, "211000": 7.5, "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4, "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8, "211111": 1.8, "211120": 2, "211121": 0.9, "211200": 4.6, "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8, "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4, "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1, "212211": 0.3, "212221": 0.1,
  };
  const V4_MAXCOMPOSED = {
    eq1: { 0: ["AV:N/PR:N/UI:N/"], 1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"], 2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"] },
    eq2: { 0: ["AC:L/AT:N/"], 1: ["AC:H/AT:N/", "AC:L/AT:P/"] },
    eq3: {
      0: { "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"], "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"] },
      1: { "0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"], "1": ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"] },
      2: { "1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"] },
    },
    eq4: { 0: ["SC:H/SI:S/SA:S/"], 1: ["SC:H/SI:H/SA:H/"], 2: ["SC:L/SI:L/SA:L/"] },
    eq5: { 0: ["E:A/"], 1: ["E:P/"], 2: ["E:U/"] },
  };
  const V4_MAXSEV = {
    eq1: { 0: 1, 1: 4, 2: 5 },
    eq2: { 0: 1, 1: 2 },
    eq3eq6: { 0: { 0: 7, 1: 6 }, 1: { 0: 8, 1: 8 }, 2: { 1: 10 } },
    eq4: { 0: 6, 1: 5, 2: 4 },
    eq5: { 0: 1, 1: 1, 2: 1 },
  };
  const V4_LV = {
    AV: { N: 0, A: 0.1, L: 0.2, P: 0.3 }, PR: { N: 0, L: 0.1, H: 0.2 }, UI: { N: 0, P: 0.1, A: 0.2 },
    AC: { L: 0, H: 0.1 }, AT: { N: 0, P: 0.1 },
    VC: { H: 0, L: 0.1, N: 0.2 }, VI: { H: 0, L: 0.1, N: 0.2 }, VA: { H: 0, L: 0.1, N: 0.2 },
    SC: { H: 0.1, L: 0.2, N: 0.3 }, SI: { S: 0, H: 0.1, L: 0.2, N: 0.3 }, SA: { S: 0, H: 0.1, L: 0.2, N: 0.3 },
    CR: { H: 0, M: 0.1, L: 0.2 }, IR: { H: 0, M: 0.1, L: 0.2 }, AR: { H: 0, M: 0.1, L: 0.2 },
  };
  // Métricas v4: required base + opcionales (default X).
  const V4_BASE = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];
  const V4_VALID = {
    AV: 'NALP', AC: 'LH', AT: 'NP', PR: 'NLH', UI: 'NPA',
    VC: 'HLN', VI: 'HLN', VA: 'HLN', SC: 'HLN', SI: 'HLN', SA: 'HLN',
    E: 'XAPU', CR: 'XHML', IR: 'XHML', AR: 'XHML',
    MAV: 'XNALP', MAC: 'XLH', MAT: 'XNP', MPR: 'XNLH', MUI: 'XNPA',
    MVC: 'XHLN', MVI: 'XHLN', MVA: 'XHLN', MSC: 'XHLN', MSI: 'XSHLN', MSA: 'XSHLN',
  };
  // Suplementales (no afectan el score): se aceptan sin validar el valor.
  const V4_SUPPLEMENTAL = new Set(['S', 'AU', 'R', 'V', 'RE', 'U']);
  // Defaults 'X' de las métricas opcionales/modificadas: la implementación de
  // referencia de FIRST parte de un objeto con TODAS las métricas presentes,
  // y m4() depende de ver 'X' (no undefined) para aplicar los worst-case.
  const V4_DEFAULTS = {
    E: 'X', CR: 'X', IR: 'X', AR: 'X', MAV: 'X', MAC: 'X', MAT: 'X', MPR: 'X', MUI: 'X',
    MVC: 'X', MVI: 'X', MVA: 'X', MSC: 'X', MSI: 'X', MSA: 'X',
  };

  function m4(s, metric) {
    const sel = s[metric];
    if (metric === 'E' && sel === 'X') return 'A';
    if ((metric === 'CR' || metric === 'IR' || metric === 'AR') && sel === 'X') return 'H';
    if (('M' + metric) in s) { const ms = s['M' + metric]; if (ms && ms !== 'X') return ms; }
    return sel;
  }

  function macroVector(s) {
    let eq1, eq2, eq3, eq4, eq5, eq6;
    const AV = m4(s, 'AV'), PR = m4(s, 'PR'), UI = m4(s, 'UI');
    if (AV === 'N' && PR === 'N' && UI === 'N') eq1 = '0';
    else if ((AV === 'N' || PR === 'N' || UI === 'N') && !(AV === 'N' && PR === 'N' && UI === 'N') && AV !== 'P') eq1 = '1';
    else eq1 = '2';

    eq2 = (m4(s, 'AC') === 'L' && m4(s, 'AT') === 'N') ? '0' : '1';

    const VC = m4(s, 'VC'), VI = m4(s, 'VI'), VA = m4(s, 'VA');
    if (VC === 'H' && VI === 'H') eq3 = '0';
    else if (VC === 'H' || VI === 'H' || VA === 'H') eq3 = '1';
    else eq3 = '2';

    if (m4(s, 'MSI') === 'S' || m4(s, 'MSA') === 'S') eq4 = '0';
    else if (m4(s, 'SC') === 'H' || m4(s, 'SI') === 'H' || m4(s, 'SA') === 'H') eq4 = '1';
    else eq4 = '2';

    const E = m4(s, 'E');
    eq5 = E === 'A' ? '0' : E === 'P' ? '1' : '2';

    if ((m4(s, 'CR') === 'H' && VC === 'H') || (m4(s, 'IR') === 'H' && VI === 'H') || (m4(s, 'AR') === 'H' && VA === 'H')) eq6 = '0';
    else eq6 = '1';

    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
  }

  function extractValueMetric(metric, str) {
    let extracted = str.slice(str.indexOf(metric) + metric.length + 1);
    const sl = extracted.indexOf('/');
    return sl > 0 ? extracted.substring(0, sl) : extracted;
  }
  function getEQMaxes(mv, eq) { return V4_MAXCOMPOSED['eq' + eq][mv[eq - 1]]; }

  function scoreV4(s) {
    if (['VC', 'VI', 'VA', 'SC', 'SI', 'SA'].every(me => m4(s, me) === 'N')) return { macroVector: macroVector(s), score: 0.0 };

    const mv = macroVector(s);
    let value = V4_LOOKUP[mv];
    const eq1 = +mv[0], eq2 = +mv[1], eq3 = +mv[2], eq4 = +mv[3], eq5 = +mv[4], eq6 = +mv[5];

    const c = (a, b, cc, d, e, f) => '' + a + b + cc + d + e + f;
    const eq1n = c(eq1 + 1, eq2, eq3, eq4, eq5, eq6);
    const eq2n = c(eq1, eq2 + 1, eq3, eq4, eq5, eq6);
    let eq3eq6n, eq3eq6nL, eq3eq6nR;
    if (eq3 === 1 && eq6 === 1) eq3eq6n = c(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
    else if (eq3 === 0 && eq6 === 1) eq3eq6n = c(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
    else if (eq3 === 1 && eq6 === 0) eq3eq6n = c(eq1, eq2, eq3, eq4, eq5, eq6 + 1);
    else if (eq3 === 0 && eq6 === 0) { eq3eq6nL = c(eq1, eq2, eq3, eq4, eq5, eq6 + 1); eq3eq6nR = c(eq1, eq2, eq3 + 1, eq4, eq5, eq6); }
    else eq3eq6n = c(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1);
    const eq4n = c(eq1, eq2, eq3, eq4 + 1, eq5, eq6);
    const eq5n = c(eq1, eq2, eq3, eq4, eq5 + 1, eq6);

    const sEq1n = V4_LOOKUP[eq1n], sEq2n = V4_LOOKUP[eq2n];
    let sEq3eq6n;
    if (eq3 === 0 && eq6 === 0) {
      const l = V4_LOOKUP[eq3eq6nL], r = V4_LOOKUP[eq3eq6nR];
      sEq3eq6n = l > r ? l : r;
    } else sEq3eq6n = V4_LOOKUP[eq3eq6n];
    const sEq4n = V4_LOOKUP[eq4n], sEq5n = V4_LOOKUP[eq5n];

    const eq1maxes = getEQMaxes(mv, 1), eq2maxes = getEQMaxes(mv, 2);
    const eq3eq6maxes = getEQMaxes(mv, 3)[mv[5]];
    const eq4maxes = getEQMaxes(mv, 4), eq5maxes = getEQMaxes(mv, 5);
    const maxVectors = [];
    for (const a of eq1maxes) for (const b of eq2maxes) for (const cc of eq3eq6maxes) for (const d of eq4maxes) for (const e of eq5maxes) maxVectors.push(a + b + cc + d + e);

    let sd = {};
    for (const maxVector of maxVectors) {
      const dist = {};
      for (const me of ['AV', 'PR', 'UI', 'AC', 'AT', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA', 'CR', 'IR', 'AR'])
        dist[me] = V4_LV[me][m4(s, me)] - V4_LV[me][extractValueMetric(me, maxVector)];
      if (Object.keys(dist).some(k => dist[k] < 0)) continue;
      sd = dist; break;
    }

    const cur1 = sd.AV + sd.PR + sd.UI;
    const cur2 = sd.AC + sd.AT;
    const cur3eq6 = sd.VC + sd.VI + sd.VA + sd.CR + sd.IR + sd.AR;
    const cur4 = sd.SC + sd.SI + sd.SA;
    const step = 0.1;

    const av1 = value - sEq1n, av2 = value - sEq2n, av3 = value - sEq3eq6n, av4 = value - sEq4n, av5 = value - sEq5n;
    const ms1 = V4_MAXSEV.eq1[eq1] * step, ms2 = V4_MAXSEV.eq2[eq2] * step, ms3 = V4_MAXSEV.eq3eq6[eq3][eq6] * step, ms4 = V4_MAXSEV.eq4[eq4] * step;

    let n = 0, ns1 = 0, ns2 = 0, ns3 = 0, ns4 = 0, ns5 = 0;
    if (!isNaN(av1)) { n++; ns1 = av1 * (cur1 / ms1); }
    if (!isNaN(av2)) { n++; ns2 = av2 * (cur2 / ms2); }
    if (!isNaN(av3)) { n++; ns3 = av3 * (cur3eq6 / ms3); }
    if (!isNaN(av4)) { n++; ns4 = av4 * (cur4 / ms4); }
    if (!isNaN(av5)) { n++; ns5 = 0; }

    const mean = n === 0 ? 0 : (ns1 + ns2 + ns3 + ns4 + ns5) / n;
    value -= mean;
    if (value < 0) value = 0;
    if (value > 10) value = 10;
    return { macroVector: mv, score: Math.round(value * 10) / 10 };
  }

  // ═══════════════════ Parsing de vector ═══════════════════
  /** Parsea un vector CVSS. @param {string} text @returns {{ok:boolean, error?:string, ...}} */
  function parse(text) {
    const raw = String(text == null ? '' : text).trim();
    if (!raw) return { ok: false, error: 'Pegá un vector CVSS.' };
    const parts = raw.split('/').filter(Boolean);
    const head = parts[0] || '';
    const mh = /^CVSS:(\d+\.\d+)$/i.exec(head);
    if (!mh) return { ok: false, error: 'Falta el prefijo CVSS:x.y al inicio.' };
    const version = mh[1];
    /** @type {Record<string,string>} */
    const metrics = {};
    for (const p of parts.slice(1)) {
      const kv = p.split(':');
      if (kv.length !== 2 || !kv[1]) return { ok: false, error: 'Métrica mal formada: "' + p + '".' };
      metrics[kv[0].toUpperCase()] = kv[1].toUpperCase();
    }
    return { ok: true, version, metrics };
  }

  function validate(version, metrics, valid, required, skip) {
    for (const k of required) if (!(k in metrics)) return 'Falta la métrica obligatoria ' + k + '.';
    for (const k of Object.keys(metrics)) {
      if (skip && skip.has(k)) continue;       // suplementales: sin efecto en el score
      const allowed = valid[k];
      if (!allowed) return 'Métrica desconocida para v' + version + ': ' + k + '.';
      if (allowed.indexOf(metrics[k]) < 0) return 'Valor inválido ' + k + ':' + metrics[k] + '.';
    }
    return null;
  }

  /** Vector → score. @param {string} text @returns {{ok:boolean, error?:string, result?:any}} */
  function compute(text) {
    const p = parse(text);
    if (!p.ok) return p;
    const { version, metrics } = p;
    if (version === '3.1' || version === '3.0') {
      const err = validate(version, metrics, V3_VALID, V3_REQUIRED);
      if (err) return { ok: false, error: err };
      const r = scoreV3(metrics, version);
      return { ok: true, result: { kind: 'v3', version, metrics, ...r } };
    }
    if (version === '4.0') {
      const err = validate(version, metrics, V4_VALID, V4_BASE, V4_SUPPLEMENTAL);
      if (err) return { ok: false, error: err };
      const r = scoreV4(Object.assign({}, V4_DEFAULTS, metrics));
      return { ok: true, result: { kind: 'v4', version, metrics, score: r.score, macroVector: r.macroVector, severity: rating(r.score) } };
    }
    return { ok: false, error: 'Versión no soportada: ' + version + ' (soporto 3.0, 3.1, 4.0).' };
  }

  // ═══════════════════ Render ═══════════════════
  function sevClass(sev) { return 'cv-' + sev.toLowerCase(); }

  function render(container) {
    container.innerHTML =
      '<div class="lab-sec">' +
      '<div class="lab-intro"><b>CVSS Calculator.</b> Pegá un vector <b>v3.1</b> o <b>v4.0</b> ' +
      '(p.ej. <code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code>) y calculo el score con ' +
      'la fórmula oficial de FIRST. La v4.0 usa las tablas de referencia vendorizadas (BSD-2-Clause).</div>' +
      '<textarea id="cvIn2" class="cv-io" spellcheck="false" style="min-height:70px" ' +
      'placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"></textarea>' +
      '<div class="x5-actions"><button id="cvGo2" class="cv-btn">Calcular</button>' +
      '<button class="cv-btn cv-ex" data-v="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">ej. v3.1</button>' +
      '<button class="cv-btn cv-ex" data-v="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N">ej. v4.0</button></div>' +
      '<div id="cvOut2"></div></div>';
    const out = container.querySelector('#cvOut2');
    const ta = container.querySelector('#cvIn2');
    const go = () => renderOut(out, compute(ta.value));
    container.querySelector('#cvGo2').onclick = go;
    container.querySelectorAll('.cv-ex').forEach(b => { b.onclick = () => { ta.value = b.dataset.v; go(); }; });
  }

  function renderOut(out, res) {
    if (!res.ok) { out.innerHTML = '<div class="lab-note">' + esc(res.error) + '</div>'; return; }
    const r = res.result;
    let html = '<div class="cv-card ' + sevClass(r.severity) + '">' +
      '<div class="cv-big">' + esc((r.kind === 'v3' ? r.environmental || r.temporal || r.base : r.score).toFixed(1)) + '</div>' +
      '<div class="cv-meta"><div class="cv-sev">' + esc(r.severity) + '</div>' +
      '<div class="cv-ver">CVSS v' + esc(r.version) + (r.kind === 'v4' ? ' · MacroVector ' + esc(r.macroVector) : '') + '</div></div></div>';

    if (r.kind === 'v3') {
      html += '<table class="lab-kv"><tbody>' +
        '<tr><th>Base</th><td>' + r.base.toFixed(1) + ' <span class="cv-tag ' + sevClass(r.baseSeverity) + '">' + esc(r.baseSeverity) + '</span></td></tr>' +
        (r.temporal !== r.base ? '<tr><th>Temporal</th><td>' + r.temporal.toFixed(1) + '</td></tr>' : '') +
        (r.environmental !== r.base ? '<tr><th>Environmental</th><td>' + r.environmental.toFixed(1) + '</td></tr>' : '') +
        '</tbody></table>';
    }

    html += '<div class="lab-panel collapsed"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
      '<span>🔬 Métricas</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' +
      '<table class="lab-kv mono"><tbody>' +
      Object.keys(r.metrics).map(k => '<tr><th>' + esc(k) + '</th><td>' + esc(r.metrics[k]) + '</td></tr>').join('') +
      '</tbody></table></div></div>';

    out.innerHTML = html;
  }

  if (typeof window !== 'undefined' && window.LAB) {
    window.LAB.registerTool({ id: 'cvss', label: 'CVSS Calc', icon: '🎯', group: '🧪 LAB / TOOLS', render });
  }
  return { parse, compute, scoreV3, scoreV4, macroVector, rating };
})();
