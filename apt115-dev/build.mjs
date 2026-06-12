// Build de APT115 con esbuild — ESQUELETO (Etapa 2).
//
// Mete esbuild en el pipeline y produce UN bundle file://-safe desde los scripts
// que hoy carga index.html, SIN refactorizar el código.
//
// POR QUÉ CONCATENACIÓN Y NO BUNDLING POR IMPORTS (hallazgo de Etapa 2):
// el código actual comparte estado entre <script> vía el scope léxico global
// (p.ej. data/core.js define `const CORE_DATA=…` y app.js hace
// `const D=[...CORE_DATA,…]`). Cada <script> ve los `const`/`let` top-level de los
// otros porque comparten el Global Lexical Environment. Si en cambio se empaqueta
// por imports (esbuild bundle), cada archivo pasa a ser un MÓDULO ESM aislado: sus
// `const` quedan en scope de módulo, NO se comparten, y app.js los ve undefined
// (+ esbuild tree-shakea los data/ por no tener side-effects observables). Probado:
// el bundle por imports dejaba afuera core/mitre/intel → app roto.
// → Concatenar en el orden de index.html reproduce el comportamiento actual EXACTO
//   (mismo scope de script, mismo orden). El bundling por imports es el estado FINAL
//   de la Etapa 3, recién cuando cada archivo exporte/importe explícito.
//
// Los motores/datos lazy (libyara, capstone, packs YARA, peid-userdb, gtfobins…) se
// cargan en runtime, NO están como <script> en index.html → no entran al bundle.
//
// Salida → apt115-dev/dist/ (NO se sirve). El cableado en index.html (reemplazar los
// <script> por uno solo) es el paso siguiente, tras verificar en navegador.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import * as esbuild from 'esbuild';

const HERE = import.meta.dirname;
const APT = path.resolve(HERE, '..', 'static', 'apt115');
const OUT = path.join(HERE, 'dist');

// Fuente de verdad: los <script src="..."> de index.html, en orden de aparición.
const html = readFileSync(path.join(APT, 'index.html'), 'utf8');
const scripts = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
if (!scripts.length) { console.error('No encontré <script src> en index.html'); process.exit(1); }

// Concatenar. El `;\n` entre archivos evita problemas de ASI al unir scripts que
// terminan sin punto y coma (en index.html van como <script> separados).
let bundle = '// APT115 — bundle generado por apt115-dev/build.mjs. NO editar a mano.\n' +
  '// Concatenación de los <script> de index.html, en orden. Ver build.mjs.\n';
for (const s of scripts) {
  bundle += `\n/* ===== ${s} ===== */\n;\n`;
  bundle += readFileSync(path.join(APT, s), 'utf8');
  bundle += '\n';
}

mkdirSync(OUT, { recursive: true });
const devPath = path.join(OUT, 'apt115.bundle.js');
const minPath = path.join(OUT, 'apt115.bundle.min.js');
writeFileSync(devPath, bundle);

// esbuild SOLO para minificar (transform de un script, sin semántica de módulos).
const min = await esbuild.transform(bundle, { minify: true, legalComments: 'none', target: 'es2020' });
writeFileSync(minPath, min.code);

const kb = (p) => (readFileSync(p).length / 1024).toFixed(0);
console.log(`${scripts.length} scripts concatenados.`);
console.log(`  dev:  dist/apt115.bundle.js      ${kb(devPath)} KB`);
console.log(`  prod: dist/apt115.bundle.min.js  ${kb(minPath)} KB`);
writeFileSync(path.join(OUT, 'bundle-inputs.txt'), scripts.join('\n') + '\n');
