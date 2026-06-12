// Build de APT115 con esbuild — HÍBRIDO (Etapa 3 en curso).
//
// Produce el bundle único que carga index.html (static/apt115/apt115.bundle.js),
// file://-safe. index.html ya NO lista las fuentes (carga el bundle), así que el
// MANIFIESTO de fuentes vive acá (SOURCES), en el orden en que se cargaban.
//
// Estado de la migración:
//   - CONVERTIDOS a ESM (src/triage/): esbuild los empaqueta por IMPORTS reales
//     (grafo de deps, tree-shaking) y los re-expone en window.Triage para los
//     consumidores aún no migrados (back-compat).
//   - RESTO: se CONCATENA en orden. Comparten estado por el scope léxico global
//     (data/core.js define `const CORE_DATA=…`; app.js hace `const D=[...CORE_DATA]`),
//     que el bundling por imports rompería. Se concatena hasta que exporten explícito.
// A medida que se convierte más, un archivo pasa de SOURCES (concat) a CONVERTED
// (import). Cuando todo sea ESM, desaparece la concatenación.
//
// Lazy fuera del bundle (se cargan en runtime, no son fuentes): libyara-wasm,
// capstone (import(url) dinámico), packs YARA, peid-userdb, gtfobins/lolbas.
//
// Salidas: static/apt115/apt115.bundle.js (DEPLOY, minificado, se commitea) +
// apt115-dev/dist/ (dev sin minificar + bloque ESM aislado, gitignoreado).
// Regenerar con `node build.mjs` tras cada cambio de fuente, antes de commitear.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import * as esbuild from 'esbuild';

const HERE = import.meta.dirname;
const APT = path.resolve(HERE, '..', 'static', 'apt115');
const SRC = path.join(HERE, 'src');
const OUT = path.join(HERE, 'dist');

// Manifiesto de fuentes, en orden de carga (era el orden de los <script> de index.html).
const SOURCES = [
  'data/core.js', 'data/mitre.js', 'data/intel.js', 'app.js',
  'vendor/spark-md5.min.js', 'vendor/fuzzy/tlsh.min.js',
  'tools/registry.js', 'tools/capstone-core.js', 'data/magic-extra.js',
  'tools/triage/util.js', 'tools/triage/pe.js', 'tools/triage/elf.js', 'tools/triage/macho.js',
  'tools/triage/cfb.js', 'tools/triage/vba.js', 'tools/triage/analyzers.js', 'tools/triage/capa.js',
  'tools/triage/maldoc.js', 'tools/triage/lnk.js', 'tools/triage/pdf.js', 'tools/triage/eml.js',
  'tools/triage/fuzzy.js', 'tools/yara/yara.js', 'tools/triage/peid.js', 'tools/triage/epdisasm.js',
  'tools/triage/steg.js', 'tools/triage/triage.js',
  'tools/revshell/payloads.js', 'tools/revshell/revshell.js', 'tools/convert/convert.js',
  'tools/lolref/lolref.js', 'tools/netcalc/netcalc.js', 'tools/ioc/ioc.js', 'tools/disasm/disasm.js',
  'tools/stego/stego.js', 'tools/urlinsp/urlinsp.js', 'tools/cryptolab/cryptolab.js',
];

// Módulos ya convertidos a ESM: ruta vieja → export en src/.
const CONVERTED = {
  'tools/triage/util.js': { mod: './triage/util.js', name: 'util' },
  'tools/triage/pe.js': { mod: './triage/pe.js', name: 'pe' },
  'tools/triage/elf.js': { mod: './triage/elf.js', name: 'elf' },
  'tools/triage/macho.js': { mod: './triage/macho.js', name: 'macho' },
};

// 1) Bloque ESM: importa los convertidos y los cuelga de window.Triage (back-compat).
const names = Object.values(CONVERTED).map((c) => c.name);
const entry =
  Object.values(CONVERTED).map((c) => `import { ${c.name} } from ${JSON.stringify(c.mod)};`).join('\n') +
  `\nwindow.Triage = window.Triage || {};\n` +
  names.map((n) => `window.Triage.${n} = ${n};`).join('\n') + '\n';

const esmBuild = await esbuild.build({
  stdin: { contents: entry, resolveDir: SRC, sourcefile: '_esm-entry.js', loader: 'js' },
  bundle: true, format: 'iife', target: ['es2020'], legalComments: 'none', write: false,
});
const esmBlock = esmBuild.outputFiles[0].text;

// 2) Resto: concatenación de las fuentes NO convertidas, en orden. El `;\n` evita ASI.
let rest = '';
for (const s of SOURCES) {
  if (CONVERTED[s]) continue; // va en el bloque ESM
  rest += `\n/* ===== ${s} ===== */\n;\n` + readFileSync(path.join(APT, s), 'utf8') + '\n';
}

// El bloque ESM va PRIMERO: deja util/pe/elf/macho en window.Triage antes de que
// corran sus consumidores (analyzers/triage/capa), que aparecen después en el resto.
const header = '// APT115 — bundle generado por apt115-dev/build.mjs. NO editar a mano.\n';
const bundle = header +
  '\n/* ===== [esbuild] módulos ESM convertidos → window.Triage ===== */\n' + esmBlock +
  '\n/* ===== [concat] fuentes aún no migradas ===== */\n' + rest;

mkdirSync(OUT, { recursive: true });
writeFileSync(path.join(OUT, 'apt115.bundle.js'), bundle);
writeFileSync(path.join(OUT, 'esm-block.js'), esmBlock);
const min = await esbuild.transform(bundle, { minify: true, legalComments: 'none', target: 'es2020' });
writeFileSync(path.join(OUT, 'apt115.bundle.min.js'), min.code);
writeFileSync(path.join(APT, 'apt115.bundle.js'), min.code); // artefacto de DEPLOY

const kb = (s) => (Buffer.byteLength(s) / 1024).toFixed(0);
console.log(`fuentes: ${SOURCES.length} (ESM import-bundle: ${names.join(', ')} | concat: ${SOURCES.length - names.length})`);
console.log(`  deploy: static/apt115/apt115.bundle.js  ${kb(min.code)} KB (minificado)`);
console.log(`  dev:    dist/apt115.bundle.js            ${kb(bundle)} KB`);
