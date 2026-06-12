// Build de APT115 con esbuild — HÍBRIDO (Etapa 3 en curso).
//
// Estado de la migración: los parsers core (util/pe/elf/macho) ya son módulos ESM
// en src/triage/. El resto sigue siendo global-script en static/apt115/tools/.
// El build refleja eso:
//   - Los CONVERTIDOS se empaquetan con esbuild por IMPORTS reales (grafo de deps,
//     tree-shaking) y se re-exponen en window.Triage para los consumidores aún no
//     migrados (back-compat durante la transición).
//   - El RESTO se CONCATENA en el orden de index.html (comparte scope léxico global;
//     ver el hallazgo de Etapa 2 en el README).
// A medida que se convierta más, los archivos pasan del bloque concatenado al
// bundle de imports. Cuando todo sea ESM, desaparece la concatenación.
//
// El bloque ESM va PRIMERO: deja util/pe/elf/macho en window.Triage antes de que
// corran sus consumidores (analyzers/triage/capa), que aparecen más tarde en el resto.
//
// Lazy fuera del bundle (no son <script> en index.html): libyara, capstone, packs
// YARA, peid-userdb, gtfobins/lolbas.
//
// Salida → apt115-dev/dist/ (NO se sirve). Cablear index.html es el paso siguiente,
// tras verificar en navegador.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import * as esbuild from 'esbuild';

const HERE = import.meta.dirname;
const APT = path.resolve(HERE, '..', 'static', 'apt115');
const SRC = path.join(HERE, 'src');
const OUT = path.join(HERE, 'dist');

// Módulos ya convertidos a ESM: ruta vieja (en index.html) → export en src/.
const CONVERTED = {
  'tools/triage/util.js': { mod: './triage/util.js', name: 'util' },
  'tools/triage/pe.js': { mod: './triage/pe.js', name: 'pe' },
  'tools/triage/elf.js': { mod: './triage/elf.js', name: 'elf' },
  'tools/triage/macho.js': { mod: './triage/macho.js', name: 'macho' },
};

// Fuente de verdad del orden: los <script src> de index.html.
const html = readFileSync(path.join(APT, 'index.html'), 'utf8');
const scripts = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);

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

// 2) Resto: concatenación de los scripts NO convertidos, en orden.
let rest = '';
for (const s of scripts) {
  if (CONVERTED[s]) continue; // ya va en el bloque ESM
  rest += `\n/* ===== ${s} ===== */\n;\n` + readFileSync(path.join(APT, s), 'utf8') + '\n';
}

const header = '// APT115 — bundle generado por apt115-dev/build.mjs. NO editar a mano.\n';
const banner = '\n/* ===== [esbuild] módulos ESM convertidos → window.Triage ===== */\n';
const bundle = header + banner + esmBlock + '\n/* ===== [concat] scripts aún no migrados ===== */\n' + rest;

mkdirSync(OUT, { recursive: true });
writeFileSync(path.join(OUT, 'apt115.bundle.js'), bundle);
writeFileSync(path.join(OUT, 'esm-block.js'), esmBlock); // para verificar el bloque ESM aislado
const min = await esbuild.transform(bundle, { minify: true, legalComments: 'none', target: 'es2020' });
writeFileSync(path.join(OUT, 'apt115.bundle.min.js'), min.code);

const kb = (s) => (Buffer.byteLength(s) / 1024).toFixed(0);
console.log(`convertidos a ESM (esbuild import-bundle): ${names.join(', ')}`);
console.log(`concatenados (aún global-script): ${scripts.length - names.length}`);
console.log(`  dev:  dist/apt115.bundle.js      ${kb(bundle)} KB`);
console.log(`  prod: dist/apt115.bundle.min.js  ${kb(min.code)} KB`);
