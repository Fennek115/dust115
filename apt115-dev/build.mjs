// Build de APT115 con esbuild — HÍBRIDO, PRESERVANDO POSICIÓN.
//
// Produce el bundle único que carga index.html (static/apt115/apt115.bundle.js),
// file://-safe. El MANIFIESTO de fuentes (SOURCES) vive acá, en orden de carga
// (index.html ya no las lista: carga el bundle).
//
// Cada fuente se emite EN SU POSICIÓN del manifiesto:
//   - CONVERTIDA a ESM (src/): esbuild la empaqueta sola (IIFE) y se inserta acá.
//   - NO convertida: se concatena su contenido viejo acá.
// Preservar la posición es CLAVE: los analyzers/tools se registran en orden de
// carga (Triage.analyzers.register / LAB.registerTool), así que mover un archivo
// de lugar cambiaría la cadena. Insertar en posición permite convertir CUALQUIER
// archivo de a uno sin reordenar nada.
//
// Los módulos convertidos cuelgan su API de window (Triage/LAB/los handlers
// inline del cheatsheet). Comparten estado por globals, no por imports; por
// eso cada entry se empaqueta independiente (sin grafo compartido entre
// entries — los src/app/* sí se importan entre sí dentro de su entry).
//
// Solo quedan concatenados los 2 vendor third-party (spark-md5/tlsh), que no
// se convierten.
//
// Lazy fuera del bundle: libyara-wasm, capstone (import(url) dinámico), packs YARA,
// peid-userdb, gtfobins/lolbas.
//
// Salidas: static/apt115/apt115.bundle.js (DEPLOY, minificado, se commitea) +
// apt115-dev/dist/apt115.bundle.js (dev sin minificar, gitignoreado).
// Regenerar con `node build.mjs` tras cada cambio de fuente, antes de commitear.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import * as esbuild from 'esbuild';

const HERE = import.meta.dirname;
const APT = path.resolve(HERE, '..', 'static', 'apt115');
const SRC = path.join(HERE, 'src');
const OUT = path.join(HERE, 'dist');

// Manifiesto de fuentes, en orden de carga.
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

// Módulos ya convertidos a ESM (ruta vieja → módulo en src/). Cada uno se
// AUTO-CUELGA de window internamente, así que el build solo lo importa por
// efecto secundario (esto generaliza a módulos con side effects: el framework
// se registra/auto-inicializa al cargar).
const CONVERTED = {
  'app.js': './app/index.js',
  'data/core.js': './data/core.js',
  'data/mitre.js': './data/mitre.js',
  'data/intel.js': './data/intel.js',
  'data/magic-extra.js': './data/magic-extra.js',
  'tools/revshell/payloads.js': './data/payloads.js',
  'tools/registry.js': './lab/registry.js',
  'tools/capstone-core.js': './lab/capstone-core.js',
  'tools/triage/peid.js': './triage/peid.js',
  'tools/triage/triage.js': './triage/triage.js',
  'tools/disasm/disasm.js': './tools/disasm.js',
  'tools/triage/util.js': './triage/util.js',
  'tools/triage/pe.js': './triage/pe.js',
  'tools/triage/elf.js': './triage/elf.js',
  'tools/triage/macho.js': './triage/macho.js',
  'tools/triage/cfb.js': './triage/cfb.js',
  'tools/triage/analyzers.js': './triage/analyzers.js',
  'tools/triage/capa.js': './triage/capa.js',
  'tools/triage/lnk.js': './triage/lnk.js',
  'tools/triage/pdf.js': './triage/pdf.js',
  'tools/triage/eml.js': './triage/eml.js',
  'tools/triage/vba.js': './triage/vba.js',
  'tools/triage/maldoc.js': './triage/maldoc.js',
  'tools/triage/epdisasm.js': './triage/epdisasm.js',
  'tools/triage/steg.js': './triage/steg.js',
  'tools/yara/yara.js': './triage/yara.js',
  'tools/triage/fuzzy.js': './triage/fuzzy.js',
  'tools/ioc/ioc.js': './tools/ioc.js',
  'tools/urlinsp/urlinsp.js': './tools/urlinsp.js',
  'tools/cryptolab/cryptolab.js': './tools/cryptolab.js',
  'tools/convert/convert.js': './tools/convert.js',
  'tools/netcalc/netcalc.js': './tools/netcalc.js',
  'tools/lolref/lolref.js': './tools/lolref.js',
  'tools/revshell/revshell.js': './tools/revshell.js',
  'tools/stego/stego.js': './tools/stego.js',
};

// Empaqueta un módulo ESM convertido a un IIFE (import por efecto secundario).
async function bundleConverted(mod) {
  const r = await esbuild.build({
    stdin: { contents: `import ${JSON.stringify(mod)};\n`, resolveDir: SRC, sourcefile: '_entry.js', loader: 'js' },
    bundle: true, format: 'iife', target: ['es2020'], legalComments: 'none', write: false,
  });
  return r.outputFiles[0].text;
}

// Arma el bundle emitiendo cada fuente EN SU POSICIÓN.
const chunks = await Promise.all(SOURCES.map(async (s) => {
  const c = CONVERTED[s];
  if (c) return `\n/* ===== ${s} → ESM (esbuild) ===== */\n` + await bundleConverted(c) + '\n';
  return `\n/* ===== ${s} ===== */\n;\n` + readFileSync(path.join(APT, s), 'utf8') + '\n'; // `;\n` evita ASI
}));

const bundle = '// APT115 — bundle generado por apt115-dev/build.mjs. NO editar a mano.\n' + chunks.join('');

mkdirSync(OUT, { recursive: true });
writeFileSync(path.join(OUT, 'apt115.bundle.js'), bundle);
const min = await esbuild.transform(bundle, { minify: true, legalComments: 'none', target: 'es2020' });
writeFileSync(path.join(OUT, 'apt115.bundle.min.js'), min.code);
writeFileSync(path.join(APT, 'apt115.bundle.js'), min.code); // artefacto de DEPLOY

const converted = Object.keys(CONVERTED).map((s) => s.split('/').pop().replace('.js', ''));
const kb = (s) => (Buffer.byteLength(s) / 1024).toFixed(0);
console.log(`fuentes: ${SOURCES.length} (ESM: ${converted.join(', ')} | concat: ${SOURCES.length - converted.length})`);
console.log(`  deploy: static/apt115/apt115.bundle.js  ${kb(min.code)} KB`);
