// Cargador de módulos para tests — APT115
//
// Los parsers viven hoy como IIFE que cuelgan de globals (`window.Triage.*`,
// `window.LAB`). Para testearlos en Node sin un navegador, los evaluamos en un
// contexto `vm` aislado con un `window` falso mínimo. Cada llamada a loadTriage()
// crea un sandbox NUEVO, así un test no contamina los globals de otro.
//
// Patrón documentado en static/apt115/HANDOFF.md §4 (verificación en Node).

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';
import path from 'node:path';
import vm from 'node:vm';

export const APT_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'static', 'apt115'
);

// Globals del navegador que algún parser puede tocar. Los core (util/pe/elf/
// macho) no usan ninguno; los de hash/eml/steg usan crypto/TextDecoder, ya
// disponibles en Node. NO proveemos document/DOM: los tests cubren la lógica de
// parseo, no el render de UI.
function makeSandbox() {
  const sandbox = {
    console,
    TextDecoder, TextEncoder,
    crypto: webcrypto,
    atob, btoa,
    performance,
    setTimeout, clearTimeout,
    Uint8Array, Uint16Array, Uint32Array, DataView, ArrayBuffer,
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  return sandbox;
}

// Carga uno o más archivos (rutas relativas a static/apt115/) en un mismo
// sandbox, en orden. Devuelve el objeto sandbox (con sandbox.Triage, .LAB, …).
export function loadTriage(...relPaths) {
  const sandbox = makeSandbox();
  const ctx = vm.createContext(sandbox);
  for (const rel of relPaths) {
    const code = readFileSync(path.join(APT_DIR, rel), 'utf8');
    vm.runInContext(code, ctx, { filename: rel });
  }
  return sandbox;
}

// Bytes desde un string ASCII/binario (cada char → 1 byte, low 8 bits).
export function bytesOf(str) {
  const a = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) a[i] = str.charCodeAt(i) & 0xff;
  return a;
}
