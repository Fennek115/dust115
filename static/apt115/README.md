# APT115 CODEX ARCANUM

Toolkit de seguridad ofensiva y análisis estático de malware, **100%
client-side**: todo corre en tu navegador, nada se sube a ningún servidor.
Vive en `https://dust115.github.io/dust115/apt115/` y también funciona abriendo
`index.html` como archivo local (file://), sin internet.

## Qué trae

**Cheatsheet ofensivo** — comandos de recon/web/AD/privesc/tunneling con
variables de engagement ({LHOST}, {RHOST}, …) que se sustituyen en vivo,
favoritos, notas, checklist con progreso, comandos propios, panel Target Intel
y export/import de la sesión completa a JSON.

**LAB / TOOLS:**

- **Malware Triage** — soltá un archivo y corre la cadena de analyzers que
  aplican: PE/ELF/Mach-O (parsers propios: headers, imports, mitigaciones,
  firma de código), hashes (md5/sha/imphash/TLSH/telfhash), entropía, Rich
  Header, recursos/Authenticode, strings, capacidades estilo capa con tags
  ATT&CK, macros VBA (maldoc), LNK, PDF, email .eml, **YARA real**
  (libyara-wasm con packs Mandiant/GCTI/ReversingLabs/signature-base), PEiD,
  desensamblado del entry point (Capstone) y esteganálisis de imágenes.
- **Reverse Shell & C2 Generator**, **Mini-CyberChef** (encodings, XOR, JWT,
  hashes), **GTFOBins/LOLBAS offline**, **Network Calc**, **IOC Extractor**,
  **Disassembler** (x86/ARM/MIPS), **URL/Domain Inspector** (homógrafos IDN,
  typosquats, DGA), **Crypto/Payload Lab** (XOR brute, RC4, AES) y **Stego
  Lab** (LSB/append/metadata, con AES-GCM opcional).

## Privacidad

- Los archivos que analizás **no salen de tu navegador**. No hay backend, no
  hay telemetría, no hay requests a internet en ejecución.
- Los lookups externos (VirusTotal, MalwareBazaar, urlscan, whois) son
  **opt-in**: solo abren un link en otra pestaña cuando los clickeás.
- El estado del cheatsheet (favoritos, notas, intel) vive en el localStorage
  de tu navegador. Usá Export Session para respaldarlo.

## Límites conocidos

- Análisis **estático**: no ejecuta ni desempaca muestras. Ante packing real
  o anti-disasm fuerte, detecta y deriva a herramientas dinámicas.
- El Disassembler (Capstone WASM) no funciona en file:// (sí servido).
- Los packs YARA grandes se usan completos al escanear pero no se vuelcan al
  editor (queda como "pack activo"); escribir en el editor pasa a usar tus
  reglas.
- El análisis de píxel del esteganálisis se limita a imágenes de hasta ~40 MP
  (más grandes: reducilas externamente); el nivel de contenedor corre igual.
- Esto orienta un triage; no reemplaza un sandbox ni a un analista.

## Para desarrollo

El código fuente vive en `apt115-dev/` (raíz del repo); `apt115.bundle.js` es
un artefacto generado — no editarlo a mano. Ver `apt115-dev/ARCHITECTURE.md` y
`apt115-dev/CONTRIBUTING.md`.

Motores y datos de terceros vendorizados con sus licencias en `vendor/`:
libyara (BSD-3), Capstone (BSD), spark-md5 (MIT), TLSH (Apache-2.0), packs
YARA de Mandiant/GCTI/ReversingLabs y signature-base de Florian Roth (DRL 1.1),
GTFOBins/LOLBAS, firmas PEiD y magic de Apache Tika.
