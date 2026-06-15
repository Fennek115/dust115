---
title: "Manual de APT115"
---

[APT115 — Codex Arcanum](/apt115/) es un toolkit de análisis estático de
malware y seguridad ofensiva que corre **100% en tu navegador**: nada se sube
a ningún servidor, nada se ejecuta, y la mayoría de los motores funcionan
incluso sin internet (`file://`). Este manual recorre cada herramienta:
**qué hace**, **cuándo usarla**, **cómo usarla paso a paso**, y a qué
herramienta profesional **derivar** cuando necesités ir más a fondo — porque
APT115 está pensado para orientar un triage rápido, no para reemplazar a un
analista ni a un sandbox.

## Índice

- [Triage: ejecutables y formatos](#triage-ejecutables-y-formatos)
- [Triage: documentos, red y esteganografía](#triage-documentos-red-y-esteganografía)
- LAB / TOOLS ofensivas y utilitarias — próximamente
- Forensics — próximamente

---

## Triage: ejecutables y formatos

La tool **🧪 Malware Triage** (menú LAB / TOOLS) es el punto de entrada para
todo lo de esta sección. Funciona así:

1. Abrí `/apt115/` y elegí **Malware Triage** en el sidebar.
2. Arrastrá un archivo a la zona de drop (o hacé click para elegirlo desde el
   explorador). Podés soltar un PE (.exe/.dll), un ELF (binario Linux), un
   Mach-O (macOS/iOS), o cualquier otro archivo.
3. APT115 lee el archivo con `FileReader`, detecta el formato y corre **todos
   los analyzers que aplican** a ese tipo de archivo, uno debajo del otro como
   paneles colapsables. Cada panel se abre/cierra haciendo click en su título.
4. Cargar un archivo nuevo libera la memoria del anterior automáticamente.

Las secciones que siguen son los paneles que vas a ver para un **ejecutable**
(PE de Windows, ELF de Linux o Mach-O de macOS/iOS). Cada uno aparece solo si
aplica al archivo que soltaste — un ELF no muestra el panel "PE Structure",
por ejemplo.

### File Info

**Qué hace:** identifica el tipo de archivo por sus *magic bytes* (no por la
extensión), y si es un ejecutable muestra arquitectura, si es EXE o DLL/SO,
y la marca de tiempo de compilación (o avisa si esa marca no es una fecha
válida, lo que puede indicar un *reproducible build* o *timestomping*).

**Caso de uso:** es el primer panel que mirás siempre — confirma que el
archivo es lo que dice ser (un `.jpg` que en realidad es un PE es ya una señal
de alerta) y te da el contexto (arquitectura, plataforma) para interpretar
todo lo demás.

**Cómo usarlo:** no requiere acción — se completa solo al soltar el archivo.
Fijate especialmente en la fila **Tipo (magic bytes)**: si no coincide con la
extensión del archivo, es la primera señal sospechosa.

**Límites:** solo lee la cabecera; no valida que el resto del archivo sea
coherente con ese tipo.

**Para seguir investigando:** el comando `file` (Linux/macOS) o **TrID**/
**Detect It Easy (DIE)** en Windows hacen esta misma identificación con bases
de firmas mucho más grandes y dan más detalle sobre packers/instaladores. Si
"File Info" te tira algo raro (magic que no encaja, tamaño inconsistente),
confirmalo con `file -b <archivo>` antes de seguir.

### Hashes

**Qué hace:** calcula MD5, SHA-1 y SHA-256 del archivo completo (Web Crypto +
SparkMD5), y según el formato agrega hashes especializados: **imphash** y
**richhash** (PE), **build-id** y **telfhash** (ELF), **LC_UUID** (Mach-O), y
**TLSH** (fuzzy hash, para todos los formatos si el archivo tiene suficiente
complejidad). Cada hash tiene un botón de copiar, y debajo aparecen links
*opt-in* a VirusTotal y MalwareBazaar (solo abren una pestaña al hacer click —
no se consulta nada solo).

**Caso de uso:** SHA-256 es lo que vas a pegar en VirusTotal o compartir en un
reporte. **imphash**/**telfhash**/**richhash**/**TLSH** sirven para
*clustering*: encontrar otras muestras de la misma familia o del mismo
toolchain de compilación aunque el hash exacto del archivo no coincida.

**Cómo usarlo:** click en cualquier hash para copiarlo. Si tenés otro valor
TLSH a mano (de otra muestra), pegalo en el campo "comparar" para medir
distancia/similitud entre ambas.

**Límites:** TLSH necesita un mínimo de tamaño/complejidad — en archivos muy
chicos o muy uniformes da "N/A". El telfhash es una reimplementación fiel
pero no está cruzado contra una base pública.

**Para seguir investigando:** para clustering a mayor escala, **VirusTotal**
(retrohunt, similar-files) y **MalwareBazaar** ya tienen estos hashes
indexados contra millones de muestras — pegá el SHA-256 o el imphash/TLSH ahí
para ver familias relacionadas. Para fuzzy hashing más general (no solo
binarios), **ssdeep** es el estándar de facto.

### Entropía

**Qué hace:** calcula la entropía de Shannon del archivo completo y, si es un
PE, de cada sección por separado (en otros formatos, divide el archivo en 8
bloques). Valores ≳ 7.2 sugieren datos comprimidos o cifrados.

**Caso de uso:** detectar **packing** o payloads cifrados/comprimidos
embebidos. Una sección `.text` con entropía altísima (cuando normalmente
tendría 5-6) es una señal fuerte de que el código real está empacado y lo que
ves es un stub de descompresión.

**Cómo usarlo:** no requiere acción. Mirá qué sección o bloque tiene el valor
más alto — combinalo con el panel de **YARA** o **PEiD** para confirmar si
hay una firma de packer conocida ahí.

**Límites:** una entropía alta es una *señal*, no una prueba — un recurso PNG
embebido o datos ya comprimidos legítimamente también dan entropía alta.

**Para seguir investigando:** **Detect It Easy (DIE)** y **CFF Explorer**
grafican la entropía por sección igual que acá pero permiten además navegar
y volcar esas secciones a disco. Si confirmás packing, el siguiente paso es
un entorno **dinámico** (sandbox, debugger) para volcar la memoria
desempacada — algo que APT115 explícitamente no hace.

### PE Structure

**Qué hace:** parser propio de Portable Executable (Windows). Muestra
máquina, subsistema, entry point, image base, *characteristics*, las
**mitigaciones** (ASLR, DEP/NX, CFG, Force Integrity) como badges
✓/✗, la tabla de **secciones** (con su entropía), y los **imports** agrupados
por DLL — con las APIs "notables" resaltadas (las típicas de inyección de
proceso, persistencia, anti-debug, red/C2, etc., con un tooltip que explica
por qué importan).

**Caso de uso:** es el panel central para entender qué *puede hacer* un PE
sospechoso sin ejecutarlo: qué DLLs necesita, qué funciones de Windows usa
(¿`CreateRemoteThread` + `WriteProcessMemory`? eso es inyección), y si tiene
las protecciones de memoria que cabría esperar de un binario "normal".

**Cómo usarlo:** desplegá cada DLL en "Imports" haciendo click — las funciones
resaltadas en rojo/naranja (con tooltip) son las que vale la pena seguir.
Revisá "Mitigaciones": un binario reciente sin ASLR/DEP suele ser señal de un
build casero o de una herramienta de pentest, no necesariamente malware, pero
es un dato.

**Límites:** si el PE está empacado, la import table real puede estar oculta
(resuelta en runtime vía `LoadLibrary`/`GetProcAddress`, que de hecho son ellas
mismas imports "notables" — verlas solas en la lista es ya una pista).

**Para seguir investigando:** **PE-bear** y **CFF Explorer** dan el mismo tipo
de inspección con edición de la estructura y volcado de secciones; **pefile**
(Python) te deja scriptear el mismo análisis sobre lotes de muestras. Para
seguir el flujo real del programa (qué hace con esos imports), el siguiente
paso es desensamblar con **Ghidra/IDA/Binary Ninja** — `epdisasm` (más abajo)
te da apenas el entry point.

### Rich Header

**Qué hace:** decodifica el *Rich Header* de PE — una huella del toolchain
MSVC exacto (compilador/linker) que se usó para compilar el binario. Calcula
el **richhash** (para clustering: dos muestras con el mismo richhash salieron
de la misma cadena de build) y lista cada entrada con su Product ID y número
de build.

**Caso de uso:** atribución y clustering. Si tenés varias muestras de una
misma campaña, comparar richhash es una forma rápida de confirmar (o
descartar) que comparten infraestructura de compilación — incluso si el
código fue recompilado entre versiones.

**Cómo usarlo:** no requiere acción. Si el panel no aparece, el binario no
tiene Rich Header — típico de binarios **no compilados con MSVC** (MinGW/GCC)
o de binarios donde el header fue **stripeado/reescrito** deliberadamente.

**Límites:** los campos son metadata de build, no del comportamiento del
binario; su ausencia no es sospechosa per se (mucho malware en Go/Rust/MinGW
nunca lo tiene).

**Para seguir investigando:** herramientas como **rich_header_checker** o
las utilidades de **richheader** en pip permiten buscar el mismo richhash
contra colecciones propias de muestras. Para atribución más amplia, cruzá el
richhash junto con el imphash/TLSH en VirusTotal (panel de Hashes).

### Recursos / Firma

**Qué hace:** lee tres cosas de los recursos PE: el **version info**
(CompanyName, ProductName, OriginalFilename… — campos autodeclarados, fáciles
de falsificar pero útiles para detectar *impersonación*: un
`OriginalFilename: svchost.exe` en un binario llamado `update.exe` es una
bandera roja), el **manifest** (si pide `requestedExecutionLevel` elevado,
o sea que pide ejecutar como admin), y la firma **Authenticode** (parser ASN.1
propio que identifica al firmante real cruzando el serial del SignerInfo
contra la cadena de certificados embebida).

**Caso de uso:** evaluar si un binario *dice* ser algo que no es (version
info inconsistente con el nombre/comportamiento), si pide privilegios que no
debería necesitar, y si está firmado y por quién.

**Cómo usarlo:** no requiere acción. En "Firma digital" fijate si dice
"firma embebida" y quién es el **Firmante** — un certificado vencido, de una
CA poco común, o ausente del todo (sin firma Authenticode ni catálogo) sube
la sospecha. La cadena completa de certificados se puede desplegar.

**Límites:** la firma prueba *integridad e identidad del firmante*, no
inocuidad — malware firmado con certificados robados existe. APT115 no valida
la cadena criptográficamente contra una CA raíz ni chequea revocación (eso
requiere estado online); tampoco detecta firmas por **catálogo** (.cat del
sistema, fuera del propio archivo).

**Para seguir investigando:** **sigcheck** (Sysinternals) valida la cadena de
Authenticode completa contra las CAs del sistema y chequea revocación online —
es el paso natural si "Recursos / Firma" te muestra un firmante dudoso. Si el
certificado del SAN x509 te interesa en detalle, el tool **X.509 Cert
Inspector** de APT115 mismo (sección LAB/TOOLS) puede decodificar el PEM si lo
extraés.

### ELF Structure

**Qué hace:** el equivalente a "PE Structure" pero para binarios ELF de
Linux/Unix. Header (clase 32/64-bit, endianness, máquina, tipo, OS/ABI), si es
estático o dinámico (y su intérprete), si está *stripped*, **mitigaciones**
(NX, PIE, RELRO, stack canary, FORTIFY, BIND_NOW, y las modernas **CET**
IBT/Shadow Stack), dependencias dinámicas (`DT_NEEDED`, el análogo a los
imports de PE), símbolos importados/exportados (con resaltado de los
"notables": `execve`, `ptrace`, `mmap`+`mprotect`, sockets, `setuid`…), y una
**heurística de packer/anti-análisis** (segmentos RWX, firma UPX, entry point
fuera de `.text`, entropía alta por segmento, ausencia de tabla de secciones).
También detecta huellas de **Go/Rust** (con versión) cuando aplica.

**Caso de uso:** triage de malware/binarios Linux — qué syscalls/funciones usa
(¿`fork`+`setsid` para demonizarse? ¿`socket`+`connect` saliente o
`bind`+`listen` = bind shell?), qué tan "hardened" está compilado, y si hay
señales de empaquetado (UPX es extremadamente común en malware Linux).

**Cómo usarlo:** no requiere acción. Si está *stripped* y sin tabla de
secciones, el análisis sigue funcionando sobre los *program headers*
(robusto a binarios que intentan ocultar información). Revisá "Símbolos
importados" resaltados y la sección "Señales de packing".

**Límites:** símbolos importados son los que el *dynamic loader* resuelve en
runtime; un binario estático no los tiene aunque internamente llame a esas
syscalls.

**Para seguir investigando:** `readelf -a` / `objdump -d` (binutils) dan el
detalle crudo completo; **pwntools** trae `checksec` para las mitigaciones de
seguridad con el mismo resumen visual. Si "Señales de packing" marca UPX,
`upx -d` (el mismo UPX, modo decompresión) suele desempacarlo directo — algo
que APT115 deliberadamente no automatiza.

### Mach-O Structure

**Qué hace:** parser propio de Mach-O (macOS/iOS), soporta binarios *thin*
(una arquitectura) y *fat/universal* (varias slices, cada una analizada por
separado). Por slice: header y *load commands* → segmentos/secciones
(detectando constructores `__mod_init_func`, código Obj-C/Swift), **dylibs**
linkeadas con versiones, **entry point**, **UUID** (clustering), **rpaths**
(vector de *dylib hijacking*), plataforma/SDK/min-OS, símbolos
importados/exportados resaltados, cifrado **FairPlay** (apps de la App Store),
y la pieza más jugosa: la **firma de código** — CodeDirectory con flags
(`adhoc`/`hardened-runtime`/`library-validation`…), **Team ID**, si es CMS
real o *ad-hoc*, y los **entitlements** (con marcado especial de los
peligrosos como `get-task-allow` o `cs.disable-library-validation`).

**Caso de uso:** triage de malware/herramientas macOS/iOS — si un binario
está firmado de verdad o solo *ad-hoc* (típico de malware o herramientas
locales sin notarizar), qué entitlements peligrosos tiene, y si hay rpaths
explotables para *dylib hijacking*.

**Cómo usarlo:** no requiere acción. Para un binario *fat*, cada slice
(arquitectura) se muestra en su propia subsección — revisalas todas, a veces
solo una arquitectura lleva el payload malicioso. Prestá atención a "Tipo de
firma" y a "Entitlements de riesgo" si aparecen.

**Límites:** no valida criptográficamente la firma CMS contra una autoridad,
y no resuelve `DYLD_CHAINED_FIXUPS`/*exports trie* (binarios modernos sin
`LC_SYMTAB` completo pueden mostrar menos imports de los reales).

**Para seguir investigando:** **LIEF** (Python) permite scriptear el mismo
tipo de inspección y además **modificar** el binario; `codesign -dvvv` y
`spctl` (nativos de macOS) validan la firma contra Gatekeeper de verdad. Para
desensamblar, **Hopper** o **Ghidra** tienen soporte Mach-O maduro
(arm64e/pointer-auth incluido).

### .NET / CLR

**Qué hace:** extiende el parser PE — si el `DataDirectory[14]` (COM
Descriptor) no está vacío, parsea el header **COR20** (versión del runtime,
flags como `ILONLY`/`STRONGNAMESIGNED`, entry point token), el *metadata
root* (versión ej. `v4.0.30319`) y las tablas de metadata **#~** (Module,
Assembly, AssemblyRef/deps, conteo de TypeDef/MethodDef/etc. según el esquema
ECMA-335). Además, **detecta ofuscadores** conocidos (ConfuserEx, .NET
Reactor, Dotfuscator, SmartAssembly, Eazfuscator, Babel, Obfuscar,
ILProtector, CliSecure…) por firmas en los strings + heurísticas de
renombrado (identificadores no-ASCII, entropía del heap de strings de usuario,
etc.).

**Caso de uso:** identificar rápido si un binario es .NET, qué versión de
runtime/ensamblados referencia, y si pasó por un ofuscador comercial — lo cual
te dice de antemano si conviene ir directo a una herramienta de
desofuscación específica antes de leer el IL.

**Cómo usarlo:** no requiere acción; el panel aparece solo si el PE tiene CLR
header. Mirá primero si hay un ofuscador detectado — eso cambia el plan de
ataque para el siguiente paso.

**Límites:** **no decodifica el IL** (bytecode .NET) ni desofusca strings
cifrados — solo lee la tabla de metadata.

**Para seguir investigando:** **dnSpyEx** o **ILSpy** descompilan el IL a
C# legible — es el paso obvio después de confirmar que es .NET. Si se detectó
un ofuscador conocido, herramientas específicas (de-ConfuserEx, etc.) suelen
revertir buena parte antes de descompilar. La tool **PowerShell deob/obf**
de APT115 (sección LAB/TOOLS) puede ayudar si lo que hay embebido es un script,
no IL.

### Strings

**Qué hace:** extrae cadenas ASCII y UTF-16 (≥5 caracteres, hasta 8000), y
clasifica automáticamente las "notables" — URLs, IPs, rutas de archivo, claves
de registro, posibles strings en base64, etc. — con una etiqueta de color por
tipo, además de mostrar una muestra cruda con sus offsets.

**Caso de uso:** suele ser de los paneles más rentables — un atacante poco
cuidadoso deja URLs de C2, rutas de desarrollo (`C:\Users\...\Desktop\proyecto`),
nombres de mutex, o comandos en texto plano. Es también el primer lugar donde
mirar si sospechás un *config* embebido.

**Cómo usarlo:** revisá primero la sección "Notables" (ya filtrada y
etiquetada); la "Muestra" cruda de abajo sirve para buscar algo puntual con
Ctrl+F del navegador.

**Límites:** tope de 8000 strings (avisa si lo alcanzó); strings cifrados,
comprimidos o construidos en runtime (concatenación, `[char]`, XOR) no
aparecen como texto — para eso está **Crypto/Payload Lab** o **PowerShell
deob/obf**.

**Para seguir investigando:** **FLOSS** (FireEye/Mandiant, gratuito) extrae
además strings *construidos en runtime* mediante emulación — el salto natural
cuando "Strings" se ve sospechosamente vacío para el tamaño del binario. El
clásico `strings -a -e l` (binutils) sirve para extracciones puntuales por
línea de comandos sobre lotes de archivos.

### Capabilities (capa-lite)

**Qué hace:** mapea **capacidades** del binario (inyección de proceso,
persistencia, anti-análisis, C2, ransomware, robo de credenciales…) con tags
**ATT&CK/MBC**, inspirado en el proyecto **capa** de Mandiant pero liviano:
matchea sobre los **imports** y los **strings** que el triage ya extrajo (no
desensambla). Cada capacidad detectada muestra la evidencia concreta — qué
APIs o strings dispararon el match.

**Caso de uso:** un resumen ejecutivo de "qué tipo de cosa es esto" en un
vistazo — útil para priorizar entre varias muestras (¿cuál parece ransomware?
¿cuál tiene capacidades de robo de credenciales?) antes de meterte a fondo en
una sola.

**Cómo usarlo:** no requiere acción. Es una **heurística de orientación, no
de confirmación** — lo dice el propio panel: un binario *packed* expone pocos
imports y puede no disparar nada; eso en sí mismo es información (sugiere
empaquetado).

**Límites:** no sigue flujo de ejecución ni analiza *basic blocks* — un match
es "este import/string aparece", no "esta capacidad se ejecuta bajo esta
condición".

**Para seguir investigando:** la herramienta **capa** completa (Mandiant,
gratuita) sí analiza *basic blocks* con reglas mucho más numerosas y precisas
sobre el binario desensamblado — el upgrade natural una vez que sabés que vale
la pena profundizar en esa muestra.

### YARA

**Qué hace:** motor **YARA real** corriendo en WASM (libyara), 100% local y
offline. Tiene un editor de reglas con reglas de ejemplo precargadas, y un
selector para cargar **packs completos** de reglas públicas: Mandiant Red Team
(169 reglas), GCTI/Cobalt Strike (91), ReversingLabs (1240) y signature-base
de Florian Roth (5271).

**Caso de uso:** escanear el archivo cargado contra miles de firmas conocidas
de familias de malware, herramientas de C2, packers, etc. — sin instalar nada
ni mandar el archivo a ningún lado.

**Cómo usarlo:**
1. Elegí un pack del selector "cargar reglas…" (la primera vez tarda un poco
   en bajar/compilar el pack — queda "activo" sin volcarse entero al editor).
2. Click en **▶ Escanear**.
3. Si querés usar tus propias reglas, escribilas/pegalas en el editor — eso
   desactiva el pack activo y usa solo lo que está en el textarea.

**Límites:** la compilación es todo-o-nada: si tus reglas tienen errores, no
corre ninguna. Los packs grandes (signature-base, ~6MB) se cargan lazy la
primera vez que los elegís.

**Para seguir investigando:** el binario **`yara`** CLI (o **YARA-X**, el
reescrito en Rust) corre los mismos packs sobre directorios enteros o sets
masivos de muestras, y permite reglas con módulos no soportados en WASM
(`magic`, `cuckoo`, `dex`). Herramientas como **Loki**/**THOR** (Nextron)
empaquetan estos mismos packs para escaneo de hosts completos.

### Packer / Compiler (PEiD)

**Qué hace:** identifica el packer o compilador de un PE al estilo del
clásico **PEiD**, usando una base de ~4445 firmas sobre el *entry point* (y un
barrido acotado alrededor).

**Caso de uso:** confirmación rápida de un packer específico (UPX, ASPack,
Themida, etc.) — si "Entropía" ya te hizo sospechar packing, este panel te
dice *cuál*.

**Cómo usarlo:** no requiere acción.

**Límites:** depende de firmas exactas en el entry point; packers
personalizados o versiones nuevas no matchean nada (lo cual no significa que
no esté packeado — volvé a "Entropía"/"Señales de packing").

**Para seguir investigando:** **Detect It Easy (DIE)** mantiene una base de
firmas mucho más amplia y actualizada, además de heurísticas adicionales
(no solo el entry point) — es el sucesor de facto de PEiD y el primer lugar
donde mirar si este panel no encontró nada pero "Entropía" sigue sospechando.

### Entry Point (disasm)

**Qué hace:** desensambla el entry point del ejecutable (PE/ELF/Mach-O)
usando **Capstone v5** compilado a WASM (~1.8MB, carga *lazy* al apretar el
botón). Infiere la arquitectura del header (con override manual si hace
falta) y tiene robustez anti-ruido: detecta entropía alta en el EP (packing),
desincronización temprana del desensamblado, permite re-sincronizar con un
desfase manual, y un botón "seguir el primer salto" para mapear el `jmp`/`call`
inicial de un stub de packer hacia su destino.

**Caso de uso:** un vistazo rápido a las primeras instrucciones que ejecuta
el binario — útil para confirmar si el EP es código "normal" de compilador o
un stub de descompresión/loader.

**Cómo usarlo:**
1. Click en **▶ Desensamblar EP**. Si la arquitectura no se infirió bien,
   elegila manualmente en el selector.
2. Ajustá "instr" (cantidad de instrucciones) y "desfase" (re-sincronizar
   ±N bytes) si el desensamblado se ve corrupto.
3. Si una instrucción temprana es un `jmp`/`call` con destino inmediato,
   usá "▶ seguir a 0x..." para saltar ahí (típico para llegar al OEP real
   tras un stub de packer).
4. "copiar" exporta el desensamblado como texto.

**Límites:** **no desempaca** — es análisis estático puro. Ante packing real
o anti-disasm fuerte, esto detecta y deriva, no resuelve. Capstone WASM no
funciona en `file://` (sí servido desde `/apt115/`).

**Para seguir investigando:** **Ghidra**, **IDA Free/Pro** o **Binary Ninja**
desensamblan (y los dos primeros/Binary Ninja **descompilan**) el binario
completo, no solo el EP, con análisis de flujo y cross-references. Si el EP
acá apunta a un stub de packer reconocible, herramientas de *unpacking*
específicas (o un sandbox dinámico) son el siguiente paso — fuera del alcance
estático de APT115 a propósito.

---

## Triage: documentos, red y esteganografía

Esta sección cubre dos cosas distintas:

- Paneles que aparecen **dentro de Malware Triage** cuando soltás un
  **documento** (Office, PDF, .eml, .lnk) o una **imagen** en vez de un
  ejecutable: **Macros VBA**, **PDF**, **Email (.eml)**, **Windows Shortcut
  (LNK)** y **Esteganografía (imagen)**.
- Tools independientes del sidebar (**🧪 LAB / TOOLS**) pensadas para texto y
  payloads sueltos en vez de un archivo completo: **IOC Extractor**,
  **URL/Domain Inspector**, **Crypto/Payload Lab** y **Stego Lab**.

### Macros VBA (maldoc)

**Qué hace:** extrae el código VBA de documentos Office — tanto el formato
OLE legacy (.doc/.xls/.ppt) como OOXML con macros (.docm/.xlsm/.pptm) — y lo
analiza al estilo **olevba**: marca **auto-ejecución** (`AutoOpen`,
`Document_Open`, `Workbook_Open`…), **keywords sospechosas** (`Shell`,
`CreateObject`, `powershell`, `URLDownloadToFile`, `CreateThread`…),
**ofuscación** (`Chr()`, `StrReverse`, `Base64`…) y extrae **IOCs** (URLs/IPs)
directamente del código fuente de las macros.

**Caso de uso:** triage de un documento adjunto sospechoso (el vector de
phishing más común) — confirmar si tiene macros, si se auto-ejecutan al
abrirse, y qué hacen sin necesidad de abrir el documento en Office.

**Cómo usarlo:** soltá el documento en Malware Triage; el panel aparece solo
si detecta una estructura CFB/OLE o un `vbaProject.bin` dentro del ZIP
OOXML. Mirá primero "Indicadores" (auto-exec/sospechoso/ofuscación) y después
desplegá cada módulo en "Código" para leer el VBA descomprimido.

**Límites:** solo VBA — no cubre macros **Excel 4.0/XLM** (otro motor), RTF,
documentos cifrados con contraseña, ni **VBA stomping** (cuando el atacante
vacía el código fuente comprimido y el comportamiento real solo vive en el
p-code compilado).

**Para seguir investigando:** **oletools** (`olevba`, Python, mismo autor que
inspiró este analyzer) cubre Excel 4.0/XLM y documentos cifrados con
contraseñas comunes. Para VBA stomping, **ViperMonkey** emula el p-code
cuando el código fuente no está disponible.

### PDF (documento)

**Qué hace:** triage estilo **pdfid** (Didier Stevens) en dos niveles. El
nivel rápido (automático) cuenta keywords sospechosas (`/JavaScript`,
`/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`, `/JBIG2Decode`,
`/RichMedia`…), detecta **ofuscación de nombres** (`/J#61vaScript` ≡
`/JavaScript`), reporta la estructura (objetos/streams/xref/`%%EOF`,
incluidas actualizaciones incrementales sospechosas), extrae **URIs** y
destinos de `/Launch`, y avisa si hay datos tras el último `%%EOF` (payload
apendizado / polyglot). El nivel perezoso, con un botón, **infla los streams
`/FlateDecode`** localmente y busca JavaScript/exploits conocidos (`eval`,
`unescape`, `Collab.*`, `media.newPlayer`, heap-spray `%u...`, comandos de
sistema…).

**Caso de uso:** un PDF adjunto que querés revisar sin abrirlo en un lector
(que podría disparar el exploit). El nivel rápido te dice si vale la pena
seguir; el nivel de stream te muestra el JS real si lo hay.

**Cómo usarlo:** soltá el PDF en Malware Triage. Revisá "Indicadores" y
"Keywords sospechosas" primero. Si el panel sugiere JavaScript o no estás
seguro, click en **▶ Inflar streams y buscar JavaScript** — descomprime los
streams `/FlateDecode`/`/ASCIIHexDecode` y resalta los fragmentos con
indicadores, con snippets de contexto.

**Límites:** no resuelve referencias entre objetos PDF ni descifra PDFs
protegidos con contraseña.

**Para seguir investigando:** el paquete **pdf-tools** de Didier Stevens
(`pdfid.py` + `pdf-parser.py`) hace este mismo análisis con más profundidad
(navegación objeto por objeto, filtros adicionales); **peepdf** agrega un
shell interactivo y puede ejecutar el JS embebido en una caja controlada para
ver qué hace de verdad — el paso natural si "Inflar streams" encontró algo.

### Email (.eml)

**Qué hace:** triage de correos RFC822/MIME — el vector #1 de phishing.
Parsea headers (con *unfolding* de líneas de continuación) y el MIME
multipart recursivo (decodifica base64 y quoted-printable). Extrae
From/To/Subject/Date/Return-Path/Reply-To/Message-ID, evalúa
**SPF/DKIM/DMARC** como badges pass/fail (leídos de
`Authentication-Results`/`Received-SPF`/`DKIM-Signature`), detecta
**spoofing** (From ≠ Return-Path, Reply-To ≠ From, *display name* que simula
otra dirección, impersonación de marcas conocidas), reconstruye la **cadena
de Received** (hops + IP de origen), lista **URLs** del cuerpo, y para cada
**adjunto** decodificado calcula magic bytes + SHA-256 y marca extensiones
peligrosas o **dobles extensiones** (`factura.pdf.exe`).

**Caso de uso:** analizar un `.eml` reenviado/exportado para confirmar si es
phishing — quién lo mandó *realmente* (vs. quién dice ser), si pasó las
validaciones de autenticación, y si el adjunto es lo que pretende ser.

**Cómo usarlo:** soltá el `.eml` en Malware Triage (se detecta por heurística
de headers). El panel se aparece automáticamente; revisá "Autenticación"
(badges SPF/DKIM/DMARC) y "Indicadores" de spoofing primero, luego "Adjuntos"
para el hash/extensión real de cada archivo.

**Límites:** no valida criptográficamente la firma DKIM (solo lee el
resultado ya declarado en los headers, típicamente puesto por tu propio
servidor de correo); sin descifrado S/MIME.

**Para seguir investigando:** **MXToolbox** y similares permiten re-validar
SPF/DKIM/DMARC contra DNS en vivo (útil si el correo no pasó por un gateway
que ya lo evaluó). Para los adjuntos extraídos, volvé a soltarlos en Malware
Triage (PE/PDF/maldoc, lo que corresponda). **PhishTool**/**Any.Run** son el
siguiente paso si necesitás ver el comportamiento de URLs/adjuntos en
ejecución.

### Windows Shortcut (LNK)

**Qué hace:** parser propio de [MS-SHLLINK] — los `.lnk` son un vector de
**acceso inicial** muy común (el ícono dice "documento" pero el target es un
intérprete). Extrae LinkFlags, timestamps, *show command*; **LinkInfo**
(la ruta/target real, label de volumen, recurso de red si el LNK apunta a un
share UNC); **StringData** (nombre, ruta relativa, directorio de trabajo,
**argumentos** — donde suele ir el comando real); y **ExtraData** de alta
señal: variables de entorno con el target real, ícono real, y el
**TrackerDataBlock** con el **MachineID** (nombre NetBIOS de la máquina donde
se creó el LNK — útil para atribución/clustering). Marca **datos apendizados**
tras la estructura (payload embebido) e **indicadores**: uso de
powershell/mshta/rundll32/`-enc`/IEX/DownloadString/rutas UNC, y **ícono
spoofeado** (ícono de una app legítima pero el target es un intérprete).

**Caso de uso:** el `.lnk` que llega en un ZIP de phishing o en un USB —
confirmar qué ejecuta *de verdad* (vs. lo que el ícono/nombre sugieren), y
si trae un MachineID que pueda correlacionar con otras muestras de la misma
campaña.

**Cómo usarlo:** soltá el `.lnk` en Malware Triage. Mirá primero "Qué
ejecuta" e "Indicadores" — ahí está el target real y los argumentos.
"MachineID (build host)" en la cabecera es el dato de atribución.

**Límites:** **no parsea el `LinkTargetIDList`** (los *shell items* tipo
"esto apunta a Mi PC → Escritorio → archivo.txt") — se salta registrando su
tamaño; el target sale de LinkInfo/StringData/ExtraData, que en la práctica
es donde está la señal accionable.

**Para seguir investigando:** **LnkParse3** (Python) sí decodifica el
`LinkTargetIDList` completo si necesitás esa ruta de shell items. Si el LNK
viene de Jump Lists (`*.automaticDestinations-ms`/`*.customDestinations-ms`),
la tool **Jump Lists** de APT115 (sección Forensics) lo procesa en su
contexto original con el MRU de uso.

### Esteganografía (imagen)

**Qué hace:** dos niveles de esteganálisis sobre PNG/JPEG/GIF/BMP/WEBP. El
nivel **contenedor** (automático): encuentra el final lógico del archivo y
detecta **datos apendizados tras el EOF** (el truco clásico de "pegar" un ZIP
o ejecutable después del IEND/EOI), hace **carving** de magics embebidos
(ZIP/RAR/7z/PDF/gzip/ELF/PNG/JPEG dentro del archivo), y lee
**metadatos/comentarios** (chunks `tEXt`/`zTXt`/`iTXt` de PNG, `COM`/`EXIF`/
`XMP` de JPEG, comentario de GIF). El nivel **píxel** (perezoso, con botón):
decodifica la imagen con Canvas y corre el **ataque chi-cuadrado** de
Westfeld sobre LSB-replacement (estima la probabilidad de que haya algo
embebido), muestra los **planos de bit** (0-7 de cada canal, estilo
Aperi'Solve) y extrae el **stream LSB como strings**.

**Caso de uso:** una imagen sospechosa de un CTF o de una campaña que usa
esteganografía para ocultar payloads o configuración de C2 — primero el nivel
contenedor (rápido, casi siempre el "truco" real está ahí: algo pegado al
final), después el nivel de píxel si sospechás LSB.

**Cómo usarlo:** soltá la imagen en Malware Triage. El nivel contenedor
corre solo. Para el nivel de píxel, click en **▶ Analizar LSB y planos de
bit** — te muestra el score chi², y podés navegar los planos de bit por canal
y bit (0-7) buscando patrones visuales anómalos.

**Límites:** detecta **LSB-replacement**, datos apendizados y metadata — **no
rompe esquemas con clave** (Steghide, F5/matrix encoding); para esos, el panel
detecta la posibilidad pero deriva. El nivel de píxel se limita a ~40 MP.

**Para seguir investigando:** **zsteg** (Ruby) automatiza la búsqueda de LSB
en más variantes de bit-order/canal que el plano-por-plano manual de acá.
**binwalk** es el estándar para carving de archivos embebidos a mayor escala.
Si sospechás **Steghide**, **stegseek** hace fuerza bruta de passphrase contra
diccionarios — mucho más rápido que el stegcracker original.

### IOC Extractor

**Qué hace:** tool de texto (no de archivo) — pegás cualquier texto (un
reporte, un log, un email) y extrae automáticamente hashes (MD5/SHA-1/
SHA-256), URLs, emails, IPv4/IPv6, dominios, CVEs, IDs de **ATT&CK**, claves
de registro y rutas Windows. Soporta texto **defanged** (`hxxp://`,
`[.]`, `evil[.]com`) — lo *refanguea* antes de extraer — y puede *defanguear*
la salida para pegarla de vuelta en un reporte sin que los IOCs sean
clickeables/activos.

**Caso de uso:** te pasaron un reporte de threat intel o un log y necesitás
la lista limpia de IOCs para cargarlos en tu plataforma (MISP, una lista de
bloqueo, etc.) — sin copiar/pegar y limpiar a mano cada uno.

**Cómo usarlo:** pegá el texto en el textarea. La extracción corre en vivo;
cada categoría (hashes, URLs, IPs, dominios, CVE, ATT&CK…) aparece agrupada
con su conteo. Usá el toggle de defang/refang según necesites el resultado
"vivo" o "seguro para pegar en un doc".

**Límites:** extracción por expresiones regulares — no resuelve DNS, no
valida que una URL/dominio exista, y dominios que coinciden con extensiones
de archivo (`informe.pdf`) se filtran pero pueden colarse falsos positivos en
texto ambiguo.

**Para seguir investigando:** **CyberChef** tiene una receta "Extract IOCs"
similar pero encadenable con docenas de otras transformaciones. Para
*gestionar* IOCs a escala (deduplicar, taggear, compartir con tu equipo/la
comunidad), **MISP** es el estándar — exportá la lista de acá y armá un evento.

### URL / Domain Inspector

**Qué hace:** pegás URLs o dominios (uno por línea, defanged o no) y cada uno
se descompone y evalúa por riesgo. Decodifica **punycode → Unicode** (IDN),
detecta **homógrafos** (mezcla de scripts dentro de un label, o un label no
latino bajo un TLD de otro script — `аррӏе.com` sí dispara, `пример.рф` no),
**typosquatting** (distancia de Levenshtein + sustituciones leet `1`→`l`,
`0`→`o` sobre cada token — detecta `paypa1.com`), marca cuando el dominio
registrado real es distinto de la marca que aparenta el subdominio
(`paypal.com.evil.ru` → el dominio real es `evil.ru`), una heurística de
**DGA** (entropía, ratio de vocales, corridas de consonantes, dígitos sobre
el label), TLD abusados, IPs literales (decimal/hex), credenciales en la URL,
sobre-encoding, puertos no estándar y esquemas peligrosos.

**Caso de uso:** una lista de URLs/dominios sospechosos de un phishing,
un log de DNS, o IOCs de un reporte — priorizar cuáles vale la pena investigar
primero por su nivel de riesgo, y entender *por qué* un dominio parece
sospechoso (homógrafo vs. typosquat vs. DGA son problemas distintos con
remediaciones distintas).

**Cómo usarlo:** pegá una URL o dominio por línea en el textarea. Cada uno
aparece con su panel de riesgo (alto/medio/bajo) y el detalle de qué disparó
cada hallazgo. Los lookups a VirusTotal/urlscan/whois son **opt-in** — solo
abren un link al hacer click.

**Límites:** 100% heurístico y local — no resuelve DNS ni consulta listas de
reputación por sí mismo (eso son los lookups opt-in).

**Para seguir investigando:** **urlscan.io** y **VirusTotal** (los lookups
opt-in de acá) dan veredictos basados en escaneos reales y reputación
histórica. **dnstwist** genera variaciones typosquat/homógrafo de *tu propio*
dominio y chequea cuáles están registradas — el caso de uso inverso (defensivo
en vez de analizar un IOC que ya tenés).

### Crypto / Payload Lab

**Qué hace:** para destrabar payloads ofuscados. Pegás el blob (hex, base64 o
texto — auto-detectado) y ves su **entropía** (pista de cifrado/compresión vs.
XOR/texto plano). Cuatro modos: **(1) XOR brute de 1 byte** — prueba las 256
claves y ordena los candidatos por plausibilidad (texto imprimible + chi²
contra frecuencia del inglés + keywords + **magic bytes** — un candidato con
un magic reconocible en offset 0 va primero, casi siempre es la respuesta).
**(2) XOR con clave repetida** — estima el largo de la clave con el **Índice
de Coincidencia** por columnas (más robusto que Kasiski/Hamming en texto
ASCII) y recupera la clave columna por columna. **(3) XOR/RC4 con clave**
conocida (texto o hex). **(4) AES** (Web Crypto) CBC/CTR/GCM, cifrar o
descifrar con clave+IV en hex.

**Caso de uso:** un string en base64 que claramente no es texto plano, un
config de malware con XOR de clave corta, o un payload que sabés que es
AES y tenés (o querés probar) la clave.

**Cómo usarlo:** pegá el blob. Elegí el modo con los botones (XOR brute es el
default). Para "XOR clave repetida", el largo de clave estimado se muestra
antes de recuperarla. Para "XOR/RC4 con clave" y "AES" completá los campos de
clave/IV que aparecen. El resultado se puede copiar como texto/hex/b64, y se
detecta el magic del resultado (si parece un archivo reconocible, esa es la
señal de que acertaste).

**Límites:** el brute de 1 byte y la recuperación por columnas asumen que el
*plaintext* tiene sesgo estadístico (texto, scripts, binarios estructurados)
— un payload de alta entropía real (ya cifrado con algo fuerte) no se
destraba por XOR. No hace fuerza bruta de claves AES/RC4, solo aplica las que
le das.

**Para seguir investigando:** **CyberChef** tiene recetas equivalentes
encadenables (XOR Brute Force, "Magic" para detección automática) y mucho
más — el salto natural si necesitás combinar varios pasos (ej. base64 → XOR
→ gunzip). Para fuerza bruta real de claves (AES/RC4 con diccionario), scripts
con **pycryptodome** en Python te dan el control total.

### Stego Lab

**Qué hace:** la contraparte "constructora" del analyzer **Esteganografía
(imagen)** — embebe y extrae payloads en imágenes, con tres modos: **LSB**
(bit menos significativo de R/G/B, salida PNG sin pérdida), **Append** (pega
el payload tras el EOF, formato original) y **Metadata** (chunk `tEXt` de PNG
con keyword "A115"). Cifrado **AES-GCM 256** opcional con passphrase (PBKDF2-
SHA256, 200k iteraciones) — el blob lleva salt+IV embebidos.

**Caso de uso:** preparar un challenge de CTF, hacer pruebas de concepto de
exfiltración esteganográfica, o simplemente entender cómo se ve un payload
embebido para reconocerlo al analizar muestras reales (lo que produce esta
tool, el analyzer de Esteganografía de Malware Triage lo detecta de vuelta).

**Cómo usarlo:**
1. Pestaña **▸ Embeber**: soltá la imagen portadora, elegí el modo (LSB/
   Append/Metadata) con los botones, escribí o pegá el payload, opcionalmente
   una passphrase para cifrar con AES-GCM, y click en **▶ Generar**. Descargá
   el resultado (siempre PNG para LSB/Metadata).
2. Pestaña **◂ Extraer**: soltá la imagen con el payload embebido, indicá el
   modo (o probá los tres) y la passphrase si corresponde.

**Límites:** LSB/Append/Metadata son detectables por las herramientas
estándar (ese es el punto — interopera con el analyzer de Triage y con
`exiftool`/`zsteg`). No implementa esquemas con clave tipo F5/matrix encoding
(esos requieren su propio motor).

**Para seguir investigando:** **steghide** y **OpenStego** implementan
esquemas con clave (matrix encoding) más resistentes al chi² que el LSB
simple de acá — el upgrade si necesitás algo menos detectable. **zsteg**
sigue siendo la herramienta de referencia para *encontrar* lo que esta tool
(u otras) escondieron.

---

*Próximas secciones: LAB/TOOLS ofensivas y utilitarias, y Forensics — en
construcción.*
