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
- Triage: documentos, red y esteganografía — próximamente
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

*Próximas secciones: Triage de documentos/red/esteganografía, LAB/TOOLS
ofensivas y Forensics — en construcción.*
