---
title: "Manual de APT115 — Codex Arcanum"
date: 2026-06-15T02:01:03-03:00
draft: false
summary: "Manual de usuario de APT115: qué hace cada herramienta del toolkit de análisis estático y seguridad ofensiva, cuándo usarla, cómo paso a paso, y a qué herramienta profesional derivar cuando el triage llega a su límite."
tags: ["apt115", "malware", "análisis-estático", "seguridad-ofensiva", "forensics", "herramientas"]
---

Hay una tentación, frente a un archivo desconocido, de querer que una sola
herramienta diga la verdad sobre él: que se prenda una luz verde o una roja y
se termine la conversación. Este manual es, en parte, un argumento contra esa
tentación.

APT115 hace análisis estático: lee el archivo sin ejecutarlo, mira su
estructura, sus cadenas, sus firmas, y reporta lo que encuentra. Eso es mucho y
es poco al mismo tiempo. Es mucho porque la estructura de un binario dice más de
lo que su autor quisiera —los nombres de las secciones, los imports, la entropía
de un bloque comprimido, la marca de tiempo que no cuadra. Es poco porque nada
de eso es el archivo corriendo, mostrando lo que realmente hace cuando cree que
nadie lo mira.

Conviene decirlo de entrada: lo que sale de acá es *una* lectura, no *la*
lectura. Un triage orienta; no concluye. Indica por dónde empezar a desconfiar,
qué panel mirar dos veces, qué derivar a un sandbox o a un desensamblador de
verdad. La herramienta es necesaria y no es suficiente, y casi todo el daño que
se hace con estas cosas viene de confundir esas dos palabras —de leer un "no
detecté nada" como un "no hay nada".

Hay además una asimetría que conviene tener presente. Encontrar un indicador es
un problema de búsqueda: basta con que aparezca uno. Descartar que el archivo
sea malicioso es un problema de cobertura: habría que descartarlos todos, y eso
no se hace leyendo una cabecera en el navegador. Por eso, para cada herramienta,
el manual no solo explica qué hace y cómo se usa, sino a qué herramienta
profesional derivar cuando el triage llega a su límite. Saber dónde termina lo
que una herramienta puede afirmar es parte de saber usarla.

Lo que sigue recorre cada panel y cada tool con esa idea encima: qué mira, qué
señal importa, y qué no se sigue de lo que muestra.

---

[APT115 — Codex Arcanum](../../apt115/) es un toolkit de análisis estático de
malware y seguridad ofensiva que corre **100% en tu navegador**: nada se sube
a ningún servidor, nada se ejecuta, y la mayoría de los motores funcionan
incluso sin internet (`file://`). Este manual recorre cada herramienta:
**qué hace**, **cuándo usarla**, **cómo usarla paso a paso**, y a qué
herramienta profesional **derivar** cuando necesites ir más a fondo — porque
APT115 está pensado para orientar un triage rápido, no para reemplazar a un
analista ni a un sandbox.

## Índice

- [Triage: ejecutables y formatos](#triage-ejecutables-y-formatos)
- [Triage: documentos, red y esteganografía](#triage-documentos-red-y-esteganografía)
- [LAB / TOOLS ofensivas y utilitarias](#lab--tools-ofensivas-y-utilitarias)
- [Forensics](#forensics)

---

## Triage: ejecutables y formatos

La tool **🧪 Malware Triage** (menú LAB / TOOLS) es el punto de entrada para
todo lo de esta sección. Funciona así:

1. Abre `/apt115/` y elige **Malware Triage** en el sidebar.
2. Arrastra un archivo a la zona de drop (o haz click para elegirlo desde el
   explorador). Puedes soltar un PE (.exe/.dll), un ELF (binario Linux), un
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

**Caso de uso:** es el primer panel que miras siempre — confirma que el
archivo es lo que dice ser (un `.jpg` que en realidad es un PE es ya una señal
de alerta) y te da el contexto (arquitectura, plataforma) para interpretar
todo lo demás.

**Cómo usarlo:** no requiere acción — se completa solo al soltar el archivo.
Fíjate especialmente en la fila **Tipo (magic bytes)**: si no coincide con la
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

**Cómo usarlo:** click en cualquier hash para copiarlo. Si tienes otro valor
TLSH a mano (de otra muestra), pégalo en el campo "comparar" para medir
distancia/similitud entre ambas.

**Límites:** TLSH necesita un mínimo de tamaño/complejidad — en archivos muy
chicos o muy uniformes da "N/A". El telfhash es una reimplementación fiel
pero no está cruzado contra una base pública.

**Para seguir investigando:** para clustering a mayor escala, **VirusTotal**
(retrohunt, similar-files) y **MalwareBazaar** ya tienen estos hashes
indexados contra millones de muestras — pega el SHA-256 o el imphash/TLSH ahí
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

**Cómo usarlo:** no requiere acción. Mira qué sección o bloque tiene el valor
más alto — combinalo con el panel de **YARA** o **PEiD** para confirmar si
hay una firma de packer conocida ahí.

**Límites:** una entropía alta es una *señal*, no una prueba — un recurso PNG
embebido o datos ya comprimidos legítimamente también dan entropía alta.

**Para seguir investigando:** **Detect It Easy (DIE)** y **CFF Explorer**
grafican la entropía por sección igual que acá pero permiten además navegar
y volcar esas secciones a disco. Si confirmas packing, el siguiente paso es
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

**Cómo usarlo:** despliega cada DLL en "Imports" haciendo click — las funciones
resaltadas en rojo/naranja (con tooltip) son las que vale la pena seguir.
Revisa "Mitigaciones": un binario reciente sin ASLR/DEP suele ser señal de un
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

**Caso de uso:** atribución y clustering. Si tienes varias muestras de una
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
contra colecciones propias de muestras. Para atribución más amplia, cruza el
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

**Cómo usarlo:** no requiere acción. En "Firma digital" fíjate si dice
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
extraes.

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
(robusto a binarios que intentan ocultar información). Revisa "Símbolos
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
header. Mira primero si hay un ofuscador detectado — eso cambia el plan de
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
mirar si sospechas un *config* embebido.

**Cómo usarlo:** revisa primero la sección "Notables" (ya filtrada y
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
sobre el binario desensamblado — el upgrade natural una vez que sabes que vale
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
1. Elige un pack del selector "cargar reglas…" (la primera vez tarda un poco
   en bajar/compilar el pack — queda "activo" sin volcarse entero al editor).
2. Click en **▶ Escanear**.
3. Si quieres usar tus propias reglas, escribilas/pegalas en el editor — eso
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
no esté packeado — vuelve a "Entropía"/"Señales de packing").

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
   usa "▶ seguir a 0x..." para saltar ahí (típico para llegar al OEP real
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

- Paneles que aparecen **dentro de Malware Triage** cuando sueltas un
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

**Cómo usarlo:** suelta el documento en Malware Triage; el panel aparece solo
si detecta una estructura CFB/OLE o un `vbaProject.bin` dentro del ZIP
OOXML. Mira primero "Indicadores" (auto-exec/sospechoso/ofuscación) y después
despliega cada módulo en "Código" para leer el VBA descomprimido.

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

**Caso de uso:** un PDF adjunto que quieres revisar sin abrirlo en un lector
(que podría disparar el exploit). El nivel rápido te dice si vale la pena
seguir; el nivel de stream te muestra el JS real si lo hay.

**Cómo usarlo:** suelta el PDF en Malware Triage. Revisa "Indicadores" y
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

**Cómo usarlo:** suelta el `.eml` en Malware Triage (se detecta por heurística
de headers). El panel se aparece automáticamente; revisa "Autenticación"
(badges SPF/DKIM/DMARC) y "Indicadores" de spoofing primero, luego "Adjuntos"
para el hash/extensión real de cada archivo.

**Límites:** no valida criptográficamente la firma DKIM (solo lee el
resultado ya declarado en los headers, típicamente puesto por tu propio
servidor de correo); sin descifrado S/MIME.

**Para seguir investigando:** **MXToolbox** y similares permiten re-validar
SPF/DKIM/DMARC contra DNS en vivo (útil si el correo no pasó por un gateway
que ya lo evaluó). Para los adjuntos extraídos, vuelve a soltarlos en Malware
Triage (PE/PDF/maldoc, lo que corresponda). **PhishTool**/**Any.Run** son el
siguiente paso si necesitas ver el comportamiento de URLs/adjuntos en
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

**Cómo usarlo:** suelta el `.lnk` en Malware Triage. Mira primero "Qué
ejecuta" e "Indicadores" — ahí está el target real y los argumentos.
"MachineID (build host)" en la cabecera es el dato de atribución.

**Límites:** **no parsea el `LinkTargetIDList`** (los *shell items* tipo
"esto apunta a Mi PC → Escritorio → archivo.txt") — se salta registrando su
tamaño; el target sale de LinkInfo/StringData/ExtraData, que en la práctica
es donde está la señal accionable.

**Para seguir investigando:** **LnkParse3** (Python) sí decodifica el
`LinkTargetIDList` completo si necesitas esa ruta de shell items. Si el LNK
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
final), después el nivel de píxel si sospechas LSB.

**Cómo usarlo:** suelta la imagen en Malware Triage. El nivel contenedor
corre solo. Para el nivel de píxel, click en **▶ Analizar LSB y planos de
bit** — te muestra el score chi², y puedes navegar los planos de bit por canal
y bit (0-7) buscando patrones visuales anómalos.

**Límites:** detecta **LSB-replacement**, datos apendizados y metadata — **no
rompe esquemas con clave** (Steghide, F5/matrix encoding); para esos, el panel
detecta la posibilidad pero deriva. El nivel de píxel se limita a ~40 MP.

**Para seguir investigando:** **zsteg** (Ruby) automatiza la búsqueda de LSB
en más variantes de bit-order/canal que el plano-por-plano manual de acá.
**binwalk** es el estándar para carving de archivos embebidos a mayor escala.
Si sospechas **Steghide**, **stegseek** hace fuerza bruta de passphrase contra
diccionarios — mucho más rápido que el stegcracker original.

### IOC Extractor

**Qué hace:** tool de texto (no de archivo) — pegas cualquier texto (un
reporte, un log, un email) y extrae automáticamente hashes (MD5/SHA-1/
SHA-256), URLs, emails, IPv4/IPv6, dominios, CVEs, IDs de **ATT&CK**, claves
de registro y rutas Windows. Soporta texto **defanged** (`hxxp://`,
`[.]`, `evil[.]com`) — lo *refanguea* antes de extraer — y puede *defanguear*
la salida para pegarla de vuelta en un reporte sin que los IOCs sean
clickeables/activos.

**Caso de uso:** te pasaron un reporte de threat intel o un log y necesitas
la lista limpia de IOCs para cargarlos en tu plataforma (MISP, una lista de
bloqueo, etc.) — sin copiar/pegar y limpiar a mano cada uno.

**Cómo usarlo:** pega el texto en el textarea. La extracción corre en vivo;
cada categoría (hashes, URLs, IPs, dominios, CVE, ATT&CK…) aparece agrupada
con su conteo. Usa el toggle de defang/refang según necesites el resultado
"vivo" o "seguro para pegar en un doc".

**Límites:** extracción por expresiones regulares — no resuelve DNS, no
valida que una URL/dominio exista, y dominios que coinciden con extensiones
de archivo (`informe.pdf`) se filtran pero pueden colarse falsos positivos en
texto ambiguo.

**Para seguir investigando:** **CyberChef** tiene una receta "Extract IOCs"
similar pero encadenable con docenas de otras transformaciones. Para
*gestionar* IOCs a escala (deduplicar, taggear, compartir con tu equipo/la
comunidad), **MISP** es el estándar — exporta la lista de acá y arma un evento.

### URL / Domain Inspector

**Qué hace:** pegas URLs o dominios (uno por línea, defanged o no) y cada uno
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

**Cómo usarlo:** pega una URL o dominio por línea en el textarea. Cada uno
aparece con su panel de riesgo (alto/medio/bajo) y el detalle de qué disparó
cada hallazgo. Los lookups a VirusTotal/urlscan/whois son **opt-in** — solo
abren un link al hacer click.

**Límites:** 100% heurístico y local — no resuelve DNS ni consulta listas de
reputación por sí mismo (eso son los lookups opt-in).

**Para seguir investigando:** **urlscan.io** y **VirusTotal** (los lookups
opt-in de acá) dan veredictos basados en escaneos reales y reputación
histórica. **dnstwist** genera variaciones typosquat/homógrafo de *tu propio*
dominio y chequea cuáles están registradas — el caso de uso inverso (defensivo
en vez de analizar un IOC que ya tienes).

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
config de malware con XOR de clave corta, o un payload que sabes que es
AES y tienes (o quieres probar) la clave.

**Cómo usarlo:** pega el blob. Elige el modo con los botones (XOR brute es el
default). Para "XOR clave repetida", el largo de clave estimado se muestra
antes de recuperarla. Para "XOR/RC4 con clave" y "AES" completa los campos de
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
más — el salto natural si necesitas combinar varios pasos (ej. base64 → XOR
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
1. Pestaña **▸ Embeber**: suelta la imagen portadora, elige el modo (LSB/
   Append/Metadata) con los botones, escribe o pega el payload, opcionalmente
   una passphrase para cifrar con AES-GCM, y click en **▶ Generar**. Descarga
   el resultado (siempre PNG para LSB/Metadata).
2. Pestaña **◂ Extraer**: suelta la imagen con el payload embebido, indica el
   modo (o prueba los tres) y la passphrase si corresponde.

**Límites:** LSB/Append/Metadata son detectables por las herramientas
estándar (ese es el punto — interopera con el analyzer de Triage y con
`exiftool`/`zsteg`). No implementa esquemas con clave tipo F5/matrix encoding
(esos requieren su propio motor).

**Para seguir investigando:** **steghide** y **OpenStego** implementan
esquemas con clave (matrix encoding) más resistentes al chi² que el LSB
simple de acá — el upgrade si necesitas algo menos detectable. **zsteg**
sigue siendo la herramienta de referencia para *encontrar* lo que esta tool
(u otras) escondieron.

## LAB / TOOLS ofensivas y utilitarias

Estas tools viven en el grupo **🧪 LAB / TOOLS** del sidebar (no requieren
soltar un archivo de muestra). Varias de ellas comparten una **barra de
variables** arriba de la página (`LHOST`, `LPORT`, `RHOST`, `RPORT`,
`DOMAIN`): definilas una vez y se propagan a los payloads/templates que las
usan.

### Reverse Shell & C2

**Qué hace:** generador de payloads a partir de un catálogo de plantillas
(bash, Python, PHP, PowerShell, Netcat, socat, listeners, web shells,
persistencia, etc.), organizadas en pestañas por categoría. Cada plantilla
usa las variables `{LHOST}`/`{LPORT}`/`{RHOST}`/`{RPORT}`/`{DOMAIN}` de la
barra superior, y algunas categorías permiten **encoding** del resultado:
Raw, URL, Double-URL, Base64 o `powershell -enc` (UTF-16LE → base64).

**Caso de uso:** en un pentest/CTF autorizado, necesitas levantar rápido un
listener y un one-liner de reverse shell para una víctima Linux/Windows, o
un payload codificado para colarlo en un campo que filtra ciertos
caracteres (espacios, comillas).

**Cómo usarla:**
1. Completa `LHOST`/`LPORT` (y `RHOST`/`RPORT`/`DOMAIN` si aplica) en la
   barra de variables de arriba de la página.
2. Elige la categoría con las pestañas (bash, Python, PowerShell, etc.).
3. Si la categoría tiene encodings, elige uno con los botones de la fila
   `Encoding:`.
4. Click en cualquier payload (o en su botón **copy**) para copiarlo al
   portapapeles, ya con tus variables sustituidas.

**Límites:** es un catálogo de plantillas estáticas, no genera shellcode
binario ni evade AV/EDR — para eso hace falta un generador real (msfvenom,
Sliver) con encoders/stagers propios.

**Para seguir investigando:** **revshells.com** y la chuleta de
**PayloadsAllTheThings** tienen catálogos más extensos y actualizados.
**msfvenom** (Metasploit) genera shellcode/binarios con encoders reales, y
frameworks de C2 como **Sliver** o **Cobalt Strike** (con autorización)
manejan el listener, la sesión y el post-explotación de punta a punta —
acá sólo armas el one-liner inicial.

### Convert / Hash

**Qué hace:** una "mini-CyberChef" de operaciones puras input→output, todas
en un mismo panel con botones por categoría: **Base64/Hex/URL/Base32/HTML**
(encode/decode), **Cifras** (ROT-N y XOR en hex, usando el campo Key),
**JWT** (decodifica header/payload, avisa si `alg=none` o si `exp` ya
venció), **Hashes** (MD5/SHA-1/256/512 de un texto, y **Hash ID** que
reconoce el formato de un hash por longitud/patrón — bcrypt, md5crypt,
NTLM, etc.), **Timestamp** (epoch en s/ms/µs/ns o fecha → ISO/UTC/local/
relativo, en ambos sentidos) y **Regex** (pruebas un patrón `/.../flags` en
el campo Key contra el texto del input y ves cada match con sus grupos).

**Caso de uso:** tienes un string que "no se ve normal" y necesitas
decodificarlo rápido (JWT de una request, hash de una base de datos
filtrada, timestamp de un log, blob base64/hex de un payload) sin abrir
otra herramienta.

**Cómo usarla:**
1. Pega el texto en el textarea de **Input**.
2. Si la operación lo necesita (XOR, ROT-N, Regex), completa el campo
   **Key / N / patrón**.
3. Click en el botón de la operación deseada (agrupadas por categoría:
   Base64, Hex, URL, Base32, HTML, Cifras, JWT, Hashes, Timestamp, Regex).
4. El resultado aparece en el textarea de **Output**; **copy** lo manda al
   portapapeles.

**Límites:** XOR/ROT-N acá son transformaciones directas (no fuerza bruta —
para eso está **Crypto / Payload Lab** en Triage). El "Hash ID" es por
patrón/longitud, no es infalible (varios algoritmos comparten longitud).

**Para seguir investigando:** **CyberChef** es la versión completa —
recetas encadenables (varios pasos en pipeline) y muchas más operaciones.
Para JWTs específicamente, **jwt.io** y **jwt_tool** permiten además
*forjar* tokens para probar bypasses de firma.

### GTFOBins / LOLBAS

**Qué hace:** referencia **offline** y buscable de dos catálogos públicos:
**GTFOBins** (binarios Unix que se pueden abusar para escalar privilegios,
escapar de shells restringidas, etc., categorizados por técnica: suid,
sudo, capabilities, file read/write, shell, etc.) y **LOLBAS** (binarios y
scripts legítimos de Windows — "living off the land" — con comandos de
ejemplo y referencia a MITRE ATT&CK). Los datasets se cargan recién al
abrir la tool (no pesan en la carga inicial) y funcionan sin internet.

**Caso de uso:** estás en una shell limitada en Linux y encontraste que
`find` corre con bit SUID, o en una máquina Windows tienes `certutil`
disponible y quieres saber si sirve para algo más que validar certificados
— buscas el binario y la tool te muestra los one-liners ya armados.

**Cómo usarla:**
1. Elige la fuente con los botones **GTFOBins · Unix** / **LOLBAS ·
   Windows**.
2. Escribe en el buscador el nombre del binario o un comando/técnica (ej.
   `tar`, `suid`, `certutil`, `download`).
3. Opcionalmente filtra por categoría con el `<select>`.
4. Cada resultado muestra el binario, la(s) técnica(s) que aplican con su
   comando — click en **copy** para llevarlo al portapapeles. Los
   resultados están topeados a 60 binarios visibles; refina la búsqueda si
   hay más.

**Límites:** son los datasets públicos tal cual (licencia GPL de los
proyectos originales) — no valida si la técnica aplica a *tu* binario
específico (versión, flags disponibles, etc.), eso lo confirmas en la
máquina real.

**Para seguir investigando:** los sitios oficiales
**gtfobins.github.io** y **lolbas-project.github.io** tienen la versión
siempre actualizada (esta tool es un snapshot). Para automatizar la
detección de binarios SUID/capabilities en una máquina real, herramientas
de enumeración como **linpeas**/**winpeas** cruzan el sistema contra estas
mismas listas.

### Network Calc

**Qué hace:** tres calculadoras de red en una página. **IPv4**: de un
`a.b.c.d/n` calcula netmask, wildcard, network, broadcast, rango usable,
hosts usables y clasifica la IP (RFC1918, loopback, link-local, CGNAT,
multicast, etc.). **IPv6**: de una dirección con `/prefijo` muestra forma
comprimida y expandida, red, cantidad de direcciones (con BigInt) y tipo
(loopback, ULA, link-local, global unicast, etc.). **VLSM**: dado un bloque
base (`10.0.0.0/24`) y una lista de subredes con sus requerimientos de hosts
(`Ventas, 50` / `TI, 25` / `Enlace, 2`), calcula el plan de subneteo
*largest-first* con CIDR, máscara y rango de cada una. Además, una
**referencia de puertos** comunes para pentest, buscable por número o
servicio.

**Caso de uso:** estás armando el scoping de un pentest interno y necesitas
calcular rápido el rango de un `/26`, entender si una IP es RFC1918 o
pública, planificar subredes para varios departamentos desde un bloque
asignado, o recordar qué servicio corre típicamente en el puerto 5985.

**Cómo usarla:** cada calculadora recalcula **en vivo** mientras escribís
(sin botón "calcular"):
1. **IPv4**: escribe `a.b.c.d/n` en el primer campo (por defecto
   `10.10.14.7/24`).
2. **IPv6**: escribe la dirección con `/prefijo` (por defecto
   `2001:db8::1/64`).
3. **VLSM**: pon el bloque base y, una línea por subred, `nombre, hosts`
   en el textarea.
4. **Puertos**: escribe un número o parte de un nombre de servicio
   (`445`, `smb`, `ldap`) para filtrar la tabla.

**Límites:** la referencia de puertos es curada a mano (no es
`nmap-services` completo) — cubre los puertos más relevantes para pentest,
no todos los registrados en IANA.

**Para seguir investigando:** **ipcalc**/**sipcalc** en línea de comandos
hacen lo mismo que las calculadoras IPv4/IPv6 y son útiles para
scriptear. Para VLSM en redes grandes/complejas, herramientas de
documentación de red (IPAM como **NetBox**) llevan el registro persistente
que esta tool no guarda.

### Network Map

**Qué hace:** parsea la salida de **nmap** — XML (`-oX`) o grepable
(`-oG`/`.gnmap`) — y arma un mapa de hosts agrupados por subred `/24`,
mostrando IP, hostname, OS detectado (si está) y puertos abiertos con su
servicio/producto/versión. Resalta con una ⭐ los **servicios "jugosos"**
para pentest (SMB, LDAP, RDP, WinRM, bases de datos, Docker/K8s API,
Redis, etc., por nombre de servicio o número de puerto conocido). Permite
exportar el mapa como **texto**, **markdown** o **JSON**, o mandarlo
directo a una **nota** del panel de notas de APT115.

**Caso de uso:** terminaste un escaneo de nmap sobre un rango y quieres una
vista organizada por subred para priorizar — qué hosts tienen SMB/RDP/LDAP
abiertos (candidatos a AD), cuáles tienen una base de datos expuesta, etc.,
y dejar ese resumen como punto de partida en tus notas de la sesión.

**Cómo usarla:**
1. Pega en el textarea la salida de `nmap -oX -` (XML) o `nmap -oG -`
   (grepable/`.gnmap`) — se detecta el formato automáticamente y se
   procesa en vivo mientras pegas.
2. El mapa aparece agrupado por subred `/24`, con cada host y sus puertos
   abiertos; los servicios jugosos quedan marcados con ⭐.
3. Usa los botones **copiar md** / **copiar txt** / **copiar json** para
   exportar, o **→ nota** para crearla directo en el panel de notas de
   APT115.

**Límites:** sólo lista puertos en estado `open` (u `open|filtered`); no
interpreta scripts NSE más allá de lo que nmap ya puso en `service`/
`product`/`version`. El agrupado por subred es siempre `/24` para IPv4
(no configurable).

**Para seguir investigando:** **nmap** mismo sigue siendo la fuente —
para escaneos más agresivos o con NSE específico vuelves a la línea de
comandos. Para correlacionar el mapa con capturas de pantalla de servicios
web, **EyeWitness** o **gowitness**; para orquestar el flujo completo de
descubrimiento → enumeración, **AutoRecon**.

### Archive / APK

**Qué hace:** lee el **central directory** de un ZIP/JAR/APK/OOXML
(docx/xlsx/pptx) **sin descomprimirlo**, vía el mismo parser de ZIP que usa
el resto de APT115. Lista cada entrada con tamaño, tamaño comprimido,
ratio y método, y marca banderas de riesgo: **zip-slip** (rutas con
`../`), rutas absolutas o con backslash, **doble extensión señuelo**
(`factura.pdf.exe`), entradas **ejecutables**, archivos **anidados** (zip
dentro de zip) y **ratios de compresión absurdos** (>100×, señal de
zip-bomb). Detecta el tipo de contenedor (ZIP/JAR/APK/OOXML/ODF-EPUB). Para
**APK** además identifica los `classes*.dex`, las librerías nativas por ABI
(`lib/<abi>/`) y — decodificando el string pool del
`AndroidManifest.xml` binario (AXML) — extrae la lista de **permisos**
declarados.

**Caso de uso:** te llega un adjunto `.zip`/`.docx` o un `.apk` y antes de
extraer/instalar nada quieres saber qué hay adentro: ¿tiene un ejecutable
disfrazado de PDF? ¿intenta escribir fuera del directorio de extracción?
¿qué permisos pide la app Android (cámara, SMS, ubicación)?

**Cómo usarla:**
1. Suelta el archivo (`.zip`/`.jar`/`.apk`/`.ipa`/`.docx`/etc.) en la zona
   de drop, o haz click para elegirlo.
2. El panel **resumen** muestra tipo de contenedor, cantidad de entradas,
   tamaños y ratio global (con aviso si supera 50×).
3. Si es un APK, un panel **🤖 APK** lista DEX, ABIs nativas y permisos.
4. Si hay entradas con banderas, un panel **⚠ Riesgos** las lista con el
   detalle de cada bandera (hover para la descripción).
5. El panel **🗂 Entradas** (colapsado por defecto) tiene la tabla
   completa de todo el contenido.

**Límites:** lee la *estructura* — no descomprime ni ejecuta nada (salvo
el manifiesto del APK, que se infla sólo para leer el string pool). No
analiza el *contenido* de los archivos individuales (para eso, soltalos
en **Malware Triage** uno por uno).

**Para seguir investigando:** **apktool** y **jadx** descompilan un APK
completo (recursos + código Java/Smali) para análisis profundo; **binwalk**
es la referencia para extraer y recursar sobre archivos anidados/firmware.
Si los permisos o el `AndroidManifest` te interesan en detalle, `jadx`
también lo decodifica a XML legible directamente.

### X.509 Cert

**Qué hace:** decodifica un certificado **X.509** (PEM o DER) con un lector
ASN.1/DER local — el mismo motor que usa el triage de PE para Authenticode,
reutilizado acá de forma genérica. Muestra versión, número de serie,
algoritmo y validez de la firma, subject/issuer (DN completo), período de
validez, algoritmo y tamaño de la clave pública (RSA/EC/Ed25519, con
curva si aplica), extensiones (**SAN**, **Key Usage**, **Extended Key
Usage**, **Basic Constraints**), si es **autofirmado**, y las huellas
**SHA-1/SHA-256**. Marca advertencias: firma MD5/SHA-1, RSA < 2048 bits,
certificado vencido o aún no válido.

**Caso de uso:** capturaste el certificado de un servidor (con `openssl
s_client` o desde el navegador) o encontraste un `.crt`/`.pem` en una
muestra, y quieres inspeccionarlo rápido — ¿quién lo emitió, para qué
dominios es válido, usa criptografía débil, está vencido?

**Cómo usarla:**
1. Pega el bloque PEM (`-----BEGIN CERTIFICATE-----...`) en el textarea, o
   click en **Cargar archivo…** para soltar un `.crt`/`.cer`/`.pem`/`.der`.
2. Click en **Analizar**.
3. Si hay advertencias (firma débil, clave chica, vencido), aparecen
   primero en un bloque destacado. Después, paneles colapsables para
   Certificado, Subject, Issuer, Extensiones y Huellas.

**Límites:** es un **decodificador**, no un validador — no verifica la
firma ni construye/valida la cadena de confianza contra una CA raíz, y no
hace ninguna consulta de red (CRL/OCSP).

**Para seguir investigando:** `openssl x509 -text -noout` da la misma
información desde la línea de comandos y permite además **verificar la
cadena** (`openssl verify`). **testssl.sh** evalúa un servidor TLS
completo (cadena, protocolos, cifrados, vulnerabilidades conocidas) — el
paso natural si el certificado vino de un servidor en vivo.

### Sec Headers / CSP

**Qué hace:** pegas un bloque de headers HTTP de respuesta (con o sin la
status line) y los analiza, dando una **nota A+ a F** con un score 0-100.
Revisa: **HSTS** (presencia, `max-age`, `includeSubDomains`, `preload`),
**Content-Security-Policy** (ausencia, `unsafe-inline`/`unsafe-eval`,
comodines en `script-src`, directivas faltantes como `object-src`/
`frame-ancestors`/`base-uri`), **X-Frame-Options** vs `frame-ancestors`,
**X-Content-Type-Options**, **Referrer-Policy**, **Permissions-Policy**,
cada **Set-Cookie** (flags `Secure`/`HttpOnly`/`SameSite`), y fuga de
información en `Server`/`X-Powered-By`.

**Caso de uso:** estás auditando una aplicación web y quieres una pasada
rápida de hardening de headers — pegas la salida de `curl -I` o lo que ves
en la pestaña Network del navegador y obtienes una lista priorizada de qué
falta o está mal configurado, con la severidad de cada hallazgo.

**Cómo usarla:**
1. Pega los headers en el textarea, uno por línea (`Nombre: valor`); la
   status line `HTTP/1.1 200 OK` se ignora si está presente.
2. Click en **Analizar**.
3. Arriba aparece la nota (A+..F) y el score; debajo, la tabla de
   **hallazgos** ordenada por severidad (✖ crítico, ⚠ aviso, ℹ info, ✓ ok).
4. Paneles colapsables adicionales: **CSP desglosada** por directiva (si
   hay) y la lista completa de **headers recibidos**.

**Límites:** 100% estático sobre lo que pegaste — no hace ningún request,
no evalúa configuración de TLS/cifrados (eso es otra capa) ni sigue
redirects.

**Para seguir investigando:** **Mozilla Observatory** y
**securityheaders.com** hacen el mismo análisis pero contra el sitio en
vivo (incluyendo seguir redirects y verificar TLS). **testssl.sh** cubre la
capa de transporte (cifrados, protocolos) que esta tool no toca.

### CVSS Calc

**Qué hace:** convierte un **vector CVSS** en su score, soportando **v3.0,
v3.1 y v4.0** con las fórmulas oficiales de FIRST. Para v3.1/v3.0 calcula
Base, Temporal y Environmental según la especificación pública. Para v4.0
es un **port fiel** de la calculadora de referencia de FIRST (cálculo de
MacroVector + búsqueda en tabla + interpolación por distancia de
severidad), con las tablas de datos vendorizadas tal cual del proyecto
oficial (BSD-2-Clause). Valida que el vector tenga el prefijo correcto, las
métricas obligatorias y valores permitidos.

**Caso de uso:** estás redactando un hallazgo de pentest o un advisory y
necesitas el score CVSS correspondiente al vector que armaste (o quieres
verificar el score que aparece en un CVE contra su vector publicado).

**Cómo usarla:**
1. Pega el vector completo, incluyendo el prefijo (`CVSS:3.1/...` o
   `CVSS:4.0/...`).
2. Click en **Calcular** (o prueba los botones de ejemplo **ej. v3.1** /
   **ej. v4.0** para ver el formato).
3. El resultado muestra el score grande con su severidad (None/Low/Medium/
   High/Critical) y, para v3, el desglose Base/Temporal/Environmental. Un
   panel colapsable lista todas las métricas parseadas.

**Límites:** sólo hace **vector → score** — no ayuda a *elegir* los
valores de las métricas (eso requiere entender la vulnerabilidad).

**Para seguir investigando:** la **calculadora oficial de FIRST**
(first.org/cvss/calculator) es la referencia canónica y permite armar el
vector de forma interactiva, métrica por métrica, si no lo tienes armado
todavía. El **NVD** (nvd.nist.gov) publica vectores ya calculados para CVEs
conocidos, útiles para comparar.

### Cracking-prep

**Qué hace:** tres utilidades **offline** para preparar (no ejecutar) un
ataque de diccionario en un pentest autorizado. **(1) Perfilador de
objetivo** (lógica portada de CUPP): completas datos conocidos del objetivo
(nombre, apellido, apodo, pareja, hijos, mascota, empresa, fechas) y genera
candidatos combinando capitalización, variantes *leet*, concatenaciones de
palabras, sufijos numéricos/de fecha/símbolo y *keyboard walks* comunes —
con checkboxes para activar/desactivar cada estrategia. **(2) Estimador de
keyspace de máscara** (estilo PACK): una máscara hashcat (`?u?l?l?l?d?d?d`)
da el total de combinaciones y el tiempo estimado a una velocidad elegida
(GPU, rig, o bcrypt lento). **(3) Aplicador de reglas hashcat/JtR**: una
palabra base + reglas (una por línea, subset de funciones: `l u c C t r d f
{ } [ ] $ ^ T D o i s @`) muestra el resultado de cada regla.

**Caso de uso:** en un pentest autorizado conseguiste datos de OSINT sobre
un empleado (redes sociales, fechas) y quieres armar una wordlist dirigida en
vez de usar `rockyou.txt` a ciegas; o necesitas decidir si una máscara de
8 caracteres con mayúscula+minúsculas+dígitos es viable en el tiempo del
engagement.

**Cómo usarla:**
1. **Perfilador**: completa los campos que tengas (no hace falta llenarlos
   todos), tildá/destildá las estrategias (`leet`, `numbers`, `specials`,
   `caps`, `combine`, `walks`) y click en **Generar wordlist**. **copiar**
   o **descargar .txt** para usarla con hashcat/JtR.
2. **Keyspace de máscara**: escribe la máscara, elige una velocidad de
   referencia y click en **Estimar**.
3. **Reglas hashcat/JtR**: escribe la palabra base, una regla por línea, y
   click en **Aplicar** para ver la tabla regla→resultado.

**Límites:** el perfilador genera como máximo 50.000 candidatos y no
descarga ni incluye wordlists externas (`rockyou`, etc.). El subset de
reglas no cubre la sintaxis completa de hashcat (funciones avanzadas se
ignoran silenciosamente).

**Para seguir investigando:** **CUPP** (de donde está portada la lógica del
perfilador) tiene más opciones y se integra directo con crackers. **PACK**
(PEACEPESQUISH/policygen, hashcat-utils) analiza wordlists crackeadas reales
para derivar máscaras y reglas óptimas para *tu* objetivo, en vez de
genéricas. **hashcat** mismo es donde corren tanto las máscaras como las
reglas reales contra los hashes.

### SID / SDDL

**Qué hace:** decodifica dos formatos de seguridad de Windows/Active
Directory. Un **SID** (`S-1-5-32-544`) se resuelve a su nombre well-known
(usando la tabla de MS-DTYP), autoridad, y — si es un SID de dominio
(`S-1-5-21-...`) — separa el dominio del **RID** y lo resuelve contra la
tabla de RIDs conocidos (Administrator, Domain Admins, krbtgt, etc.). Un
descriptor **SDDL** (`O:BAG:DUD:(A;;FA;;;SY)...`) se desarma en Owner,
Group, **DACL** y **SACL**, y cada **ACE** se desglosa en tipo (Allow/Deny/
Audit/...), flags de herencia, derechos de acceso (resolviendo los códigos
de 2 letras como `FA`=`FILE_ALL_ACCESS`) y trustee — resolviendo también los
alias de SID de 2 letras (`BA`, `SY`, `WD`, etc.).

**Caso de uso:** estás revisando los permisos de un objeto de AD (con
`Get-Acl`, `dsacls`, o la salida de BloodHound) y tienes un SID o un SDDL
crudo que necesitas entender sin memorizar las tablas de MS-DTYP — por
ejemplo, para saber a quién corresponde un RID o qué significa exactamente
una ACE como `(A;OICI;FA;;;BA)`.

**Cómo usarla:** pega el SID o el descriptor SDDL completo en el textarea y
click en **Decodificar**. Se autodetecta el formato (si empieza con `S-1-`
y no tiene `O:`/`G:`/`D:`/`S:`, se trata como SID puro). Para SDDL, el
resultado son paneles colapsables **🔐 DACL** y **📝 SACL** con una fila por
ACE.

**Límites:** la tabla de SIDs well-known y RIDs de dominio es la estándar de
MS-DTYP — SIDs de objetos *específicos* de tu dominio (usuarios, grupos
custom) sólo muestran "DOMAIN principal (RID N)" sin nombre, porque ese
mapeo vive en el AD, no en una tabla pública.

**Para seguir investigando:** **BloodHound**/**SharpHound** mapean ACEs de
todo un dominio y muestran rutas de ataque (quién puede modificar a quién)
en lugar de un descriptor a la vez. En una máquina Windows, `Get-Acl` /
`icacls` / `dsacls` obtienen el SDDL real de un objeto para pegarlo acá.

### PowerShell deob

**Qué hace:** desarma capas comunes de ofuscación de PowerShell hasta
llegar a un punto fijo (máx. 25 iteraciones), aplicando repetidamente:
detección y decodificación de **`-EncodedCommand`**/base64 suelto (UTF-16LE
o UTF-8), expansión de **`[char]NN`**/`[char]0xNN` a literales, colapso del
**operador `-f`** (`"{0}{1}" -f 'a','b'` → `"ab"`), eliminación de
**backticks** de evasión (y expansión de `` `n``/`` `t``/`` `r``), y
**concatenación** de literales (`'a'+'b'` → `'ab'`). Por separado,
**descomprime** un blob base64 gzip/zlib/deflate-raw (probando los tres
formatos). El lado generador: a partir de un comando en claro, produce el
`-EncodedCommand` base64 correspondiente. Nada de esto se ejecuta — es
lectura/transformación de texto.

**Caso de uso:** encontraste un one-liner de PowerShell ofuscado (en un
script, un log, o como artefacto de un maldoc) y necesitas leer qué hace
realmente sin ejecutarlo; o al revés, necesitas generar un `-enc` para un
PoC.

**Cómo usarla:**
1. Pega el one-liner ofuscado en el textarea.
2. Click en **Deofuscar** — debajo aparecen las **capas** detectadas
   (`-EncodedCommand → UTF-16LE`, `[char] → literal`, `operador -f`,
   `backticks`, `concatenación`) y el resultado en el textarea de salida.
3. Si en cambio sospechas que hay un blob comprimido en base64, click en
   **Descomprimir gzip/b64** (prueba gzip/zlib/deflate-raw automáticamente).
4. Para generar un `-enc`, abre el panel **🛠 Generar -EncodedCommand**,
   escribe el comando y click en **→ -enc**.

**Límites:** cubre las técnicas de ofuscación *más comunes* — no es un
intérprete de PowerShell completo, así que lógica dinámica (variables que
se construyen en runtime, `Invoke-Expression` sobre algo calculado) puede
no resolverse del todo. Esta tool también se usa como motor de
deofuscación desde el analyzer **Macros VBA (maldoc)** del Triage.

**Para seguir investigando:** **CyberChef** tiene recetas "From Base64" +
"Decode text (UTF-16LE)" encadenables para los mismos pasos, más genérico.
**PSDecode** y **PowerDecode** son frameworks dedicados a deofuscar
PowerShell con un intérprete más completo (manejan variables y funciones
dinámicas) cuando esta tool no alcanza.

### Disassembler

**Qué hace:** desensambla bytes (hex en cualquier formato — con o sin
espacios/`0x`/`\x` — o base64) con **Capstone v5** compilado a WASM,
soportando **x86 (16/32/64), ARM, ARM64 y MIPS**. El motor (~1.8 MB) se
carga de forma perezosa al primer "Desensamblar". Es el mismo motor que usa
el analyzer **Entry Point (disasm)** del Triage para el entry point de un
PE/ELF — acá lo aplicas a *cualquier* blob de bytes que tengas a mano,
típicamente shellcode generado en otra tool de APT115.

**Caso de uso:** generaste un payload con **Reverse Shell & C2** o lo
extrajiste con **PowerShell deob**/**Crypto Lab**, y quieres leerlo
instrucción por instrucción para entender qué hace antes de usarlo o para
confirmar que el encoding/decoding salió bien.

**Cómo usarla:**
1. Pega los bytes en el textarea (hex con cualquier separador, o
   `\x55\x48...`, o base64).
2. Elige la arquitectura (`x64` por defecto) y el formato (`hex`/`base64`)
   con los `<select>`.
3. Opcional: cambia la dirección base (`0x1000` por defecto) si te importa
   que las direcciones mostradas coincidan con un offset real.
4. Click en **▶ Desensamblar** (o Ctrl/Cmd+Enter). La tabla resultante se
   puede copiar con **copiar**.

**Límites:** desensambla un blob plano — no resuelve relocations, símbolos
ni referencias cruzadas como lo haría un desensamblador sobre un binario
completo (para eso, suelta el binario en **Malware Triage**, no acá). En
`file://` el motor WASM no carga por restricciones del navegador; funciona
en el sitio servido o con `hugo server`.

**Para seguir investigando:** **radare2**/**Cutter** y **objdump** son las
opciones de línea de comandos equivalentes para un blob de bytes. Para
análisis de un *binario completo* con control de flujo, referencias
cruzadas y decompilación, **Ghidra** o **IDA** son el siguiente nivel —
esta tool es para una inspección rápida de un fragmento, no un proyecto de
reversing completo.

---

## Forensics

Estas tools viven en el grupo **🔬 Forensics** del sidebar. Todas trabajan
sobre un artefacto **ya extraído** (de un disco, una imagen forense, un
contenedor, etc.) — ninguna accede al sistema de archivos real ni monta
imágenes; sueltas el archivo puntual (un hive, un `$MFT`, un `.evtx`...) y la
tool lo parsea byte a byte en el navegador.

### Metadata Scrub

**Qué hace:** lee toda la metadata "oculta" de una imagen o documento —EXIF
(incluida geolocalización GPS), XMP, IPTC, perfil ICC en JPEG; chunks de
texto y `tIME`/`eXIf` en PNG; propiedades de autor/empresa/plantilla en
docx/xlsx/pptx; `/Info` y XMP en PDF— y te da una **copia limpia
descargable** (`nombre.cleaned.ext`), sin tocar el original.

**Caso de uso:** vas a compartir o publicar un archivo (una captura de
pantalla, un documento) y quieres sacarle el rastro antes: quién lo creó, con
qué software, y sobre todo si una foto lleva coordenadas GPS de dónde se
tomó.

**Cómo usarla:**
1. Abre **Metadata Scrub** en el sidebar.
2. Arrastra el archivo a la zona de drop o haz click para elegirlo (JPEG,
   PNG, docx/xlsx/pptx o PDF).
3. Se muestra la metadata detectada: EXIF con sus tags (si hay GPS, aparece
   un link directo a OpenStreetMap con la ubicación), XMP/IPTC/ICC, o
   `/Info`+XMP en PDF.
4. Si es JPEG, puedes tildar **conservar perfil de color ICC**.
5. Click en **⬇ Descargar copia limpia** — descarga `nombre.cleaned.ext` y
   te dice qué se quitó (y cuánto bajó de peso el archivo).

**Límites:** sólo cubre JPEG, PNG, OOXML (docx/xlsx/pptx) y PDF. En PDF el
scrub **blanquea los valores in-place** (preserva offsets) — no cubre
objetos en *object streams* comprimidos ni documentos con versiones
incrementales o firmados digitalmente.

**Para seguir investigando:** **mat2** (Metadata Anonymisation Toolkit) es
la referencia multiplataforma y cubre más formatos (audio, video, ODF...).
**exiftool** sigue siendo la herramienta de inspección/edición de metadata
más completa si necesitas algo más que un scrub rápido.

### SQLite Forensics

**Qué hace:** parser propio del formato SQLite 3 (sin motor SQL real) que
lee el schema, recorre los b-tree de cada tabla para listar las filas
**vivas**, y además **recupera registros borrados** haciendo *carving* del
espacio no asignado de cada página y de las páginas de la freelist — donde
el contenido viejo sigue ahí hasta que se sobreescribe.

**Caso de uso:** la mayoría de los artefactos modernos (historial y cookies
de navegador, bases de WhatsApp/Signal/Telegram, muchos artefactos
iOS/macOS) son SQLite. Un visor SQL normal sólo te muestra las filas vivas;
acá además puedes recuperar mensajes o entradas de historial **borrados**.

**Cómo usarla:**
1. Abre **SQLite Forensics**.
2. Suelta el archivo `.db`/`.sqlite`/`.sqlite3`.
3. Aparece el overview: page size, cantidad de páginas, encoding, páginas en
   la freelist (= contenido borrado potencialmente recuperable), y la lista
   de tablas.
4. Click en una tabla para ver el `CREATE` statement y sus filas vivas.
5. Click en **Escanear espacio no asignado + freelist** para recuperar
   filas borradas — aparecen marcadas con ♻ junto a las vivas.

**Límites:** no lee `-wal`/`-journal` (sólo el archivo principal), no
resuelve overflow de payloads muy grandes (los marca), y el carving puede
dar resultados parciales o nulos si la base fue compactada con `VACUUM`.

**Para seguir investigando:** **DB Browser for SQLite** o el `sqlite3` CLI
para consultas normales sobre las filas vivas. Para recuperación de borrados
más exhaustiva (incluido WAL), **sqlite-dissect** o tallar el archivo
completo con **bulk_extractor**.

### PCAP Analyzer

**Qué hace:** disecciona una captura **.pcap**/**.pcapng** de punta a punta
— capa de enlace (Ethernet/VLAN/SLL/RAW) → IPv4/IPv6 → TCP/UDP/ICMP — y
extrae **DNS** (consultas/respuestas), **HTTP** (host/URI/User-Agent) y el
**SNI** de los `ClientHello` TLS. Agrupa todo en conversaciones por 5-tupla y
arma una lista de **IOCs** (IPs, dominios, URLs) del tráfico.

**Caso de uso:** tienes una captura de tráfico de una sandbox, un honeypot o
una víctima, y quieres saber rápido con qué hosts/dominios habló (posible
C2), qué descargó por HTTP, y a qué dominios apuntaban las conexiones TLS
(SNI) sin tener que abrir Wireshark.

**Cómo usarla:**
1. Abre **PCAP Analyzer**.
2. Suelta el `.pcap`/`.pcapng`/`.cap`.
3. Arriba se muestra formato, byte order, link type, cantidad de paquetes y
   duración. Debajo: protocolos, las **conversaciones** top por bytes, y las
   tablas de **DNS**, **HTTP** y **TLS SNI** (sólo las que tengan datos).
4. La sección **IOCs** agrupa IPs/dominios/URLs — usa **copiar IOCs**, **→
   nota** (al panel de notas) o **exportar JSON** para el reporte completo.

**Límites:** no reensambla streams TCP multi-segmento ni fragmentación IP,
no descifra TLS (sólo lee el SNI en claro del ClientHello), y capa a 200.000
paquetes por archivo.

**Para seguir investigando:** **Wireshark**/**tshark** para inspección
completa con reensamblado de streams, filtros y decodificadores de
protocolo. **NetworkMiner** extrae automáticamente archivos/credenciales/
objetos transferidos de la misma captura.

### utmp / wtmp / btmp

**Qué hace:** parsea los registros de sesión de Linux —`/var/run/utmp`
(sesiones actuales), `/var/log/wtmp` (histórico de logins/logouts/reboots) y
`/var/log/btmp` (intentos de login **fallidos**)— y detecta indicios de
**manipulación**: registros en cero intercalados entre registros válidos
(blanqueo quirúrgico, típico de un utmp editor/rootkit) y timestamps fuera
de orden cronológico.

**Caso de uso:** revisar quién entró al sistema, cuándo, desde qué IP,
cuántos reinicios hubo, o cuántos intentos de login fallaron (fuerza bruta).
También útil para detectar si alguien intentó borrar su rastro editando
`wtmp` en vez de no dejarlo.

**Cómo usarla:**
1. Abre **utmp / wtmp / btmp**.
2. Suelta el archivo (`utmp`, `wtmp` o `btmp`).
3. Overview: cantidad de registros, reinicios, logins de usuario, usuarios e
   IPs remotas vistas.
4. Si se detectan anomalías, aparece una tabla aparte con el tipo y detalle
   de cada una.
5. Tabla de registros estilo `utmpdump` (tipo, PID, usuario, línea, host,
   IP, fecha) + **exportar JSON** / **→ nota**.

**Límites:** asume el struct de **amd64/glibc (registros de 384 B)** — otra
arquitectura/libc puede tener otro tamaño de registro; si el archivo no es
múltiplo de 384 se avisa pero no se reinterpreta.

**Para seguir investigando:** `utmpdump` (incluido en util-linux) para una
segunda lectura de referencia, y `last`/`lastb`/`lastlog` directamente en el
sistema si todavía está vivo.

### Jump Lists

**Qué hace:** parsea las **Jump Lists** de Windows —
`*.automaticDestinations-ms` (contenedor CFB con el stream `DestList` +
streams `SHLLINK`, reusando los parsers CFB y LNK propios) y
`*.customDestinations-ms` (secuencia de LNKs sin contenedor, que se tallan
directamente)— mostrando el orden **MRU**, último acceso, si está fijado
("pinned") y el equipo donde se generó cada entrada.

**Caso de uso:** reconstruir qué archivos o documentos abrió el usuario
recientemente con cada aplicación —incluso si después los borró—, en qué
unidad estaban (local, red o USB), y desde qué equipo (`MachineID`), algo
que las Jump Lists conservan mucho más tiempo que el "Recientes" visible.

**Cómo usarla:**
1. Abre **Jump Lists**.
2. Suelta el archivo, típicamente desde
   `…\Recent\AutomaticDestinations\<AppID>.automaticDestinations-ms` o
   `…\CustomDestinations\<AppID>.customDestinations-ms`.
3. El overview muestra el tipo de Jump List y el **AppID** — si está en la
   base curada de APT115 (Explorer, Chrome, Edge, Word, PowerShell, etc.) se
   resuelve el nombre de la app.
4. Si hay indicadores (rutas de red UNC, unidades USB, ejecutables/scripts,
   MachineIDs), aparecen en un panel separado.
5. Tabla de entradas/destinos en orden MRU + **exportar JSON** / **→ nota**.

**Límites:** la base de AppIDs es **parcial** (curada a mano) — apps no
listadas se muestran con su AppID en hex sin nombre resuelto.

**Para seguir investigando:** **JLECmd** (Eric Zimmerman) parsea Jump Lists
con cobertura completa y una base de AppIDs mucho más extensa; **LECmd** del
mismo autor para analizar LNKs individuales con todo el detalle.

### $MFT (NTFS)

**Qué hace:** parsea un `$MFT` de NTFS ya extraído, reconstruyendo el
**timeline del filesystem** (fechas MACE de cada archivo), listando
**archivos borrados** (registros marcados como no-en-uso) y data
**residente** (contenido chico embebido directo en el registro MFT). Además
detecta **timestomping**: compara los timestamps de `$STANDARD_INFORMATION`
(triviales de alterar con `SetFileTime`) contra los de `$FILE_NAME` (mucho
más difíciles de modificar), y marca discrepancias.

**Caso de uso:** armar una línea de tiempo de actividad del filesystem y
detectar si alguien intentó camuflar la fecha real de creación/modificación
de un archivo (técnica anti-forense clásica tras dejar caer un payload).

**Cómo usarla:**
1. Abre **$MFT (NTFS)**.
2. Suelta el `$MFT` ya extraído (registros `FILE` de 1024 B).
3. Overview: registros parseados, archivos/directorios, borrados, cuántos
   tienen data residente, y si hubo problemas de *fixup* (sector
   inconsistente).
4. Si hay señales de timestomping, aparece una tabla con el número de
   registro, nombre y el detalle de cada señal (ej. "SI.crtime anterior a
   FN.crtime").
5. Tabla de registros (nombre, padre, tamaño, fechas SI) + **exportar JSON**
   / **→ nota**.

**Límites:** `$DATA` no-residente lista los *runs* pero no resuelve su
contenido; no sigue `$ATTRIBUTE_LIST` hacia registros de extensión.

**Para seguir investigando:** **MFTECmd** (Eric Zimmerman) / **analyzeMFT**
para un parseo completo con export a CSV o bodyfile, listo para cargar en
**Plaso**/**timeline tools** y cruzar con otras fuentes.

### Registry Hive (regf)

**Qué hace:** parsea un hive del registro de Windows (`NTUSER.DAT`,
`SOFTWARE`, `SYSTEM`, `SAM`...), recorriendo el árbol completo de claves y
valores con su fecha de **last-write**. Resalta automáticamente **hallazgos
forenses** sobre rutas curadas de alto valor —`Run`/`RunOnce` (persistencia),
`Services`, `UserAssist`, `RecentDocs`, `TypedPaths`/`TypedURLs`, `RunMRU`,
`USBSTOR`/`MountPoints2` (USB), `AppCompatCache` (ShimCache), `BAM`, IFEO,
`Winlogon`, `MUICache`— y avisa si el hive está **sucio** (logs de
transacción sin aplicar). También **recupera claves y valores borrados**
tallando las celdas libres del hive por firma `nk`/`vk`.

**Caso de uso:** cazar persistencia (claves Run, servicios, IFEO,
Winlogon) y reconstruir actividad/ejecución del usuario (UserAssist,
RecentDocs, ShimCache, BAM, dispositivos USB conectados) en un hive
extraído de una máquina comprometida.

**Cómo usarla:**
1. Abre **Registry Hive (regf)**.
2. Suelta el hive (debe tener el magic `regf`).
3. Overview: versión, nombre interno, última escritura, y si el hive está
   limpio o **sucio**.
4. **Hallazgos forenses**: lista de claves curadas con su por qué (ej.
   "Persistencia (Run)") y los valores que contienen.
5. Si hay celdas libres con `nk`/`vk` recuperables, aparece **Recuperados de
   celdas libres** (claves y valores borrados).
6. **Árbol de claves** navegable completo (`<details>` colapsables) +
   **exportar JSON** / **→ nota**.

**Límites:** no aplica los logs `.LOG1`/`.LOG2` (sólo avisa si el hive está
sucio); valores "big data" (>16 KB) listan tamaño pero no se reensamblan;
los descriptores de seguridad (`sk`) no se decodifican, sólo se cuentan.

**Para seguir investigando:** **RegRipper** corre plugins específicos por
cada hallazgo (Run keys, UserAssist, ShimCache...) con interpretación más
profunda. **Registry Explorer** (Eric Zimmerman) permite navegación completa
y recuperación avanzada, incluyendo los logs de transacción.

### Event Log (EVTX)

**Qué hace:** parsea un `.evtx` (Windows Event Log) decodificando su
**Binary XML** —el sistema de templates + arrays de substitución que hace
que este formato sea de los más difíciles— y reconstruye cada evento como
XML, extrayendo `<System>`/`<EventData>`. Resalta los **EventID de alto
valor forense** (4624/4625 logons, 4688 procesos, 7045/4697 servicios
instalados, 1102/104 borrado de logs, 4104 PowerShell script block, 4720+
gestión de cuentas, Kerberos, etc.) y detecta **contenido sospechoso**
(patrones de LOLBins/ofuscación: `-enc`, `downloadstring`, `iex`,
`certutil`, `rundll32`...).

**Caso de uso:** timeline forense de un Windows comprometido — quién inició
sesión y cuándo, qué procesos se crearon, qué servicios se instalaron
(persistencia), si se ejecutó PowerShell con contenido sospechoso, o si se
borró el log de eventos (anti-forense).

**Cómo usarla:**
1. Abre **Event Log (EVTX)**.
2. Suelta el `.evtx` ya extraído (magic `ElfFile`).
3. Overview: versión, cantidad de chunks, eventos parseados, próximo
   record#, y si el log está limpio o **sucio**/lleno.
4. **Hallazgos forenses**: tabla con record#, EventID, hora, qué significa,
   y un resumen de los datos del evento — marcados con ⚠ si coinciden con un
   patrón sospechoso.
5. Tabla completa de eventos (record#, EventID, nivel, hora, proveedor,
   canal) + **exportar JSON** / **→ nota**.

**Límites:** no procesa templates que cruzan chunks (caso raro); los valores
binarios se muestran en hex; no resuelve los mensajes legibles que dependen
de la DLL del proveedor (los datos crudos sí se extraen).

**Para seguir investigando:** **python-evtx** o `Get-WinEvent`/`wevtutil`
(PowerShell) para una segunda lectura. Para *threat hunting* con reglas
sobre EVTX, **Chainsaw** o **Hayabusa** aplican detecciones Sigma
directamente sobre estos mismos archivos.

### journald (systemd)

**Qué hace:** es el equivalente Linux de la tool EVTX — parsea un
**journal binario de systemd** (`.journal`, formato **COMPACT**),
recorriendo la cadena de *entry arrays* → objetos `ENTRY` → objetos `DATA`
para reconstruir cada entrada con todos sus campos (`MESSAGE`, `_PID`,
`_UID`, `_COMM`, `_SYSTEMD_UNIT`, `PRIORITY`, `_HOSTNAME`...). Resalta
**señales forenses**: logins SSH (exitosos/fallidos), uso de `sudo`/`su`
(con el comando ejecutado), aperturas/cierres de sesión, crashes/OOM,
servicios caídos y mensajes de prioridad error/crítico.

**Caso de uso:** timeline de actividad de un Linux comprometido — accesos
SSH (incluido fuerza bruta), escaladas con `sudo`, procesos que crashearon,
servicios systemd que fallaron.

**Cómo usarla:**
1. Abre **journald (systemd)**.
2. Suelta el `.journal` ya extraído (magic `LPKSHHRH`).
3. Overview: Machine ID, Boot ID, flags del archivo (COMPACT, KEYED-HASH,
   compresión ZSTD/LZ4/XZ si aplica), cantidad de entradas y rango temporal
   cubierto.
4. **Hallazgos forenses**: tabla con hora, qué es (ej. "SSH login fallido",
   "sudo — comando"), proceso/PID y el mensaje.
5. Tabla completa de entradas (hora, unit/proceso, PID, prioridad, mensaje)
   + **exportar JSON** / **→ nota**.

**Límites:** soporta el formato moderno COMPACT; los payloads `DATA`
grandes (>512 B) comprimidos con ZSTD/LZ4/XZ se **marcan** pero no se
descomprimen (los campos chicos, la inmensa mayoría en la práctica, se leen
directo sin problema).

**Para seguir investigando:** `journalctl` sobre el mismo archivo
(`journalctl --file=...`) para todos los filtros y formatos de salida
nativos de systemd. Para centralizar y correlacionar logs de muchas
máquinas, **Loki** o un stack **ELK**.
