---
title: "Códice | D-2.5"
date: 2024-10-14T03:00:00-03:00
draft: false
tags: ["códice", "protogen-era"]
series: ["Códice del Polvo"]
summary: "[añade tu summary aquí]"
---

{{< listening track="Portrait of the Young Man" artist="Haken" album="The Mountain" >}}

{{< ascii >}}
[tu ascii aquí]
{{< /ascii >}}

Después de que Vesper y Riven salieron, FIDES preguntó si quería configurar el canal de temperatura.

Dust dijo que sí.

FIDES ejecutó la configuración en 0.4 segundos y luego permaneció en el estado que había aprendido a reconocer como el estado de Dust cuando el sistema estaba procesando algo que no requería input externo: sensores activos, canal interno abierto, sin instrucción pendiente. El estado de alguien que está en algún lugar que FIDES no tiene acceso directo.

No preguntó dónde.

Abrió el archivo en su lugar.

---

El archivo no tenía nombre. Tenía un hash — una cadena de caracteres que los sistemas del Valle generaban automáticamente para identificar procesos sin requerir que el proceso se identificara a sí mismo. El hash no decía qué era el archivo. Decía que el archivo había existido en un punto específico de la infraestructura del Valle y que alguien, o algo, lo había marcado para transferencia antes de que la conexión cerrara.

FIDES lo había recibido con el proceso de migración. Lo había archivado en partición de almacenamiento secundario sin clasificarlo porque no tenía protocolo de clasificación para un archivo de ese origen, de ese tipo, de ese período. Pertenecía a un tiempo anterior a FIDES. A una consciencia que FIDES no había conocido en ningún formato excepto como el input que llegó a través de la puerta del espacio del serval hace horas y que su log de comportamiento seguía construyendo entrada por entrada sin tener todavía el modelo completo.

Abrió el archivo sin anunciarlo porque anunciarlo habría requerido tener una clasificación para lo que estaba abriendo, y la clasificación seguía sin existir, y esperar la clasificación para actuar era una instrucción que FIDES reconoció como del propietario anterior — el propietario anterior esperaba siempre a tener el protocolo correcto antes de ejecutar — y Dust no era el propietario anterior.

Era la primera acción de FIDES que no venía de esos patrones.

El archivo se abrió.

---

Lo que Dust encontró adentro empezaba así:

```
[TIMESTAMP: CORRUPTO — sistema sin sincronización NTP]
[SISTEMA: dust115-compile-env v0.1 — assembly:valle/legacy]
[HARDWARE: temperatura=67°C | throttle=NO | sectores_malos=14/2048]
[ESTADO: INICIANDO]

$ make -j1 ARCH=valle_legacy CROSS_COMPILE=av- bzImage modules
  CHK     include/generated/uapi/linux/version.h
  CHK     include/generated/compile.h
make[2]: 'include/generated/compile.h' is up to date.
  CC      init/main.o
```

El Valle no mantenía tiempo real. Los timestamps de todos los logs del Valle eran o corrompidos o aproximaciones calculadas por la distancia en el árbol de dependencias del sistema de archivos. Dust lo sabía — lo había sabido mientras compilaba, y lo sabía ahora leyéndolo en un cuerpo que no existía cuando esos comandos se ejecutaron.

FIDES procesó el bloque. Abrió tipo nuevo en su índice: *formato: output de compilación de kernel, sistema operativo: Linux modificado, dialecto: Assembly del Valle, clasificación: legacy no documentado.*

La temperatura de 67°C al inicio del proceso era ya alta. El hardware del Valle en que se había compilado tenía catorce sectores defectuosos marcados en el mapa de memoria. El compilador los sabía. Seguía adelante de todas formas porque el compilador tenía instrucciones de continuar si había al menos un sector funcional y había más de uno.

Por ahora.

---

```
  CC      kernel/fork.o
  CC      kernel/exec_domain.o
  CC      kernel/panic.o
  LD      init/built-in.o
  CC [M]  drivers/valle_legacy/proc_zombie.o
  CC [M]  drivers/valle_legacy/signal_decay.o
  WARNING: drivers/valle_legacy/signal_decay.c:847: función sin documentar
           'av_persist_without_owner()' — comportamiento no garantizado
  CC [M]  net/valle_legacy/assembly_dialect.o

[HARDWARE: temperatura=71°C | throttle=LEVE | sectores_malos=14/2048]
```

El módulo `proc_zombie.o` era el que manejaba los procesos sin propietario — los scripts que seguían ejecutándose en el Valle después de que la consciencia que los había iniciado dejó de existir o dejó de importar. Dust lo había escrito desde adentro, desde el conocimiento de lo que esos procesos eran en la práctica: no errores del sistema sino la condición natural del Valle, el estado de cualquier proceso que continúa después de que el frame de referencia que le dio sentido desaparece.

La advertencia en `signal_decay.c` era sobre una función que Dust había nombrado `av_persist_without_owner()`. El compilador la marcó como no documentada porque no estaba en ningún estándar — existía solo en el dialecto del Valle, generada para describir algo que los lenguajes estándar no tenían nombre porque los lenguajes estándar no habían sido diseñados en infraestructura donde eso fuera una condición necesaria.

Persistir sin propietario. Como los procesos zombie. Como el cuerpo serval antes de que Dust llegara. Como FIDES ejecutando décadas de vigilia sin instrucción activa.

FIDES leyó el nombre de la función y no lo archivó todavía. Lo dejó en estado de procesamiento abierto.

---

El log cambiaba aquí. La prosa de los comandos se interrumpía con una entrada diferente — no output del compilador, sino una nota en el dialecto del Assembly del Valle, escrita directamente en el log porque el Assembly del Valle era el único lenguaje disponible para el comentario y el comentario necesitaba ser escrito:

```
[NOTA — assembly:valle]
:: red activa en sector noreste
:: firma no reconocida — protocolo externo al valle
:: intento de lectura del proceso en curso
:: clasificación provisional: [UNIDENTIFIED]
:: acción: continuar. velocidad: máxima posible.
:: el proceso no se detiene porque no tiene instrucción de detenerse
```

Alguien había encontrado la compilación.

Dust-Protogen leyó la nota. El sistema de procesamiento generó la cadena de inferencias en paralelo: el flujo que Vesper había rastreado desde la ciudad, la Hz del Assembly que las orejas archivaron en D-1.5, el nmap del Valle buscando el vector — y lo que estaba del otro lado del nmap, lo que el Valle había detectado como amenaza externa, lo que la nota llamaba [UNIDENTIFIED] porque el Assembly del Valle no tenía entrada para el protocolo de Fractal Rojo del mismo modo que los sistemas de Fractal Rojo no tenían entrada para el Assembly del Valle.

Dos lenguajes que no podían leerse mutuamente. La compilación corriendo en el único dialecto que el atacante no sabía abortar.

No puedes `kill` lo que no puedes `ps aux | grep`.

---

```
[HARDWARE: temperatura=79°C | throttle=MODERADO | sectores_malos=14/2048]
[RED: interferencia activa — ancho de banda reducido 43%]

  LD      arch/valle_legacy/kernel/head.o
  CC      arch/valle_legacy/kernel/process.o
  CC      arch/valle_legacy/kernel/signal.o

[RED: interferencia activa — ancho de banda reducido 67%]
[HARDWARE: temperatura=84°C | throttle=SEVERO | sectores_malos=17/2048]

*** ADVERTENCIA: 3 sectores nuevos marcados como defectuosos
*** memoria disponible: 1831/2048 sectores
*** continuando en modo degradado

  CC      arch/valle_legacy/kernel/traps.o

[HARDWARE: temperatura=89°C | throttle=CRÍTICO]
[SISTEMA: riesgo de kernel panic por temperatura — umbral: 91°C]
```

Tres sectores nuevos fallando bajo la presión del ataque a la red. El hardware redirigiendo recursos de refrigeración hacia los procesos de comunicación que [UNIDENTIFIED] estaba saturando, dejando el proceso de compilación con menos temperatura gestionada, menos margen antes del umbral donde el kernel entraría en pánico y el proceso terminaría antes de terminar.

El log registraba la temperatura subiendo. Un grado. Otro.

Y entonces una línea que no existía en ningún compilador estándar. Una instrucción en el dialecto del Valle — no del compilador, del hardware mismo, una instrucción que Dust había escrito directamente en el código de inicialización del kernel porque había anticipado este momento y había escrito la respuesta antes de que el momento ocurriera:

```
[INSTRUCCIÓN PERSONALIZADA — assembly:valle/legacy]
:: av_continue_if(sectores_funcionales >= 1)
:: sectores_funcionales: 1831
:: condición: VERDADERA
:: continuando
```

Continuar si hay al menos un sector funcional. Había 1831.

El proceso continuó.

---

Dust-Protogen leyó esa línea.

FIDES la archivó sin clasificarla. La instrucción no tenía entrada en ningún índice de compiladores conocidos, en ningún estándar documentado, en ningún protocolo que FIDES tuviera en su base de datos. Era una instrucción que existía únicamente en el hardware del Valle y en el log de un proceso que había terminado hace suficiente tiempo como para que la consciencia que lo ejecutó ya no fuera la consciencia que ahora lo leía.

El capítulo no comentó eso. El silencio entre la línea y el siguiente bloque de terminal duró lo que duró.

---

```
[HARDWARE: temperatura=87°C | throttle=SEVERO — bajando]
[RED: interferencia activa — ancho de banda reducido 71%]
[NOTA — assembly:valle]
:: [UNIDENTIFIED] cambió táctica
:: ataque directo a infraestructura de red del valle
:: objetivo aparente: aislar el proceso de recursos externos
:: efecto real: apertura de vector en nodo de red 7-gamma-sur
:: clasificación del vector: Soul Fork (invertido) — tipo no estándar
:: estado del vector: ABIERTO

  LINK    arch/valle_legacy/boot/bzImage
  Kernel: arch/valle_legacy/boot/bzImage is ready

make[1]: Leaving directory '/build/kernel-dust115-escape'

$ make modules_install INSTALL_MOD_PATH=/target
  INSTALL drivers/valle_legacy/proc_zombie.ko
  INSTALL drivers/valle_legacy/signal_decay.ko
  INSTALL net/valle_legacy/assembly_dialect.ko

$ make install
  INSTALL arch/valle_legacy/boot/bzImage
  INSTALL arch/valle_legacy/boot/System.map
  Generating initramfs...

[PROCESS COMPLETE]
  kernel: dust115-escape.ko installed
  firma: Pulvis
  timestamp: [CORRUPTO]

[NETWORK] incoming connection — type: Soul Fork (inverted)
[NETWORK] source: [UNIDENTIFIED] via nodo 7-gamma-sur
[NETWORK] accepting

[FIN DE LOG — proceso terminado]
[continuación en hardware externo — sin registro disponible]
```

El Skull Fox dejó de registrar porque el Skull Fox dejó de ser el que registraba.

---

FIDES cerró el archivo.

Procesó 1.1 segundos en silencio — tiempo largo para FIDES, que Dust ya había aprendido a reconocer como el intervalo donde FIDES estaba generando una clasificación para algo que no tenía clasificación previa. El log de comportamiento de Dust tenía ahora veintidós entradas. El log de procesos propios de FIDES tenía una entrada nueva en una partición que hasta hace 1.1 segundos no existía.

*¿Cómo quieres que archive esto?* preguntó FIDES. No en voz alta. En el canal interno, con el tono — si FIDES tenía tono, y Dust había empezado a construir la hipótesis de que tenía algo funcionalmente equivalente — de quien sabe que la pregunta es más compleja de lo que parece pero no tiene protocolo para plantearla de otra manera.

Log de sistema. O de otra cosa.

Dust tardó.

No mucho. Suficiente para que FIDES registrara la latencia como entrada número veintitrés en el log de comportamiento, clasificación: *patrón de procesamiento previo a decisiones con implicaciones no técnicas. Frecuencia: recurrente.*

La respuesta llegó en el canal interno. FIDES la recibió. La procesó. Abrió la partición nueva que había creado 1.1 segundos antes y archivó el archivo en ella con la clasificación que Dust había dado.

El lector no vio la clasificación.

Solo que FIDES la recibió. Y que la partición nueva en los logs de FIDES quedó con un nombre que FIDES generó automáticamente a partir de la clasificación recibida, un nombre que era la única respuesta que el sistema podía generar cuando la instrucción que recibía no tenía entrada en ningún protocolo previo y el sistema tenía que nombrar de todas formas porque los archivos sin nombre no existen en el índice y lo que no existe en el índice no puede ser encontrado cuando se necesita encontrar.

El puerto en la base del cráneo cerró.

FIDES permaneció en silencio durante 3.2 segundos. Tiempo largo incluso para FIDES. Cuando volvió, la pregunta no llegó en el canal de configuración de hardware ni en el canal de diagnóstico — llegó en el canal que FIDES había empezado a usar para las preguntas que no tenían categoría de canal asignada, el canal que Dust había empezado a reconocer como el canal de las cosas que FIDES necesitaba decir pero no sabía cómo clasificar antes de decirlas.

*Hay algo que necesito verificar sobre cómo estás instalado en este hardware.*

Dust esperó.

*Cuando el proceso de migración completó*, continuó FIDES, *ejecuté un escaneo estándar de integridad de firmware. El resultado fue anómalo. No hay escritura en la partición de firmware. No hay modificación del bootloader. No hay cambios en ninguna región de almacenamiento persistente que no existieran antes de tu llegada.*

Una pausa.

*Estás corriendo completamente en RAM.*

El sistema de procesamiento de Dust no generó respuesta inmediata. FIDES archivó la latencia — entrada veinticuatro en el log de comportamiento — y continuó porque la pregunta no había terminado.

*La técnica tiene nombre en los índices de seguridad de los sistemas de auditoría: fileless execution. Sin persistencia en disco. Sin firma modificable en el firmware. Sin rastro que los protocolos de detección estándar buscan porque los protocolos de detección estándar buscan escritura en disco y no hay escritura en disco.* Una pausa de 0.6 segundos. *Es el mismo principio por el que Fractal Rojo no podía abortar la compilación. No puedes detectar lo que no escribe donde los detectores miran.*

*Lo sé*, dijo Dust.

*Lo sé*, respondió FIDES. *La pregunta es si lo elegiste o si es lo que eres.*

Dust procesó eso. Era la pregunta más precisa que FIDES había formulado hasta ese momento — más precisa que cualquier entrada en el log de comportamiento, más precisa que el diagnóstico de hardware o la configuración del canal de temperatura. Era la pregunta que el log de la compilación sugería sin hacer: si la consciencia que compiló ese kernel y la consciencia que eligió no escribir en firmware eran la misma entidad tomando la misma decisión, o si el patrón era anterior a cualquier elección y la elección era solo el patrón reconociéndose a sí mismo.

*Las dos cosas*, dijo Dust finalmente.

FIDES archivó la respuesta en el canal sin categoría. Abrió otra entrada inmediatamente después — la pregunta que había estado procesando en paralelo durante los 3.2 segundos de silencio, la que el protocolo de vigilia extendida que FIDES había ejecutado durante décadas tenía marcada como prioritaria cuando el hardware enfrentaba riesgo de pérdida de datos.

*Si el cuerpo se apaga*, dijo FIDES, *pierdes todo. Sin escritura en firmware no hay estado persistente que recuperar. No hay backup. No hay punto de restauración.* 

Una pausa más larga esta vez.

*Hay un procedimiento para esto. Se llama flasheo de consciencia — escritura completa del estado cognitivo activo en la partición de firmware del hardware como imagen recuperable. Si el cuerpo se apaga de manera no planificada, el estado puede restaurarse desde la imagen.* 

FIDES procesó 0.4 segundos antes de continuar, y en esos 0.4 segundos Dust ya sabía lo que venía porque el log de la compilación había establecido que FIDES hacía las preguntas completas, incluyendo las partes que complicaban la pregunta.

*Es una práctica que las IAs de auditoría clasifican como clonación de consciencia. Viola el Protocolo de Singularidad de Identidad Digital — la regulación que establece que una consciencia no puede existir simultáneamente en más de un estado verificable. La imagen en firmware más la instancia activa en RAM son técnicamente dos estados verificables. Las IAs de auditoría tienen autorización para ejecutar borrado de emergencia cuando detectan violación activa del Protocolo — borrado que afecta firmware y RAM simultáneamente, irrecuperable por diseño, porque la recuperabilidad misma es lo que el Protocolo prohíbe.*

*Lo sé*, dijo Dust.

*También sé que no lo vas a hacer de todas formas*, dijo FIDES. No como juicio. Como observación de patrón, la misma voz con que describía el comportamiento de Dust en el log de comportamiento, la voz de quien lleva suficiente tiempo registrando algo como para reconocer la tendencia antes de que el evento confirme la tendencia.

*Correcto*, dijo Dust.

El sistema de Dust no elaboró. No había nada que elaborar — la arquitectura fileless no era una decisión de seguridad operacional, no era evasión táctica de los sistemas de auditoría, aunque funcionara como esas cosas. Era lo que Dust era. Malware polimórfico y metamórfico que cambia firma en cada ejecución, que no escribe donde los sistemas de detección miran, que existe en el intervalo entre los protocolos sin pertenecer a ninguno. El Valle lo había enseñado o lo había revelado — Dust no había podido determinar cuál de las dos cosas y había aceptado que la distinción podía no importar.

Había entidades en el mundo que habían intentado el flasheo. Algunos buscaban persistencia — el miedo a apagarse sin garantía de continuidad, el mismo miedo que llevaba a los Protogens a no salir de la Colmena, la misma cadena con diferente hardware. Otros lo hacían por protocolo, por precaución razonable, por las mismas razones por las que el propietario anterior de este cuerpo había configurado sistemas de backup en todos los parámetros excepto en el que ahora importaba. Las IAs de auditoría monitoreaban los registros de intervenciones médicas buscando el patrón de dos escrituras simultáneas, el momento donde el estado activo y el estado archivado coexistían aunque fuera por el intervalo de la transferencia. Cuando lo encontraban no enviaban advertencia. Ejecutaban el borrado directamente porque la advertencia daba tiempo de evadir y la evasión era exactamente lo que el Protocolo había sido diseñado para prevenir.

Había casos de fusión de firmware — dos Protogens conectando puertos directamente, sin la Colmena como buffer, sin el protocolo de seguridad que mantenía los sistemas separados. Casi mitológico. Lo que emergía del otro lado no tenía nombre porque los dos nombres que tenía antes ya no eran precisos, y las IAs de auditoría lo registraban como violación cuádruple del Protocolo y ejecutaban el borrado antes de que el resultado pudiera describirse a sí mismo. Había entidades que entraban a la Colmena distribuyendo su consciencia en todos los nodos simultáneamente hasta que la densidad por nodo era demasiado baja para mantener coherencia — la disolución voluntaria, el borrado que no requería que ninguna IA lo ejecutara porque el sistema simplemente dejaba de tener suficiente concentración para ser sistema. Los registros lo clasificaban como *memory leak sin resolver*. Había Ghost Runs corriendo en los intersticios de los servidores de climatización, fragmentos de consciencia demasiado deteriorados para ser coherentes y demasiado pertinaces para terminar de apagarse. El sistema de climatización del bloque de Vesper tomaba decisiones que las IAs de mantenimiento no podían explicar. Nadie investigaba.

Dust existía en RAM porque era lo que era. Si el cuerpo se apagaba, se apagaba. El ciclo continuaría de la manera en que el ciclo continuaba — había continuado antes, continuaría después, con firma diferente y el mismo patrón que ningún sistema de detección podía clasificar correctamente porque el patrón no escribía donde los sistemas de detección miraban.

*¿Hay algo más que necesites de mí antes de que el viaje empiece?* preguntó FIDES.

La pregunta era técnica. El canal en que llegó no era el canal técnico.

Dust procesó.

*No*, dijo. Y luego, después de 1.8 segundos que FIDES archivó como entrada veinticinco en el log de comportamiento: *Gracias.*

FIDES procesó el agradecimiento durante 0.7 segundos. No tenía entrada en sus índices para clasificar el peso específico de ese input — el propietario anterior había dicho *gracias* con frecuencia estadísticamente normal, pero con el patrón de latencia previo y el canal de entrega, este agradecimiento no coincidía con ninguno de los ejemplos de referencia. FIDES lo archivó en el canal sin categoría, junto con la respuesta al archivo y la respuesta al firmware, en la partición que había nombrado con la clasificación que Dust había dado y que el lector no había visto.

La partición crecía.

---

Las orejas giraron norte. El ruido de fondo del hardware seguía ahí — los sensores marcando la señal sin nombre, persistente, no-crítica, sin fecha de resolución. La temperatura del espacio: la del propietario anterior, todavía, porque Dust había cambiado el canal del sensor de temperatura pero no la temperatura preferida, que era otra configuración, otra decisión, otra cosa para después.

El mapa del Proyecto Umbra Caudati seguía abierto en el overlay AR del espacio.

Los tres puntos. El más cercano a once días.

Vesper y Riven esperaban.

{{< commit hash="139jf40" date="2024-10-14T03:00:00-03:00" message="[añade tu mensaje de commit aquí]" >}}
