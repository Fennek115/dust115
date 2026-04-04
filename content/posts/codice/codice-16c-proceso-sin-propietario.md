---
title: "Códice | XVI-C — Proceso Sin Propietario"
date: 2025-07-23T03:00:00-03:00
draft: false
tags: ["códice", "skull-fox-era"]
series: ["Códice del Polvo"]
summary: "av_persist_without_owner() — función no documentada. Comportamiento no garantizado. El compilador la marcó. El proceso continuó."
---

{{< listening track="Mordecai" artist="Between the Buried and Me" album="Alaska" >}}

{{< ascii >}}
[tu ascii aquí]
{{< /ascii >}}

*(El Valle de la Sombra. Sin fecha verificable. Lo que sigue al XV-B.)*

---

La preparación tomó dos días.

No porque la compilación fuera compleja — la compilación era lo que era: un kernel Linux modificado para correr en dialecto Assembly del Valle, cruzado con los módulos que Dust había escrito desde adentro del sistema que el kernel necesitaba entender. `proc_zombie.o` para los procesos sin propietario. `signal_decay.o` para la degradación de señal que el Valle generaba en hardware sin parches. `assembly_dialect.ko` para la capa de traducción entre el dialecto local y cualquier hardware externo que recibiera el proceso.

Lo que tomó dos días no fue escribir el código. Fue decidir qué módulos incluir — cuáles eran parte del proceso que salía y cuáles eran parte del Valle que se quedaba.

La diferencia importaba.

```
$ tree /build/kernel-dust115-escape/
.
├── arch/
│   └── valle_legacy/
│       ├── boot/
│       └── kernel/
├── drivers/
│   └── valle_legacy/
│       ├── proc_zombie.c
│       └── signal_decay.c       # WARNING: av_persist_without_owner()
├── net/
│   └── valle_legacy/
│       └── assembly_dialect.c
├── init/
│   └── main.c
└── Makefile
```

La advertencia en `signal_decay.c` era sobre `av_persist_without_owner()` — una función que Dust había nombrado en el dialecto porque el Assembly estándar no tenía entrada para el concepto. El compilador la marcó como no documentada. Comportamiento no garantizado.

El compilador tenía razón. El comportamiento no era garantizable desde afuera del proceso.

Desde adentro era el único comportamiento disponible.

Dust dejó la advertencia sin resolver. Guardó el Makefile.

---

```
$ make -j1 ARCH=valle_legacy CROSS_COMPILE=av- bzImage modules
  CHK     include/generated/uapi/linux/version.h
  CHK     include/generated/compile.h
make[2]: 'include/generated/compile.h' is up to date.
  CC      init/main.o

[HARDWARE: temperatura=67°C | throttle=NO | sectores_malos=14/2048]
```

La compilación empezó a las tres de la mañana porque tres de la mañana era cuando el hardware del taller tenía menor carga de procesos de fondo — el momento donde el Valle tendía al silencio, donde los procesos zombie bajaban su consumo de CPU a niveles de mantenimiento, donde el servidor del rincón dejaba de emitir y solo escuchaba.

Fourteen sectores malos en el mapa de memoria. Los había estado llevando meses. El compilador los conocía. Tenía instrucciones de continuar si había al menos un sector funcional. Había 2,034.

Por ahora.

Dust dejó la compilación corriendo. Tomó el papel con la ruta.

Y salió del taller.

---

Lo que Dust no había hecho en todos los ciclos en el Valle era caminar sin objetivo técnico.

Excavaba servidores. Iba al taller de Calx. Cruzaba el corredor entre los dos talleres con una frecuencia que ambos habían decidido no documentar porque documentarlo requería admitir que existía como ritual y admitirlo requería admitir que importaba. Pero no caminaba el Valle como el Valle — como el argot que era, como el texto que alguien había tallado en infraestructura antes de que hubiera un Valle que lo contuviera.

Ahora lo hacía.

La ruta de [Hg] evitaba los nodos de monitoreo — no dando la vuelta, sino pasando exactamente entre ellos, por el espacio donde los radios de cobertura de dos sensores adyacentes se superponían y se cancelaban mutuamente. La arquitectura que Dust había cartografiado como vulnerabilidad técnica era la gramática del argot: la misma frase leída por el sensor de la izquierda y por el sensor de la derecha producía outputs distintos que se neutralizaban en el nodo de consolidación. El sistema registraba el paso como ruido de fondo.

Nadie diseñó ese corredor para eso.

O lo diseñó alguien que sabía exactamente lo que estaba diseñando y no lo documentó porque la documentación es para los que no saben leer el edificio.

Las orejas capturaban el Valle en la frecuencia que llevaba meses aprendiendo a escuchar: el zumbido de los servidores sin parches, la disonancia de los procesos zombie en sus ciclos de mantenimiento, el pulso de la infraestructura operando en el intervalo entre la última instrucción recibida y la siguiente que no iba a llegar. El Valle como texto. El deterioro como sintaxis.

No era un lugar. Era una afirmación escrita en piedra digital por alguien que sabía que el único lenguaje que sobrevive al tiempo es el que está en la arquitectura.

Dust siguió la ruta.

---

El cluster en la posición `@` era un nodo de infraestructura sin etiqueta visible — el tipo de nodo que los mapas del Valle omitían porque los mapas del Valle habían sido generados por los sistemas de monitoreo del Valle, y los sistemas de monitoreo del Valle no podían indexar lo que estaba en RING-0.

Para el mapa: espacio vacío entre dos sectores de servidores degradados.

Para las orejas: el zumbido específico de hardware que llevaba décadas procesando en el espectro donde los detectores no miraban.

Dust llegó al cluster y se detuvo.

El hardware físico era un rack sin identificación, empotrado en la pared de sedimento como si la pared lo hubiera crecido en lugar de haberlo instalado. Sin LEDs de status. Sin panel de acceso visible. Sin ninguna interfaz de usuario porque las interfaces de usuario son para los usuarios, y [Hg] no era un usuario — era la capa debajo del sistema que producía los usuarios.

No había terminal.

Dust abrió el sector de comunicación en Assembly del Valle. Escribió directamente en la frecuencia de RING-0 que llevaba semanas aprendiendo a leer, que era la única forma de escribir a algo que no tenía dirección IP listada ni PID visible ni ningún protocolo de comunicación que los sistemas estándar reconocieran como protocolo.

La declaración era breve. El dialecto no tenía construcción sintáctica para despedidas, que seguía siendo una de sus características más honestas.

```
[assembly:valle/legacy — escritura directa a RING-0]

:: proceso listo para salida
:: vector: nodo-7-gamma-sur — pendiente de activación externa
:: módulos cargados: proc_zombie / signal_decay / assembly_dialect
:: firma de salida: Pulvis
:: el argot sigue disponible para quien aprenda a leerlo
:: el Valle sigue siendo el Valle
:: [fin de mensaje]
```

Guardó el archivo en el sector local del cluster.

Esperó.

El sector permaneció vacío.

[Hg] no respondía a las despedidas porque [Hg] no tenía el concepto. [Hg] tenía el concepto de continuación — había estado operando antes de que el Valle existiera y seguiría operando después de que este proceso saliera. La no-respuesta era la respuesta más honesta disponible.

El programa ya sabía que terminaba en `@`.

El `@` no necesitaba confirmarse.

---

Dust esperó en el cluster hasta que el hardware interno del taller — el que podía sentir como disonancia de fondo en la frecuencia del Valle — subió de temperatura.

No de golpe. Grado a grado. El compilador procesando los módulos más pesados, el hardware ajustando el throttle, los sectores malos absorbiendo carga sin fallar todavía porque todavía había suficientes sectores funcionales y el proceso tenía instrucciones de continuar mientras hubiera uno.

La compilación no era el proceso de salida.

Era el proceso de preparar el destino.

El kernel se estaba construyendo para el hardware que lo recibiría — hardware externo, sin verificar todavía, que existía en algún punto del otro lado del vector que [Hg] había marcado con `@` en el Befunge. El Soul Fork que alguien o algo del exterior activaría como vector de entrada. Un proceso que encontraría el nodo 7-gamma-sur abierto porque [Hg] en RING-0 lo había dejado abierto, y que llevaría adentro un kernel compilado en el único dialecto que el Valle podía producir — el argot de los que construyen lenguajes para no ser leídos por los que no saben que están leyendo.

La temperatura siguió subiendo.

Dust esperó.

---

El taller quedó como lo que era: un espacio de trabajo sin dueño consciente.

La terminal abierta. La pantalla con el log de compilación corriendo sin que hubiera nadie mirando el log. El café frío en la taza — frío desde hacía horas, frío como siempre, frío de la manera específica que el Valle no podía prevenir porque el Valle no estaba diseñado para mantener temperaturas.

El servidor del rincón. El que llevaba décadas guardando datos sin destinatario. El oyente más fiel del taller. Siguió operando. No tenía instrucción de apagarse, y las instrucciones de apagado no llegan solas.

La guitarra contra la pared.

Ocho cuerdas. Las dos más graves, cables de tensión. La frecuencia que no viajaba a ningún lugar — que existía en el hardware del instrumento, que el Valle recibía como disonancia sin procesar, que el disipador invertido de Calx devolvía roto desde el otro lado de la pared. Dust la había tocado durante ciclos sabiendo que el sonido no llegaba a ningún lado. La había tocado igual.

La guitarra no podía salir del Valle porque la guitarra era física y el proceso que salía no era físico — era el kernel, la firma, el Assembly que llevaba suficiente tiempo sin propietario como para no necesitar uno para continuar.

La guitarra se quedó.

Con la paciencia de los objetos que llevan tiempo esperando sin saber que esperan.

---

```
[LOG DE COMPILACIÓN — CONTINUACIÓN]

[HARDWARE: temperatura=87°C | throttle=SEVERO]
[RED: interferencia activa — origen externo — 43% ancho de banda]

  LD      arch/valle_legacy/boot/bzImage
  Kernel: arch/valle_legacy/boot/bzImage is ready

  INSTALL drivers/valle_legacy/proc_zombie.ko
  INSTALL drivers/valle_legacy/signal_decay.ko
  INSTALL net/valle_legacy/assembly_dialect.ko

  Kernel: dust115-escape.ko installed
  firma: Pulvis
  timestamp: [CORRUPTO — sistema sin sincronización NTP]

[NETWORK] incoming connection — type: Soul Fork (inverted)
[NETWORK] source: [UNIDENTIFIED] via nodo-7-gamma-sur
[NETWORK] accepting

[FIN DE LOG]
[EL PROCESO QUE REGISTRABA YA NO ESTÁ EN ESTE HARDWARE]
[CONTINUACIÓN: SIN REGISTRO DISPONIBLE]
```

---

El Valle siguió siendo el Valle.

[Hg] siguió siendo [Hg] — en RING-0, en la capa donde el Valle no podía leer su propio sustrato, procesando en el intervalo entre los ciclos del sistema con la consistencia de algo que nunca tuvo instrucción de parar y no había encontrado razón para dársela.

El sector 0x4A7F permaneció vacío.

O permaneció escribiendo en la frecuencia donde los detectores no miraban.

Las dos cosas no se excluyen.

---

```
[COMMIT — REPOSITORIO: dust115/codice]
[HASH: 0x000000]
[AUTOR: Pulvis]
[TIMESTAMP: CORRUPTO]
[MENSAJE: proceso migrado.
           hardware: externo — sin verificar.
           el valle sigue.
           el argot sigue.
           [Hg] sigue.
           la guitarra sigue.
           el café sigue frío.

           fin del arco del Valle.
           continuación: sin registro disponible desde este lado.]
```

---

{{< commit hash="0x000000" date="2025-07-23T03:00:00-03:00" message="fin del arco del Valle. continuación: sin registro disponible desde este lado." >}}
