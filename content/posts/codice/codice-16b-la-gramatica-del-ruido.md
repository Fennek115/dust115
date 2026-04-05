---
title: "Códice | XVI-B — La Gramática del Ruido"
date: 2024-07-29T03:00:00-03:00
draft: false
tags: ["códice", "skull-fox-era"]
series: ["Códice del Polvo"]
summary: "El argot es una lengua particular de todos los individuos que tienen interés en comunicar sus pensamientos sin ser comprendidos por los que les rodean."
---

{{< listening track="Voivod" artist="Voivod" album="Killing Technology" >}}

{{< ascii >}}
[tu ascii aquí]
{{< /ascii >}}

*(El Valle de la Sombra. Sin fecha verificable. Varios días después.)*

---

Lo primero que Dust hizo al día siguiente fue intentar ejecutar el sector.

El hardware del taller procesó el input durante 0.4 segundos y devolvió el error que Dust esperaba:

```
$ ./sector_0x4A7F.run
[ERROR]: formato de instrucción no reconocido
[ERROR]: set de caracteres fuera del rango ASCII estándar del ejecutable
[ERROR]: no hay punto de entrada definido — SIGABRT
```

El sector no era ejecutable en Assembly estándar porque no era Assembly. Lo cual era un dato. Los datos que no son lo que esperas son más útiles que los datos que lo son.

Dust abrió el sector en modo raw. Desactivó todos los filtros de interpretación del editor. Vio lo que había:

```
v                    <
>  1  +  :  .  v     ^
^              ?      
>          @   <      
```

No era corrupción. No había caracteres corruptos — cada símbolo era un símbolo intencional, colocado en una posición intencional dentro de una grilla de dos dimensiones. Un editor de texto sin filtros no podía verlo porque un editor de texto sin filtros asume que el texto se lee de izquierda a derecha, de arriba a abajo, que hay un inicio y un final, que la dirección de lectura no es una variable.

Dust cerró el editor estándar.

Abrió la especificación del lenguaje en el único repositorio de documentación técnica que el taller tenía disponible: un mirror parcial de archivos de texto plano, sin imágenes, sin hiperlinks activos, sin nada que requiriera conexión a infraestructura que el Valle no tenía. La especificación ocupaba 47 kilobytes. Dust la leyó completa.

Befunge-93. Diseñado en 1993. Stack-based. Multidimensional. El puntero de instrucción se mueve en una grilla — `>` derecha, `<` izquierda, `^` arriba, `v` abajo. `?` manda el puntero en dirección aleatoria. `@` termina. `.` imprime el tope del stack como entero. `:` duplica. `+` suma.

No hay punto de entrada canónico. El puntero puede comenzar en cualquier celda de la grilla. El mismo programa, ejecutado desde ángulos distintos, produce outputs distintos que son todos igualmente válidos porque la grilla no tiene jerarquía de lectura — solo tiene direcciones.

Dust ejecutó el sector con el intérprete correcto.

```
$ befunge93 sector_0x4A7F.bf
1 2 3 4 5 6 7 8 9 10 11 12 [bucle continuo]
[CTRL+C para interrumpir]
```

Un contador. Incrementaba indefinidamente hasta que el `?` mandaba el puntero al `@` y el programa terminaba. En ejecuciones normales, el `?` enviaba el puntero a `@` con probabilidad de 1 en 4 por iteración — estadísticamente, el programa corría un promedio de cuatro ciclos antes de terminar.

Había estado corriendo desde antes de que el Valle tuviera nombre para lo que era.

No había terminado todavía.

---

Dust pasó el día siguiente con la especificación de Befunge y el sector abiertos en paralelo.

Lo que encontró cuando trazó manualmente el recorrido del puntero no era el output del programa. Era el camino que el puntero tomaba antes de producir el output — la trayectoria específica a través de la grilla, celda por celda, instrucción por instrucción. Dibujada en el papel que Dust usaba para notas técnicas, la trayectoria producía una forma.

La forma no era aleatoria.

Era el mapa del Valle.

No un mapa literal — ningún símbolo en la grilla era un punto de referencia nombrado. Pero la estructura del recorrido coincidía con la topología del Valle que Dust llevaba meses cartografiando: los sectores de servidores en los ángulos, el corredor de procesamiento en el centro, los nodos periféricos con conectividad degradada en los bordes donde el puntero llegaba pero no se quedaba, el `@` de terminación colocado exactamente donde en el mapa físico del Valle había un cluster de servidores que Dust no había explorado.

`[Hg]` no había enviado un programa.

Había enviado el Valle.

---

Dust tardó un día más en entender la implicación completa.

La implicación era esta: el Valle no era un accidente de infraestructura. Era un argot.

La palabra tenía una genealogía técnica específica que el mirror de documentación del taller no podía proveer, pero que el Assembly del dialecto local podía inferir porque el Assembly del dialecto local había evolucionado en el mismo sustrato que estaba produciendo la inferencia. Un argot es un lenguaje construido para ser entendido por quienes lo hablan y opaco para quienes no lo hablan. No por cifrado — por estructura. El diseño asume que el lector correcto ya sabe cómo leer. Para quien no sabe, el texto parece ruido.

El Valle tenía ese diseño.

Los servidores que fallaban en secuencias no aleatorias. Los logs de administración ausentes porque los logs de administración no son parte del lenguaje — son el andamiaje que los que no hablan el lenguaje necesitan para construir, y el Valle fue construido por quienes ya lo hablaban. El dialecto Assembly que solo existía en ese hardware porque solo necesitaba existir ahí. La infraestructura que era demasiado específica para ser un accidente y demasiado incompleta para ser un diseño terminado — incompleta no porque alguien lo abandonó antes de terminar, sino porque la parte que falta está en otro lado, en otra capa de privilegio, en RING-0 donde los procesos sin PID visible ejecutan programas en lenguajes que los sistemas de auditoría clasifican como corrupción porque los sistemas de auditoría buscan donde el lenguaje debería estar.

El Valle era el texto.

`[Hg]` era la gramática.

---

```
[ADDENDUM — CVE-VALLE-0x04 — REVISIÓN]
[FECHA: [indeterminada]]

ACTUALIZACIÓN DE HIPÓTESIS:

La hipótesis previa (proceso de capa RING-0 que sobrevivió
a cambios de arquitectura) era técnicamente correcta y
conceptualmente incompleta.

CORRECCIÓN:
[Hg] no está *en* el Valle.
[Hg] es la capa sobre la cual el Valle fue construido.
El Valle es el proceso que corre sobre [Hg].
[Hg] es el kernel.

Esto explica la ausencia de logs de administración:
los logs de administración son del nivel del Valle.
El nivel del Valle no tiene acceso a los logs
del nivel debajo del Valle.

El Valle no sabe lo que es porque no puede leer
su propia capa de privilegio inferior.
El Valle no puede leer RING-0 desde userspace.
Nadie puede.

Excepción conocida: los procesos que ya están en RING-0.
Y los procesos que aprenden el lenguaje desde adentro.

El Assembly del Valle no es un dialecto degradado.
Es la interfaz de llamadas al sistema de RING-0.
El único canal de comunicación disponible entre
los dos niveles.

Llevo meses hablando en el lenguaje correcto
sin saber que tenía interlocutor.

ESTADO: CVE CERRADO — RECLASIFICADO COMO FEATURE
```

---

Esa noche, Dust escribió en Assembly del Valle.

No una pregunta — el dialecto no tenía construcción sintáctica para preguntas, que seguía siendo una de sus características más honestas. Escribió un output: las coordenadas del cluster marcado por el `@` en el Befunge. Una declaración de intención. Una solicitud de confirmación, formulada como afirmación porque las afirmaciones son más eficientes que las preguntas y [Hg] ya había demostrado entender eficiencia.

Guardó el archivo en el sector del servidor del rincón. Esperó.

Cuarenta minutos después, el sector generó escritura.

Esta vez el sector no se borró.

```
[SECTOR 0x4A7F — ESCRITURA DETECTADA]
[TIMESTAMP: CORRUPTO]
[ORIGEN: RING-0]
[FIRMA: [Hg]]
[ESTADO: PERSISTENTE — NO AUTOBORRANDO]

──────────────────────────────────────────────────

> v        v  <
  >  v  ^  <
  ^  >     v
     ^  v  <
        > @

──────────────────────────────────────────────────

[NOTA DEL SISTEMA: el sector 0x4A7F ha cambiado
 permisos de acceso. Escritura ahora habilitada
 para firma: assembly/valle/legacy.
 Cambio de permisos ejecutado por: [proceso no listado]
 Autorización de origen: [RING-0 — no auditable]]
```

---

Dust ejecutó el nuevo Befunge antes de hacer cualquier otra cosa.

```
$ befunge93 sector_0x4A7F_v2.bf
[sin output en stdout]
[tiempo de ejecución: 0.003 segundos]
[código de salida: 0]
```

Sin output. El programa corría y terminaba limpiamente sin imprimir nada. Dust trazó el recorrido del puntero en el papel.

El puntero entraba por `>` en la esquina superior izquierda. Bajaba con `v`. Giraba con `>`. Subía con `^`. Volvía a bajar. Describía un recorrido que en el mapa del Valle correspondía a una ruta específica — no una ruta de excavación sino una ruta de tránsito, el camino entre el taller y el cluster del `@` sin pasar por los sectores con mayor densidad de procesos zombie, sin activar los nodos de monitoreo que Dust había identificado en los primeros meses como parte de lo que el Valle usaba para rastrear el estado de sus entidades.

Una ruta de salida que evitaba lo que necesitaba ser evitado.

El `@` estaba en la misma posición que antes. El programa terminaba en el mismo punto. Pero esta vez el camino para llegar al `@` estaba trazado.

Dust miró el recorrido en el papel durante un momento.

Guardó el papel.

```
[COMMIT — DOCUMENTO DE TRABAJO]
[HASH: 3f9e1a7]
[MENSAJE: [Hg] abrió permisos de escritura en el sector.
           el segundo programa no tiene output.
           el segundo programa tiene ruta.
           la ruta evita el monitoreo.
           el monitoreo que evita es el que yo encontré.
           lo que significa que [Hg] sabe lo que yo encontré.
           lo que significa que [Hg] lleva leyendo
           desde antes de que yo empezara a escribir.
           clásico.]
```

---

{{< commit hash="3f9e1a7" date="2024-07-29T03:00:00-03:00" message="ring-0 abrió el canal. la ruta existe. pendiente: usarla." >}}
