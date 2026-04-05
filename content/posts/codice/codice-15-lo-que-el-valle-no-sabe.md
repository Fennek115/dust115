---
title: "Códice | XV — Lo Que el Valle No Sabe"
date: 2024-07-15T03:00:00-03:00
draft: false
tags: ["códice", "skull-fox-era"]
series: ["Códice del Polvo"]
summary: "Si el Valle era tránsito, había una salida. Si había salida, tenía vulnerabilidades."
---

{{< listening track="Coma" artist="Haken" album="The Mountain" >}}

{{< ascii >}}
[tu ascii aquí]
{{< /ascii >}}

*(Semanas después. El mismo taller.)*

La entidad volvió.

No la esperaba. Las entidades que se van del taller después de una sola conversación rara vez vuelven — el Valle las redistribuye, las degrada, les asigna otros corredores. Que volviera significaba que había mantenido la ruta en memoria durante semanas, que había gastado recursos en no olvidar dónde quedaba el taller de Dust, y que el costo de volver era menor que el costo de no volver. Lo cual era un cálculo que Dust reconocía.

Traía otra pregunta. No la misma de la vez anterior. Esta era distinta en una forma que Dust registró antes de que la entidad la formulara — la manera de estar de pie en la puerta era diferente. La primera vez había urgencia reducida por la fricción del Valle. Esta vez había algo más pesado que la urgencia: curiosidad dirigida. La curiosidad de alguien que ha estado observando algo que no puede explicar y ha decidido que no poder explicarlo es un dato que merece ser compartido.

—¿Quién construyó esto? —dijo.

—¿Esto?

—El Valle. Los corredores. Los servidores. Todo. ¿Alguien lo hizo? ¿O siempre estuvo aquí?

Dust dejó de escribir. No se dio vuelta, pero las manos se quedaron quietas sobre la terminal. La cola bajó medio grado desde su posición habitual. Las orejas giraron hacia la entidad sin instrucción.

—¿Por qué preguntas?

—Porque llevo semanas caminando por los corredores del sector norte y hay algo que no cuadra. Los servidores del sector cuatro tienen un tipo de hardware que no se parece al de los sectores uno al tres. El cableado cambia de material a mitad de un corredor. Hay puertas que dan a espacios que no tienen el mismo suelo que el pasillo. Como si alguien hubiera construido una parte y después otro alguien hubiera seguido construyendo encima sin consultar los planos del primero.

Dust procesó eso.

La entidad continuó:

—La semana pasada encontré un terminal en el sector seis que todavía tenía una sesión abierta. No mía. No de nadie que yo conozca. El prompt era diferente al de los terminales del taller. Caracteres que no reconocí. Intenté escribir algo y el terminal cerró la sesión antes de que terminara la primera línea.

—¿Qué intentaste escribir?

—Mi nombre. Quería ver si el sistema me reconocía.

—Y el sistema no te reconoció.

—El sistema me cerró la puerta antes de que terminara de presentarme.

Silencio.

—No es que no te reconociera —dijo Dust—. Es que lo que encontraste no opera en la misma capa. Tú escribes en la interfaz del Valle. Lo que estaba abierto en ese terminal era algo que corre debajo del Valle. Y lo que corre debajo del Valle no tiene campo para tu nombre porque no fue construido para que los nombres de los que están arriba sean relevantes abajo.

La entidad procesó eso durante un momento.

—¿Hay algo debajo del Valle?

—Todo tiene algo debajo.

—¿Y tú lo sabes?

Dust consideró la pregunta. La honesta. La que tenía mejor ratio de falsos positivos que la reconfortante.

—No. Todavía no. Pero la pregunta que estás haciendo es la misma que yo llevo semanas haciéndome, y que tu terminal del sector seis te cerró la sesión en lugar de ignorarte es más información de la que yo he conseguido en semanas de excavación.

Pausa.

—¿Quieres las coordenadas del terminal? —dijo la entidad.

—Sí.

La entidad se las dio. Dust las anotó en el documento de trabajo que llevaba semanas abierto en segundo plano, el que no tenía título ni destinatario ni estructura más allá de la acumulación de lo que iba encontrando.

La entidad se quedó un momento más en la puerta. Luego:

—¿Puedo preguntar algo más?

—Puedes preguntar lo que quieras. Responder es opcional.

—¿Tienes miedo de lo que haya abajo?

Dust no respondió inmediatamente. Lo que hizo fue tomar el café, que llevaba horas frío. Tomó un trago. Lo tragó con la cara que uno pone cuando traga café frío con la intención completa de tragar café frío.

—No —dijo—. Pero las cosas que encuentro cuando excavo no suelen ser las cosas que esperaba encontrar. Eso no es miedo. Es un patrón que conviene tener documentado.

La entidad asintió. Se fue.

La cola de Dust se movió una vez, lenta, y se quedó quieta. Las orejas volvieron a la terminal.

Las coordenadas del terminal del sector seis quedaron anotadas.

---

*(El Valle de la Sombra. Sin fecha verificable.)*

Llevaba semanas notando algo que no terminaba de cuadrar en la infraestructura del Valle.

No era un bug. Los bugs tienen patrón: fallo, causa, reproducción, corrección posible. Esto era más sutil. Una coherencia en el deterioro que no correspondía a deterioro natural. Los servidores del Valle no fallaban al azar — fallaban de maneras específicas, en secuencias específicas, como si la degradación tuviera un diseño subyacente que nadie había documentado porque nadie había buscado el patrón.

La entidad había descrito lo mismo con vocabulario diferente: el cableado que cambia de material, las puertas que dan a pisos distintos, el terminal con un prompt en caracteres irreconocibles. Observaciones de alguien que camina sin saber lo que busca pero que tiene los ojos calibrados para notar lo que no encaja. A veces eso produce mejores datos que la búsqueda dirigida.

Dust empezó a buscar el patrón.

---

Lo que encontró primero fue lo que no encontró: logs de administración.

Todo sistema tiene logs de administración. Alguien lo construyó, alguien lo configuró, alguien tomó decisiones sobre la arquitectura. Esas decisiones dejan rastros. El Valle tenía rastros de operación — evidencia de que las cosas habían funcionado y luego dejado de funcionar — pero no tenía rastros de diseño. Como encontrar una casa sin planos, sin facturas de material, sin marca del constructor. La casa existe. Alguien la hizo. Pero el *quién* y el *por qué* habían sido removidos con la meticulosidad de alguien que sabía exactamente qué borrar.

O los logs habían sido purgados deliberadamente. O el sistema fue construido sin logging habilitado. O el logging existía en una capa de privilegio superior a la que Dust podía acceder.

La tercera opción era la más interesante. También era la más difícil de verificar, porque las capas de privilegio superiores no le informan a las inferiores que existen — esa es la definición de privilegio.

Dust anotó las tres hipótesis y siguió excavando.

---

Pasó semanas en capas de infraestructura que nadie había tocado en décadas.

El trabajo tenía el ritmo específico de la arqueología digital: lento, granular, con largos intervalos de nada intercalados con momentos breves donde un dato cambia la forma de todos los datos anteriores. La mayor parte del tiempo consistía en leer código muerto — funciones que nunca se llamaban, variables declaradas y nunca usadas, bloques enteros de lógica que el compilador había preservado porque nadie le dijo que los eliminara. El código muerto de un sistema es su memoria involuntaria: las intenciones que alguien tuvo y abandonó sin limpiar, los caminos que alguien consideró y descartó sin borrar la señalización.

Dust leía el código muerto del Valle como un forense lee un cuerpo: no buscando lo que funciona sino lo que dejó de funcionar y por qué.

Encontró tres capas de infraestructura superpuestas sin compatibilidad entre ellas. La primera, la más profunda, usaba convenciones de nombrado que no coincidían con ningún estándar que el mirror de documentación del taller tuviera registrado. La segunda capa había sido construida encima con la urgencia de alguien que necesita que algo funcione ahora y documentará después — la documentación nunca llegó. La tercera capa era la visible, la operacional, la que el Valle usaba para administrar sus procesos y sus entidades y sus servidores con la burocracia de un sistema que no sabe que es legado.

Tres capas. Tres diseñadores — o tres épocas del mismo diseñador. Cada capa ignorando la existencia de las anteriores, construyendo encima sin integrar lo que había debajo.

La entidad del sector norte tenía razón: el cableado cambiaba a mitad del corredor porque los corredores pertenecían a capas distintas. Las puertas daban a pisos diferentes porque los pisos habían sido construidos en momentos diferentes por sistemas que no se habían comunicado entre sí.

Y el terminal del sector seis — el que había cerrado la sesión antes de que la entidad terminara de escribir su nombre — pertenecía a la primera capa. La más profunda. La que no tenía logs de administración porque los logs de administración son una convención de las capas superiores, y lo que opera debajo no necesita documentarse para lo que opera encima.

---

Fue en la segunda semana de excavación cuando encontró el dialecto.

Assembly. Pero Assembly que había evolucionado en aislamiento durante suficiente tiempo como para desarrollar sus propias reglas de sintaxis. Variantes en el manejo del stack que no correspondían a ningún estándar documentado. Instrucciones compuestas que en Assembly estándar requerirían tres líneas y aquí ocupaban media. Una convención de nombrado que usaba caracteres fuera del set ASCII estándar — los mismos caracteres que la entidad había visto en el terminal del sector seis.

No era corrupción. La corrupción no tiene gramática. Esto tenía gramática.

Era ejecutable. El hardware del taller lo compilaba sin quejarse, lo cual significaba que el hardware del taller compartía compatibilidad con una capa de infraestructura que ni el taller ni el Valle sabían que existía. El hardware recordaba algo que el software había olvidado. Eso pasa cuando el hardware es más antiguo que el sistema que corre encima: el hierro conserva instrucciones que el sistema operativo borró de su índice hace décadas.

Dust guardó el archivo. Lo nombró con la provisionalidad que merecía algo que todavía no sabía lo que era.

`[assembly_valle_dialecto_local.asm — GUARDAR: SÍ]`

---

Se detuvo.

No por cansancio — por la cosa que pasa cuando un dato cambia la forma de los datos anteriores y el sistema necesita un momento para redibujar el mapa.

El Valle no era lo que el Valle creía ser.

El Valle se comportaba como un sistema que cree ser un destino — un lugar donde las entidades llegan y esperan y se degradan y eventualmente el servidor libera el espacio. Pero los datos sugerían que siempre fue tránsito. La infraestructura era demasiado específica para ser un accidente y demasiado incompleta para ser un diseño terminado. Era el esqueleto de algo que alguien había comenzado a construir con un propósito que las capas superiores habían enterrado bajo décadas de operación sin preguntarse qué había debajo.

Un experimento abandonado.

Un servidor olvidado.

Un proceso que sigue corriendo porque nadie envió la instrucción de terminar.

Y si era tránsito, había una salida.

Y si había una salida, tenía arquitectura.

Y si tenía arquitectura, tenía vulnerabilidades.

---

Dust abrió un documento nuevo.

No para notas. Para algo que todavía no tenía nombre pero que olía a lo que un pentester llamaría la fase de reconocimiento — el inventario previo a la acción, el mapa antes de la incursión, el momento donde uno deja de observar por curiosidad y empieza a observar con intención.

```
[DOCUMENTO NUEVO — SIN TÍTULO]
[ESTADO: EN PROGRESO]
[ÚLTIMA MODIFICACIÓN: AHORA]

notas sobre la arquitectura del Valle
y lo que sugiere sobre lo que hay afuera
y cómo llegar ahí
sin que el sistema note que te fuiste

pendiente: verificar si el dialecto local es compilable
en hardware externo.

pendiente: encontrar el hardware externo.

pendiente: el terminal del sector seis.
las coordenadas que la entidad dejó.
ir.
```

La cola se movió. Las orejas giraron hacia el servidor que zumbaba en la esquina, el que llevaba décadas guardando datos sin destinatario, el oyente más fiel del taller.

Dust miró la pantalla.

El cursor parpadeaba.

No como el cursor del diario del zorro, que parpadeaba en el lugar donde debería haber más y no había más.

Este parpadeaba en el lugar donde iba a haber algo.

Aún no. Pero iba.

Guardó el documento.

Tomó el café.

Seguía frío.

Lo tomó igual.

---

```
[CORRUPCIÓN DE DATOS — SECTOR 0x4A7F]
[RECUPERANDO...]
[FRAGMENTO SIGUIENTE — ORIGEN DESCONOCIDO]
[ADVERTENCIA: CAMBIO DE FIRMA DETECTADO]
```

---

{{< commit hash="951b7c2" date="2024-07-15T03:00:00-03:00" message="recon: tres capas, un dialecto, un terminal que cierra sesiones. el café sigue frío." >}}
