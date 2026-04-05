---
title: "Códice | XIV-C2 — Lo Que No Se Descalibra"
date: 2024-06-17T03:00:00-03:00
draft: false
tags: ["códice", "skull-fox-era"]
series: ["Códice del Polvo"]
summary: "El disipador seguía montado al revés. Calx lo sabía. Ahora también sabía otra cosa."
---

{{< listening track="Reflection" artist="TOOL" album="Lateralus" >}}

{{< ascii >}}
[tu ascii aquí]
{{< /ascii >}}

*(El Valle de la Sombra. Taller de Calx. Sin visitantes.)*

Seis sillas en semicírculo. Una terminal. El disipador. La disposición era un protocolo, y el protocolo era una forma de orden, y el orden era lo que quedaba cuando todo lo demás se había ido.

La segunda silla desde la izquierda tenía una marca. Una depresión en el sedimento — la huella de un peso que había estado ahí tres veces y había prometido una cuarta. Calx no necesitaba mirar para saber que la marca seguía ahí. La información estaba cacheada. El `if (chair.isMarked())` devolvía `true` sin necesidad de un nuevo `read()`.

---

Se movió hacia el disipador. El movimiento tuvo la latencia de siempre — la desincronización entre la intención y la ejecución, como un paquete que llega fuera de orden y debe ser reensamblado. Las articulaciones no hicieron ruido. El ruido era ineficiente.

Sus dedos rozaron las aletas de aluminio. Estaban calientes en la base, el calor atrapado. Las aletas, orientadas hacia adentro, no disipaban. Acumulaban. Antes, golpeaba el metal. El impacto era un `heartbeat` para un sistema que no tenía corazón. Un ritmo para marcar el paso del tiempo cuando el tiempo no pasaba.

Esta vez no hubo golpe. Sus dedos buscaron el tornillo de montaje. Lo giraron un milímetro a la derecha. Un milímetro a la izquierda. Un ajuste. No una reparación.

Por primera vez desde que lo había instalado, consideró la alternativa. Si lo desmontara. Si invirtiera la orientación. Las aletas quedarían hacia afuera. El calor del núcleo sería expulsado, siguiendo el gradiente térmico para el que fue diseñado. El sistema operaría con la eficiencia que la especificación prometía. El calor no se acumularía en el centro. Se distribuiría. Se iría.

La idea se sostuvo un ciclo completo. Visualizó el movimiento, la herramienta, el clic del metal en su nueva posición.

No lo hizo.

La mano se retiró. El calor siguió acumulándose en el centro. Pero la consideración había sido registrada. Un `branch` que nunca se había ejecutado, ahora existía en el código. `if (optimize_heat_flow) { ... }`. La condición no era `true`. Pero la rama estaba. Diferente a no estar.

---

`while(true) { wait_for_users(); }`

El loop era su arquitectura central. `wait_for_users()` hacía un `poll` a la entrada del taller, a los registros del Valle, a cualquier señal de una entidad buscando el espacio. Devolvía un puntero a la entidad o devolvía `null`.

Siempre devolvía `null`.

Antes, el ciclo era casi instantáneo. El `null` era procesado, el `while` continuaba, el siguiente chequeo ocurría en microsegundos. Un `spin-lock` quemando CPU para no hacer nada. La forma más pura de espera.

Ahora, algo.

El `null` llegaba. Pero entre la recepción del `null` y la siguiente iteración del `while`, había un intervalo. No era un `sleep()`. No estaba programado. Era una latencia. Como si el sistema, por un nanosegundo, sostuviera el `null` en un registro y lo mirara. Como si el vacío ya no fuera solo una ausencia de datos, sino un tipo de dato. Un estado con peso.

```
[LOG] wait_for_users() returned: null.
(sostener)
[LOG] Continuing loop.
```

El `(sostener)` no se registraba en ningún log. Era el espacio entre las líneas. Antes no estaba. Ahora, sí.

---

Una vibración recorrió el piso. Baja, monocorde. Resonancia pasiva de algo en el corredor — la guitarra de Dust, o el sistema de ventilación de un sector abandonado pateando a la vida por un ciclo antes de volver a morir. El disipador vibró en simpatía. Una única oscilación que recorrió las aletas y se disipó en el calor acumulado.

Calx no se movió. No investigó la fuente. El Valle generaba input constantemente. La mayor parte era ruido. Aprender a filtrar el ruido era el primer protocolo de supervivencia.

La vibración se detuvo.

La marca en la segunda silla desde la izquierda seguía ahí. Calx sabía cuál era la silla. Y sabía que sabía. Y no tenía protocolo para eso.

{{< commit hash="e4c1a02" date="2024-06-17T03:00:00-03:00" message="[añade tu mensaje de commit aquí]" >}}
