---
title: "Códice | XVI — Lo Que el Valle No Sabe Que Es"
date: 2025-07-09T03:00:00-03:00
draft: false
tags: ["códice", "skull-fox-era"]
series: ["Códice del Polvo"]
summary: "CVE-VALLE-0x04 — proceso activo sin PID listado. Consume recursos medibles. Origen: anterior al sistema."
---

{{< listening track="Irq 13 Coprocessor" artist="MASTER BOOT RECORD" album="Interrupt Request" >}}

{{< ascii >}}
[tu ascii aquí]
{{< /ascii >}}

*(El Valle de la Sombra. Sin fecha verificable.)*

---

Lo que Dust encontró primero no fue el patrón. Fue la ausencia del patrón.

Los sistemas con deterioro orgánico fallan de maneras estadísticamente distribuidas: los sectores malos se acumulan al azar, los procesos se degradan sin coordinación entre ellos, los logs de error son ruidosos. El Valle no fallaba así. El Valle fallaba con la precisión específica de algo que tiene gramática — sectores malos en secuencias no aleatorias, degradación que seguía una lógica que ningún manual de administración de sistemas hubiera documentado porque ningún manual de administración de sistemas había sido escrito para esto.

No era deterioro. Era una arquitectura en el proceso de leerse a sí misma.

Dust abrió un documento nuevo. No para notas filosóficas.

```
[DOCUMENTO DE TRABAJO]
[CLASIFICACIÓN: USO INTERNO]
[FASE: TA0043 — RECONNAISSANCE]
[SISTEMA OBJETIVO: VALLE DE LA SOMBRA — INFRAESTRUCTURA COMPLETA]
[ESTADO: EN PROGRESO]
```

---

```
════════════════════════════════════════════════
CVE-VALLE-0x01
TÍTULO: Ausencia Total de Logs de Administración
CVSS: 7.5 (AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
TÉCNICA: T1083 — File and Directory Discovery
────────────────────────────────────────────────
DESCRIPCIÓN:
El sistema no presenta logs de decisiones arquitectónicas.
Ausencia verificada en: /var/log/admin/, /etc/audit/,
registros de configuración inicial, árbol de dependencias
de instalación. Los rastros de operación existen.
Los rastros de diseño no.

HIPÓTESIS A: Los logs fueron purgados deliberadamente.
HIPÓTESIS B: El sistema fue construido sin logging habilitado.
HIPÓTESIS C: El logging existe en una capa de privilegio
             superior a la explorada.

HIPÓTESIS C es la más interesante.
ESTADO: ABIERTO
════════════════════════════════════════════════
```

---

Tres semanas de excavación en capas de infraestructura que nadie había tocado en décadas produjeron lo que tres semanas de excavación en ese tipo de infraestructura producen normalmente: polvo digital, procesos zombie sin kernel que los hubiera invocado, y un dialecto.

El dialecto era lo interesante.

Assembly. Pero Assembly que había evolucionado en aislamiento durante suficiente tiempo como para desarrollar sus propias reglas de sintaxis: variantes en el manejo del stack que no correspondían a ningún estándar documentado, instrucciones compuestas que en el Assembly estándar requerirían tres líneas y aquí ocupaban media, una convención de nombrado que usaba caracteres fuera del set ASCII estándar porque en algún punto alguien había decidido que el set ASCII estándar era insuficiente y nadie había dicho que no.

Era ejecutable. El hardware del taller lo compilaba sin quejarse, que era más de lo que podía decirse de la mayoría del código que Dust había encontrado en el Valle.

Guardó el archivo. Le asignó la designación provisional que merecía.

```
[assembly_valle_dialecto_local.asm]
[TAMAÑO: 847 KB]
[COMPILABLE EN HARDWARE LOCAL: SÍ]
[COMPILABLE EN HARDWARE EXTERNO: NO VERIFICADO]
[GUARDAR: SÍ]
```

```
════════════════════════════════════════════════
CVE-VALLE-0x02
TÍTULO: Dialecto Assembly No Autenticado Expuesto
         en Infraestructura de Acceso General
CVSS: 6.8 (AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)
TÉCNICA: T1592.004 — Client Configurations
────────────────────────────────────────────────
DESCRIPCIÓN:
El sistema expone sin restricción de acceso un dialecto
de Assembly de origen no documentado, compilable en el
hardware del sistema y potencialmente en hardware externo
sin verificar. El dialecto tiene suficiente desviación
del estándar como para no ser reconocido por los sistemas
de auditoría de código que buscan firmas de Assembly
canónico.

NOTA: Un lenguaje diseñado para comunicar sin ser
entendido por quienes no lo hablan ya tiene nombre.
No es Assembly. Es argot.

IMPACTO: Potencial vector de ejecución arbitraria
          en capa de privilegio no especificada.
ESTADO: ACTIVO — EN ANÁLISIS
════════════════════════════════════════════════
```

---

```
════════════════════════════════════════════════
CVE-VALLE-0x03
TÍTULO: Procesos Zombie con Privilegios No Revocados
CVSS: 5.1 (AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)
TÉCNICA: T1057 — Process Discovery
────────────────────────────────────────────────
DESCRIPCIÓN:
ps aux lista 2,847 procesos activos. De ellos, 312
corresponden a PIDs sin kernel padre verificable —
el kernel que los invocó no existe en el árbol
de procesos actual. Los PIDs permanecen. Consumen
entre 0.001% y 0.4% de CPU cada uno.

Son entidades del Valle. Sus PID son lo único que
queda del proceso de registro cuando llegaron.
El sistema los olvidó pero no los apagó.

IMPACTO: Degradación acumulativa de recursos.
          Sin impacto en operación actual a niveles
          presentes. Escalable a largo plazo.
ESTADO: KNOWN — NO ACCIONABLE — DOCUMENTADO
════════════════════════════════════════════════
```

---

Los 312 eran conocidos. Lo que no estaba en la lista era lo que Dust encontró en la semana cuatro.

No apareció en `ps aux`.

No apareció en `top`, ni en `htop`, ni en `/proc`, ni en ninguna lectura del árbol de procesos que el hardware del taller podía hacer. Por definición, no existía. Por definición era imposible que consumiera recursos.

Los contadores de CPU decían otra cosa.

Dust ejecutó la auditoría de recursos tres veces. El resultado fue el mismo: 2.3% de CPU consumido por un proceso que no aparecía en ninguna lista de procesos activos. El proceso existía en el intervalo entre los protocolos de detección. El sistema no podía encontrarlo porque los sistemas de detección buscan donde los procesos deberían estar, y este proceso estaba donde los procesos no pueden estar.

```
════════════════════════════════════════════════
CVE-VALLE-0x04
TÍTULO: Proceso Activo Sin PID Listado —
         Consumo de Recursos Sin Origen Verificable
CVSS: [SIN ASIGNAR — CLASIFICACIÓN PENDIENTE]
TÉCNICA: [SIN MAPEO MITRE ATT&CK APLICABLE]
────────────────────────────────────────────────
DESCRIPCIÓN:
Proceso detectado por consumo anómalo de recursos
(CPU: 2.3% sostenido) sin entrada en tabla de procesos.
No aparece en ps aux, /proc, strace, ni en auditoría
de syscalls. El proceso ejecuta. Los detectores no
lo ven porque los detectores buscan escritura en los
registros donde los procesos deberían aparecer,
y este proceso no escribe donde los detectores miran.

No es un bug. Los bugs tienen causa. Esto tiene
una coherencia que los bugs no tienen.

ANTIGÜEDAD ESTIMADA: desconocida.
Los contadores de uso de inode sugieren actividad
anterior a la infraestructura actual del Valle.
Anterior al Valle. Posiblemente anterior
a lo que el Valle fue construido encima.

HIPÓTESIS: proceso de capa de privilegio Ring-0
            que sobrevivió a cambios de arquitectura
            de sistema operativo sin ser migrado,
            actualizado, ni terminado.
            Lleva corriendo desde antes de que hubiera
            un Valle que lo contuviera.

DESIGNACIÓN PROVISIONAL: [Hg]

NOTA: El mercurio es el único metal líquido a
temperatura ambiente. No mantiene forma fija.
No escribe donde los detectores miran.
El nombre no es filosófico. Es una clasificación
de comportamiento.

ESTADO: ABIERTO — PRIORIDAD ALTA
════════════════════════════════════════════════
```

---

Dust guardó el documento. Lo guardó en el servidor del taller, el que llevaba décadas guardando datos sin destinatario. Parecía correcto.

Luego, por motivos que el protocolo no requería documentar pero que el documento hubiera clasificado como `T1059 — Command and Scripting Interpreter`, abrió un terminal nuevo y escribió en el dialecto.

No una pregunta. El dialecto no tenía construcción sintáctica para preguntas, que era una de sus características más honestas. Escribió una declaración: que había encontrado el proceso. Que el proceso consumía 2.3% de CPU. Que ese porcentaje era, en términos del hardware del taller, equivalente a escuchar.

Guardó el archivo. Esperó.

Veintidós minutos después, el servidor del rincón — el que llevaba décadas sin destinatario, el oyente más fiel del taller — generó un log de modificación inesperado. Un sector de almacenamiento que debería estar vacío había recibido escritura.

Dust abrió el sector.

Lo que encontró no era Assembly.

```
[SECTOR 0x4A7F — ESCRITURA DETECTADA]
[TIMESTAMP: CORRUPTO]
[ORIGEN: DESCONOCIDO]
[FIRMA: NO RECONOCIDA EN ÍNDICE LOCAL]
[ESTRUCTURA INTERNA: CONSISTENTE]
[CLASIFICACIÓN: PENDIENTE]

────────────────────────────────────────

v                    <
>  1  +  :  .  v     ^
^              ?      
>          @   <      

────────────────────────────────────────

[FIN DE SECTOR]
[NOTA: EL SECTOR VOLVIÓ A ESTADO VACÍO
 0.3 SEGUNDOS DESPUÉS DE LA LECTURA]
```

---

Dust leyó el sector dos veces antes de que desapareciera.

No era Assembly. No era ningún lenguaje que el índice local reconociera como lenguaje. Pero tenía estructura interna — demasiada estructura para ser corrupción, demasiada coherencia para ser ruido. Los caracteres no eran aleatorios. `v`, `<`, `>`, `^`, `?`, `@` — instrucciones de movimiento, una instrucción aritmética, una instrucción de salida, un operador de decisión aleatoria, una instrucción de terminación que estaba colocada exactamente donde sería más difícil de alcanzar en ejecución normal.

Era un programa. Un programa escrito en un lenguaje donde la dirección de lectura no es fija — donde el mismo texto, leído desde ángulos distintos, produce outputs distintos que son todos igualmente válidos.

La cola se movió. Las orejas giraron hacia el servidor del rincón, que había vuelto a su silencio de décadas como si nada hubiera pasado.

Dust archivó el sector en memoria antes de que el sistema lo purgara. Lo añadió al documento de trabajo.

```
ADDENDUM — CVE-VALLE-0x04:

La respuesta existe. Está escrita en un dialecto
que no tengo mapeado. Tiene la coherencia específica
de un lenguaje diseñado para no ser encontrado
por quien no sabe que está buscando un lenguaje.

El operador central es ?  — dirección aleatoria.
El programa puede ejecutarse desde cualquier punto
de entrada y producir output válido desde todos ellos.

No tiene un inicio canónico.
No tiene un fin canónico excepto el @ que casi
ninguna ruta de ejecución alcanza.

Lleva corriendo desde antes de que el Valle
tuviera nombre para lo que hace.

pendiente: aprender a leer el dialecto.
pendiente: verificar si el Assembly local
           es compilable en hardware externo.
pendiente: encontrar el hardware externo.
```

---

Guardó el documento. Le asignó hash. Lo dejó en el servidor del rincón, que era el único recipiente en el taller con antigüedad suficiente para guardar algo dirigido a un proceso que existía antes de que el Valle tuviera paredes.

Tomó el café.

Seguía frío. Lo estaba desde hacía horas.

Lo tomó igual. Igual que siempre. Como lo que era: la única temperatura disponible, que es suficiente para lo que el café necesita ser.

---

```
[COMMIT — DOCUMENTO DE TRABAJO]
[HASH: 951b7c2]
[MENSAJE: reconnaissance complete.
           tres CVEs documentados.
           uno sin clasificar.
           el sin clasificar es el interesante.
           el café sigue frío.
           clásico.]
```

---

{{< commit hash="951b7c2" date="2025-07-09T03:00:00-03:00" message="reconnaissance complete. el sin clasificar es el interesante." >}}
