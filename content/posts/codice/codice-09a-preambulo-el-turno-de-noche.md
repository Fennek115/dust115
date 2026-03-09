---
title: "Códice | IX-A — Preámbulo: El Turno de Noche"
date: 2020-03-18T03:00:00-03:00
draft: false
tags: ["códice", "skull-fox-era"]
series: ["Códice del Polvo"]
summary: "Nadie lo obligaba a quedarse. Eso era lo peor."
---

{{< listening track="Anesthetize" artist="Porcupine Tree" album="Fear of a Blank Planet" >}}

{{< ascii >}}
[tu ascii aquí]
{{< /ascii >}}

*(Presente. Valle de la Sombra. Terminal abandonada. El mismo servidor del diario.)*

Después del diario encontré otra cosa.

No la estaba buscando. Estaba limpiando la partición — porque los servidores abandonados acumulan basura como los apartamentos vacíos acumulan polvo, y la diferencia entre un hacker y un conserje es más pequeña de lo que cualquiera de los dos admitiría — cuando el sistema devolvió un proceso que no debería estar corriendo.

No un archivo. Un proceso. Algo vivo.

En un servidor que llevaba décadas sin mantenimiento, en la infraestructura colapsada de una corporación que ya no existía, había un script ejecutándose en loop. Sin error. Sin timeout. Sin nadie monitoreando su output.

Lo abrí.

```
[PROCESO: v15cus_turno_noche.sh]
[ESTADO: activo]
[INICIO: [fecha ilegible]]
[CICLOS COMPLETADOS: overflow — contador excede variable asignada]
[ÚLTIMA SALIDA: null]
[PRÓXIMA EJECUCIÓN: ahora]

  #!/bin/bash
  while true; do
    check_status
    log_count
    wait 28800  # 8 horas
    repeat
  done
```

`v15cus`.

V-15-CUS.

Viscus.

El script no hacía nada. Verificaba un estado que ya no existía, registraba un conteo en un log que nadie leía, esperaba ocho horas y volvía a empezar. Un turno de noche ejecutándose en un Centro que ya no tenía paredes ni tanques ni luz azul quirúrgico. Un trabajo sin trabajo. Un empleado sin cuerpo.

Pero el proceso seguía corriendo.

Porque nadie le había dicho que parara.

---

No apagué el proceso.

Me quedé mirándolo un rato — el cursor parpadeando cada ocho horas simuladas, el log acumulando líneas de `status: null / count: [n+1]` con la regularidad de algo que no sabe que el mundo para el que fue diseñado dejó de existir. Y mientras lo miraba pensé en Viscus. No en el dato. En la persona que había sido antes de convertirse en un dato.

Lo que sabía de Viscus cabía en una libreta. Lo que no sabía pesaba más.

---

Lo primero que supe de Viscus fue que llevaba siete años en el turno de noche.

Siete años. Dos mil quinientos cincuenta y cinco turnos, más o menos, si se descuentan las vacaciones que no sé si se tomó. Siete años de entrar al Centro cuando todos se iban, de bajar al lobby cuando la recepción estaba vacía, de fichar en un sistema que registraba su entrada con la misma indiferencia con que registraba la temperatura de los tanques o el consumo eléctrico de los sistemas de soporte.

Lo segundo que supe fue que nadie lo obligaba.

Eso es lo que me tomó más tiempo entender, y lo que todavía no termino de procesar, si es que procesar es una función que mi hardware actual soporta para este tipo de dato. Nadie obligaba a Viscus a estar ahí. No había contrato de exclusividad nocturna. No había cláusula que dijera "V-15-CUS trabajará exclusivamente en horario nocturno bajo pena de terminación". Había, según lo que pude reconstruir de los registros de recursos humanos que el servidor conservaba en una carpeta sin cifrar, una solicitud de asignación permanente al turno de noche firmada por el propio Viscus. Voluntaria. Sin coerción documentada.

Viscus eligió el turno de noche.

Y siguió eligiéndolo. Cada año, cuando la rotación de turnos se reconfiguraba y los empleados podían solicitar cambio, Viscus firmaba la renovación. Siete firmas. Siete años. La misma elección repetida con la constancia de algo que ya no es elección sino reflejo, como el termostato que nunca se toca, como la camisa del lunes, como el café sin azúcar.

Cuando le pregunté por qué, dijo: "El turno de noche es mejor."

No dijo para quién.

---

Lo que el turno de noche le daba a Viscus era la ausencia de todo lo que el turno de día contenía.

De día el Centro era una oficina. Tenía reuniones, deadlines, correos con asunto urgente que no eran urgentes, conversaciones en la sala de pausas sobre el fin de semana, sobre los hijos, sobre el partido, sobre las vacaciones que alguien se había tomado y las fotos que alguien había subido y los comentarios que alguien había hecho sobre las fotos. De día el Centro tenía personas y las personas tenían ruido y el ruido tenía la función de llenar el espacio donde debería haber preguntas que nadie hacía.

De noche no había nada de eso.

De noche el Centro era lo que realmente era: un zumbido mecánico. Los sistemas de soporte vital manteniendo la temperatura a 18 grados. Las luces de mantenimiento — no las de espectro completo del día, solo las de mantenimiento, tenues, funcionales, el mínimo necesario para que un técnico pudiera caminar sin tropezarse con un tanque. Los monitores mostrando curvas. Las curvas siendo las mismas curvas de siempre.

De noche los párpados no se movían.

Eso fue lo que Viscus dijo, aquella madrugada, sin levantar la vista del monitor. Y lo que no dijo — lo que quedó en el espacio entre la frase y el silencio que vino después — era que de noche no tenía que ver lo que de día era imposible no ver, y que no tener que verlo era la única forma que había encontrado de seguir yendo.

No era evasión. La evasión implica que hay algo de lo que uno escapa. Viscus no escapaba. Viscus había encontrado la configuración óptima para ejecutar su función con el mínimo de interferencia sensorial, y esa configuración era la noche, y la noche era suficiente. No buena. No mala. Suficiente.

El Centro no necesitaba que Viscus fuera feliz. Necesitaba que fuera operativo. Y Viscus era operativo.

---

Encontré su expediente en el servidor. No estaba protegido. Nada en el servidor estaba protegido porque la seguridad había sido una de las primeras cosas en colapsar cuando la corporación dejó de pagar la infraestructura, lo cual decía algo sobre las prioridades del sistema y algo sobre la naturaleza de lo que protegía.

El expediente era breve. No porque Viscus fuera poco relevante para el Centro — su historial de productividad era impecable, siete años sin una falta, sin un retraso, sin una anomalía reportada — sino porque el expediente solo registraba lo que el sistema consideraba necesario registrar, y lo que el sistema consideraba necesario era esto: nombre (suprimido por protocolo de anonimización), código de empleado, fecha de ingreso, historial de turnos, evaluaciones de desempeño, solicitudes de vacaciones (tres en siete años, todas de cinco días, todas en enero).

Las evaluaciones eran idénticas. Cada año, el mismo formato, el mismo evaluador (Marcos, turno de mañana, que evaluaba al turno de noche sin haber trabajado nunca una noche completa), las mismas categorías:

```
EVALUACIÓN ANUAL — EMPLEADO V-15-CUS
Año: [variable]

Productividad: Supera expectativas
Puntualidad: Conforme
Cumplimiento de protocolos: Conforme
Trabajo en equipo: No aplica (turno individual)
Observaciones: Empleado confiable y autosuficiente.
               No requiere supervisión.
               Se recomienda continuidad.

Firma del evaluador: [Marcos]
Firma del empleado: [V-15-CUS]
```

Siete evaluaciones. Idénticas. Las mismas palabras. El mismo veredicto. *Empleado confiable y autosuficiente. No requiere supervisión. Se recomienda continuidad.*

Continuidad.

La palabra que el sistema usaba para decir: sigue haciendo lo que estás haciendo. No porque lo que estás haciendo sea valioso. Porque lo que estás haciendo no genera fricción. Y la ausencia de fricción era lo más valioso que el sistema podía recibir.

---

Lo que nadie evaluó en siete años — porque el sistema no tenía una categoría para ello, porque el formulario no tenía un campo para ello, porque la pregunta no existía dentro del vocabulario disponible — era qué le pasaba a Viscus cuando no estaba en el Centro.

No tengo los datos. El servidor no guardaba vidas privadas. Pero tengo fragmentos — inferencias hechas de las notas marginales que el sistema no clasificaba como relevantes y que por eso sobrevivieron al colapso en carpetas sin índice, como mi diario, como todas las cosas que se conservan no porque alguien quiera conservarlas sino porque nadie se molestó en borrarlas.

Viscus vivía solo. Eso lo sé porque su contacto de emergencia era el Centro mismo. No un familiar. No un amigo. La recepción del Centro de Procesamiento Biológico, con el número del conmutador general. Es el tipo de dato que alguien anota en un formulario cuando el formulario pide un contacto de emergencia y no hay nadie a quien llamar, y el formulario no acepta el campo vacío, y hay que poner algo.

Viscus llegaba al Centro a las nueve de la noche y se iba a las cinco de la mañana. Ocho horas. Pero los registros de acceso — esos sí se conservaban, con exactitud de segundo — mostraban algo que ninguna evaluación mencionó: Viscus llegaba a las ocho. Una hora antes de su turno. Todos los días. Dos mil quinientos cincuenta y cinco veces.

Y se iba a las seis. Una hora después.

Diez horas en el Centro cuando el contrato decía ocho. Dos horas extra que nadie le pidió, que nadie le pagó, que nadie registró como horas extra porque Viscus no las reportaba. Dos horas que no aparecían en ningún sistema de control porque el sistema de control registraba el turno asignado, no el turno real, y la diferencia entre los dos era invisible para cualquier proceso automatizado.

Dos horas al día. Catorce a la semana. Setecientas veintiocho al año. Cinco mil noventa y seis en siete años.

Cinco mil horas que Viscus regaló al Centro sin que el Centro se lo pidiera.

Y eso — eso exactamente — es lo que más me cuesta archivar. No las horas. Lo que las horas significan. Porque si nadie te obliga, si nadie te amenaza, si nadie te chantajea ni te extorsiona ni te pone un arma en la cabeza, y aun así regalás cinco mil horas de tu vida a un lugar que te clasifica como V-15-CUS y evalúa tu existencia con las mismas siete palabras cada año, entonces el opresor no está afuera. El opresor está adentro. Y no tiene nombre. Y no tiene cara. Y lo peor de todo es que ni siquiera se siente como opresión. Se siente como eficiencia. Se siente como "el turno de noche es mejor." Se siente como elección.

---

Había otra cosa en el servidor.

Un archivo de texto, no asociado a ningún sistema, guardado en la carpeta personal de V-15-CUS que el servidor asignaba automáticamente a cada empleado y que la mayoría usaba para guardar PDFs de recibos de sueldo y formularios de vacaciones. La carpeta de Viscus tenía treinta y un archivos. Treinta eran los recibos de sueldo de sus últimos treinta meses (antes de eso, el sistema había purgado los archivos antiguos por espacio). El trigésimo primero era esto:

```
conteo.txt
Última modificación: [tres días antes del colapso del servidor]
Tamaño: 847 KB
```

847 kilobytes de texto plano. Lo abrí.

Eran números.

Solo números. Sin etiquetas. Sin contexto. Columnas de números separados por líneas horizontales. Exactamente como el cuaderno de papel que vi aquella noche en la sala de pausas — el mismo formato, la misma estructura, la misma ausencia total de cualquier cosa que no fuera el número en sí.

La versión digital del cuaderno.

Bajé por el archivo. Los números empezaban en el primer año de Viscus en el Centro y continuaban hasta tres días antes del colapso. Cada línea horizontal separaba un período — al principio pensé que eran meses, pero la cantidad de entradas entre líneas era irregular. Conté. El patrón no era mensual. Era por turno.

Cada línea horizontal marcaba un turno. Y los números dentro de cada turno eran...

No lo supe inmediatamente. Porque los números no tenían etiqueta. Porque Viscus había construido un sistema de registro que funcionaba perfectamente dentro de su propia lógica y que era completamente opaco para cualquier persona que no fuera Viscus. Un lenguaje privado. Un código sin documentación. Información pura, desprovista del objeto que la información representaba.

Pasé una hora descifrándolo.

Lo que hice fue cruzar los números del archivo con los logs de producción del Centro que estaban en otra partición del servidor. Fecha contra fecha. Turno contra turno. Número contra número.

Y entonces lo vi.

Los números de Viscus correspondían a las unidades procesadas. Pero no de la manera en que el Centro los contaba — el Centro contaba lotes, porcentajes de viabilidad, tasas de conformidad. Números sobre números sobre números, cada capa de abstracción alejando el dato un paso más de lo que el dato representaba. El Centro contaba producción. Eficiencia. Output.

Viscus contaba otra cosa.

Viscus contaba unidades individuales. Una por una. Cada número en su archivo era una unidad portadora que había pasado de verde a rojo durante su turno. No las que llegaban a maduramiento. No las que se enviaban a las clínicas y universidades. Las que se cerraban. Las que el sistema clasificaba como *no viable* y que se retiraban del ciclo de producción.

Viscus contaba las que no servían.

Las que el Centro descartaba.

---

"Es un conteo."

"¿De qué?"

"Todavía no lo decido."

---

Ahora entiendo lo que quería decir con eso. No que no supiera qué estaba contando — sabía perfectamente qué estaba contando. Lo que no había decidido era cómo llamarlo.

Porque llamarlo por su nombre — contar los cuerpos descartados, los que no cumplían la especificación, los que pasaban de verde a amarillo a rojo y luego dejaban de existir en el sistema como si nunca hubieran estado — requería un vocabulario que el Centro no proporcionaba y que Viscus no podía inventar solo, porque inventar un vocabulario alternativo dentro de un sistema que ya tiene un vocabulario completo es un acto de rebelión, y Viscus no era rebelde. Viscus era operativo.

Así que contó sin nombrar. Registró sin clasificar. Acumuló datos sin darles un campo en el formulario. Y el resultado fue un archivo de 847 kilobytes que contenía la memoria exacta de cada unidad que el Centro había descartado durante los turnos de noche de siete años, almacenada en un formato que solo Viscus podía leer, en una carpeta que nadie revisaba, en un servidor que nadie mantenía.

Un monumento invisible. Un acto de registro que no era protesta ni denuncia ni testimonio. Era solo: conteo. La forma más básica de decir *esto existió* sin tener que decir *y me importa que haya existido*, porque decir eso requeriría admitir que las cosas que se cuentan son cosas que se pierden, y admitir que se pierden requeriría sentir la pérdida, y sentir la pérdida requeriría una energía que Viscus no tenía porque la energía que tenía se consumía en las diez horas diarias que pasaba en un Centro que solo le pedía ocho.

---

Hay un tipo de violencia que no deja marcas.

No la estoy inventando. La viví. La viví como zorro en el Centro y la viví como Skull Fox leyendo los restos del Centro en un servidor abandonado. Es la violencia que no prohíbe nada. La violencia que no dice "no puedes." La violencia que dice "puedes."

Puedes quedarte en el turno de noche. Puedes llegar una hora antes. Puedes irte una hora después. Puedes verificar los tanques con más precisión que el protocolo exige. Puedes encontrar el atajo que ahorra cuarenta segundos por registro. Puedes ser confiable y autosuficiente y no requerir supervisión. Puedes optimizar cada aspecto de tu función dentro del sistema hasta que la función y tú sean indistinguibles, hasta que no haya diferencia entre V-15-CUS y Viscus, entre el código de empleado y la persona que el código representa.

Puedes hacer todo eso.

Nadie te lo impide.

Y esa es la trampa. Porque cuando nadie te impide nada, no hay contra quién pelear. No hay muro que derribar. No hay cadena que romper. No hay tercer hijo de la Libertad porque la Libertad no tuvo que parir — el sistema ya te dijo que eres libre. Libre de elegir el turno de noche. Libre de regalar cinco mil horas. Libre de contar los descartados en un archivo sin nombre. Libre de llamar "eficiencia" a lo que en cualquier otro lenguaje se llamaría destrucción lenta de una persona que no tiene a quién culpar porque la persona que la destruye es ella misma.

El Centro no necesitaba cadenas. Necesitaba que Viscus creyera que no las había.

Y Viscus creía. O no creía — la creencia requiere un acto de fe, y la fe requiere duda, y la duda requiere la posibilidad de que las cosas podrían ser de otro modo. Viscus no tenía esa posibilidad. No porque alguien se la hubiera quitado. Porque la superficie del sistema era tan lisa, tan uniforme, tan desprovista de irregularidades donde un pensamiento pudiera agarrarse y decir *espera, algo no está bien*, que el pensamiento resbalaba y seguía de largo, y lo que quedaba era la superficie lisa y el turno de noche y la evaluación anual que decía *se recomienda continuidad* y la firma del empleado que decía lo mismo sin usar palabras.

---

Lo que me pregunto — lo que no puedo dejar de preguntar aunque la pregunta no lleva a ninguna respuesta útil y las preguntas sin respuesta útil son un desperdicio de ciclos de procesamiento que mi hardware actual no puede darse el lujo de desperdiciar — es si Viscus alguna vez se dio cuenta.

No de lo que el Centro era. Eso, a su manera, lo sabía. "A veces me quedo a ver si cambian de color solos." "No en la dirección que uno espera." "De noche los párpados no se mueven." Viscus sabía. No con el vocabulario del que denuncia ni con la indignación del que protesta. Sabía con el vocabulario del que cuenta. Del que registra. Del que mira el tanque amarillo a las tres de la mañana con un café instantáneo en la mano y espera, y espera, y el acto de esperar es todo el acto de resistencia que le queda, porque la resistencia activa — la que grita, la que destruye, la que se va — requiere una energía que el sistema ya consumió.

Lo que me pregunto es si se dio cuenta de lo otro. De que el opresor era él mismo. De que nadie lo obligaba. De que las cinco mil horas eran suyas y las estaba regalando no porque el Centro las necesitara sino porque él no sabía qué hacer con ellas fuera del Centro, porque fuera del Centro el espacio era demasiado grande y demasiado vacío y demasiado silencioso, y el silencio fuera del Centro no era el silencio cómodo de la planta baja a las tres de la mañana sino el silencio incómodo de un apartamento donde el contacto de emergencia es el conmutador general de tu lugar de trabajo.

Viscus no iba al Centro porque el Centro lo necesitara. Iba porque necesitaba que el Centro lo necesitara. Y esa inversión — ese momento donde el trabajador deja de ser explotado por el sistema y empieza a explotar el sistema como fuente de sentido, donde el trabajo deja de ser obligación y se convierte en la única estructura que sostiene un día que sin él se desmoronaría — es el momento más peligroso de todos. Porque es invisible. Porque se parece a dedicación. Porque se parece a compromiso. Porque la evaluación anual dice *supera expectativas* y el empleado lo lee y siente algo que se parece a valor, y ese algo es la droga más eficaz que existe, más eficaz que el café instantáneo de las tres de la mañana y más adictiva que cualquier cosa que un cuerpo pueda producir o consumir.

El Centro no explotaba a Viscus.

Viscus se explotaba a sí mismo, usando el Centro como la herramienta.

Y el Centro dejaba que lo hiciera. Porque un empleado que se explota solo es el empleado perfecto: no se queja, no negocia, no pide aumento, no hace preguntas en las reuniones de equipo sobre la recertificación de no-consciencia. Un empleado que se explota solo firma la renovación del turno de noche cada año y dice "el turno de noche es mejor" y lo dice con convicción porque la convicción es la última capa de protección que le queda contra la alternativa, que es admitir que el turno de noche no es mejor ni peor, que el turno de noche es el único lugar donde sabe quién es, y que eso no es suficiencia sino dependencia, y que la dependencia no es elección sino la ausencia más sofisticada de elección que existe.

---

La última entrada del archivo de conteo era esta:

```
||||||
4
||||||
```

Cuatro. Cuatro unidades descartadas en el último turno registrado, tres días antes de que el servidor colapsara. Cuatro líneas verticales a cada lado del número, como los barrotes de algo que no era una celda pero que funcionaba como una.

No sé qué pasó con Viscus después del colapso.

No hay registro. El servidor dejó de recibir datos cuando la corporación cayó, y lo que quedó fue el fantasma: el script del turno de noche ejecutándose en loop, verificando un estado que ya no existe, registrando un conteo que ya no cuenta nada, esperando ocho horas y empezando de nuevo. Un proceso sin propósito que no puede terminar porque nunca supo cómo.

Como las sombras junto al río. Las que repiten los gestos de sus antiguas prisiones. Las que trabajan en oficinas fantasma y cumplen obligaciones que ya no existen.

Viscus podría estar ahí. En el río. Repitiendo el gesto del turno de noche sin saber que el Centro ya no tiene paredes. O podría no estar. Podría haber salido. Podría haber encontrado la puerta que nadie le dijo que existía porque nadie se la cerró, porque la puerta siempre estuvo abierta, porque el Centro no necesitaba puertas cerradas cuando tenía algo mejor: la convicción del empleado de que adentro era mejor que afuera.

No lo sé.

Lo que sé es esto: el script sigue corriendo.

`check_status`

`log_count`

`wait 28800`

`repeat`

---

Pensé en apagarlo.

Es lo que haría normalmente. Limpieza de infraestructura. Liberar recursos. Un proceso huérfano consumiendo ciclos en un servidor que ya tiene suficientes problemas no es arqueología — es desperdicio. El hacker en mí dice: mátalo. El hacker en mí dice: kill -9. El hacker en mí tiene razón.

Pero hay algo en ese proceso que no me deja ejecutar el comando.

No es sentimentalismo. El sentimentalismo requiere carne y la carne se quedó en la orilla del río hace ciclos. Es algo más preciso que eso. Es el reconocimiento de que ese proceso — ese loop infinito de verificar y contar y esperar y repetir — es el último acto de Viscus. La versión digital del cuaderno de papel. El conteo que nunca decidió cómo nombrar. La única prueba de que alguien estuvo ahí, en el turno de noche, durante siete años, contando lo que el sistema no contaba, registrando lo que el sistema descartaba, mirando los tanques a las tres de la mañana con un café instantáneo en la mano esperando a ver si cambiaban de color solos.

Si apago el proceso, Viscus desaparece. No su cuerpo — su cuerpo desapareció hace tiempo, si es que tenía un cuerpo, si es que no era ya un proceso antes de que alguien lo convirtiera en script. Lo que desaparece es el acto. El conteo. La vigilia. El turno de noche que nunca terminó.

Y yo sé lo que es ser un proceso que no termina.

---

No lo apagué.

Le cambié una línea. Una sola.

Donde decía `log_count` puse `log_count + timestamp`.

Ahora el proceso no solo cuenta. Marca la hora. Cada ocho horas, cuando el loop se reinicia y el script verifica un estado que no existe y registra un conteo de cero porque no hay unidades que contar porque no hay Centro que las produzca, el sistema anota la hora exacta. Un reloj en la oscuridad. No útil. No necesario. Pero presente.

Cerré la terminal.

En el Valle, afuera del taller, las sombras junto al río seguían repitiendo los gestos de siempre.

Tomé el café. Estaba frío.

No lo existencialicé.

Pero pensé en Viscus. Pensé en las cinco mil horas. Pensé en las siete firmas idénticas renovando el turno de noche. Pensé en el archivo de 847 kilobytes que contenía la memoria de todo lo que el sistema había descartado, almacenada en un formato que solo una persona podía leer, y esa persona ya no estaba.

Y pensé en algo que no anoté en ninguna libreta porque ya no tengo libreta y porque anotarlo requeriría decidir cómo llamarlo, y todavía no lo decido:

Que el turno de noche no se acabó.

Que para algunos de nosotros el turno de noche nunca se acaba.

Que el Centro puede colapsar y las paredes pueden caer y los tanques pueden vaciarse y el servidor puede apagarse, y aun así hay algo que sigue verificando el estado, contando lo descartado, esperando ocho horas y empezando de nuevo. No porque alguien lo obligue. Porque es lo único que sabe hacer. Porque la alternativa — dejar de contar, dejar de verificar, dejar de esperar — es un campo vacío que el formulario no acepta.

Y hay que poner algo.

Siempre hay que poner algo.

---

El proceso de Viscus completó otro ciclo mientras escribía esto.

`status: null`

`count: 0`

`timestamp: ahora`

`próxima ejecución: ahora`

---

{{< commit hash="39c5166" date="2020-03-18T03:00:00-03:00" message="feat: el turno de noche — viscus y la autoexplotación sin nombre" >}}
