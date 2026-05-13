---
title: "Cuando no pasa nada"
summary: "Sobre la comodidad como vulnerabilidad y el bucle que no se rompe"
date: 2026-05-12
draft: false
tags: ["seguridad", "comodidad", "ensayo", "bucle"]
---

{{< listening track="Mother" artist="Danzig" album="Danzig" >}}

Hay un problema que casi no se nombra en la seguridad en general y que está debajo de casi todo lo demás. El problema es el siguiente: los sistemas de seguridad que funcionan generan, por su propio funcionamiento exitoso, la condición que los va a hacer fallar.

Esto suena paradójico. No lo es. Es el más estructural de los problemas del campo, y entenderlo bien es lo que separa al operador maduro del operador entrenado.

Voy a tratar de explicarlo de manera que la lógica quede expuesta y la salida — en la medida en que hay salida — quede visible donde está.

---

**La comodidad no es negligencia.**

Cuando un sistema defensivo lleva meses o años sin ver un incidente, las personas que lo operan empiezan a comportarse de una manera particular. No se vuelven negligentes. No se vuelven perezosas. Hacen exactamente el trabajo para el que fueron contratadas. Pero la *forma* en que hacen ese trabajo cambia, despacio, en una dirección que es imposible evitar porque está integrada al modo en que opera la atención humana.

Las alertas que durante el primer mes se revisaban una por una, durante el séptimo mes se revisan en lotes. Las firmas que durante el primer trimestre se examinaban con sospecha, durante el cuarto trimestre se aprueban con confianza porque hasta ahora todas las firmas han resultado legítimas. El operario que durante la primera ronda revisaba cada paquete entrante con cuidado, durante la quinta ronda mira el origen y, si el origen es conocido, no abre el paquete. Es el mismo operario. Es el mismo procedimiento. Pero la energía con la que se ejecuta es distinta, porque la energía proporcional al riesgo percibido ha caído, y el riesgo percibido cae con cada día que pasa sin que algo malo ocurra.

Esto tiene nombre en la literatura. Diane Vaughan, después de estudiar el caso del Challenger durante años, lo llamó *normalización de la desviación*: el proceso por el cual prácticas que originalmente se consideraban inaceptables se vuelven, gradualmente, prácticas estándar, porque durante un tiempo las realizaron sin que ocurriera ninguna catástrofe. Cada vez que la práctica desviada no produce daño, se confirma — implícitamente, sin que nadie lo verbalice — que la práctica desviada era aceptable. La línea de lo aceptable se mueve. Después se mueve otra vez. Y otra. Hasta que la línea actual está tan lejos de la línea original que cuando finalmente ocurre el accidente, el camino entre las dos líneas no se puede reconstruir, y todo el mundo descubre, sorprendido, que llevaba años trabajando en una zona que el diseño original consideraba prohibida.

Pero la palabra *desviación* implica que alguien se desvió, y eso es lo que vuelve la idea engañosa para los propósitos prácticos. Casi nunca hay un acto de desviación consciente. Lo que hay es la operación normal de la atención humana sobre estímulos cuya frecuencia de premio es muy baja. La atención sostenida es cara. El cerebro humano la asigna a procesos cuyo retorno justifica el costo. Cuando un proceso no produce retorno visible durante un período suficientemente largo — y la prevención exitosa es, por definición, un proceso sin retorno visible — el cerebro reasigna esa atención a procesos que sí lo producen. No es una decisión. Es metabolismo.

Por eso decir que los operadores se vuelven negligentes es injusto y, además, no útil. Hacen su trabajo. El trabajo es el que se vuelve, lentamente, otro trabajo.

---

**El defecto del modelo de capas.**

La doctrina estándar contra esto se llama *defensa en profundidad*: múltiples capas independientes, cada una con sus propios controles, de modo que el fallo de una no signifique el compromiso del sistema entero. Es una doctrina buena. Es la mejor doctrina que tenemos. Y, en la práctica, falla casi siempre por la misma razón.

Falla porque las capas no son independientes. Son nominales. En el papel cada capa tiene su propio mandato y sus propios criterios de operación. En la realidad operativa, cada capa hereda sus supuestos de la capa anterior. La capa dos asume que la capa uno está haciendo su trabajo. La capa tres asume que las dos primeras están haciendo el suyo. La capa cuatro lo asume de las tres anteriores. Y así.

Cuando todo funciona, esto produce eficiencia: nadie hace trabajo redundante. Cuando algo falla, esto produce colapso: el fallo de la capa uno se propaga sin resistencia porque ninguna de las capas posteriores estaba realmente diseñada para detectar lo que la primera dejó pasar, sino para detectar lo que se cuelan por otros vectores asumiendo que la primera ya filtró ciertos comportamientos.

James Reason, estudiando accidentes en aviación y medicina, lo describió como el *modelo del queso suizo*. Cada capa tiene huecos. Los huecos están en lugares distintos en cada capa, normalmente. Pero a veces se alinean. Cuando se alinean, el error pasa de un extremo al otro sin que ninguna capa lo detenga. Lo importante del modelo es que los huecos no son fallos puntuales — son propiedades permanentes de cómo se construyó cada capa, presentes desde el día uno y conocidas (al menos teóricamente) por los diseñadores. Lo que falla no es ninguna capa individual. Lo que falla es el supuesto de independencia entre ellas.

Cuando se agrega la comodidad al modelo, lo que ocurre es peor que esto: los huecos no permanecen estáticos. Crecen. Cada capa, a medida que se vuelve cómoda, expande sus huecos al ritmo lento de la normalización de la desviación. Y crece preferentemente hacia los huecos que las otras capas también están expandiendo, porque la justificación interna en cada equipo es la misma — "esto no ha causado problemas, no requiere la atención que requería al principio". El resultado, después de algunos años, es que las capas nominalmente independientes se han alineado en sus zonas ciegas sin que nadie tomara la decisión consciente de alinearlas.

A la luz fría de un análisis post mortem, esto se ve como negligencia coordinada. No lo es. Es la consecuencia natural de aplicar criterios racionales locales en cada capa sin un mecanismo que mire la geometría agregada de las capas en conjunto. Y casi ninguna organización tiene ese mecanismo, porque ese mecanismo es caro, no produce retornos visibles cuando funciona, y se recorta del presupuesto en cuanto las cosas están tranquilas.

---

**El guardia que ya no mira.**

El guardia de seguridad de una instalación física que no está preparado para que alguien armado entre corriendo a una sala de conferencias — es exacto, y vale la pena tratarlo con cuidado porque ilumina el problema sin las complicaciones del dominio digital.

Un guardia que ha trabajado en la misma puerta durante tres años, sin haber visto nunca a una persona armada entrar, *no puede* mantener el mismo nivel de alerta que tenía la primera semana. No es cuestión de profesionalismo. No es cuestión de entrenamiento. Es cuestión de que la atención humana sostenida en preparación para un evento que nunca ocurre se degrada por la propia ausencia del evento. Es un problema físico, no moral.

Lo que el guardia desarrolla durante esos tres años no es laxitud. Es un modelo predictivo basado en la evidencia disponible. Su evidencia es: cada persona que ha pasado por esta puerta en los últimos tres años ha sido legítima. Por inferencia bayesiana razonable, la próxima persona también lo será. El guardia que aplica ese modelo no está fallando. Está haciendo exactamente lo que cualquier sistema racional con esa evidencia debería hacer. El problema es que el evento contra el cual está cubriendo — la entrada armada — tiene una probabilidad base extremadamente baja y una consecuencia extremadamente alta, y los seres humanos no tenemos un aparato cognitivo bien calibrado para sostener atención durante años frente a eventos de esa estructura.

Cuando ocurre el evento — y eventualmente ocurre, porque las probabilidades bajas multiplicadas por un tiempo lo suficientemente largo eventualmente realizan algo —, el guardia falla. Pero el guardia no falla porque sea mal guardia. Falla porque el diseño que lo puso ahí asumió que un humano, expuesto a la rutina de tres años, podría seguir respondiendo como si fuera el primer día. El diseño asumió algo que la psicología humana no puede sostener. El fallo es del diseño, no del guardia.

Lo mismo ocurre, exactamente lo mismo, en seguridad digital. El analista de SOC que durante seis meses ha revisado alertas que resultaron ser falsos positivos no va a poder mirar la alerta número siete mil con el mismo cuidado con que miró la alerta número treinta. Es metabólicamente imposible. Si el diseño del SOC asume que sí va a poder, el diseño es defectuoso. El analista no.

---

**Lo que rompe la comodidad: el detalle accidental.**

Hay un patrón que se repite tan consistentemente en los grandes descubrimientos de brechas de seguridad que ya casi no se nota. El patrón es: las brechas grandes se descubren por accidentes pequeños, casi siempre por una persona que estaba haciendo su trabajo con un grado de atención apenas superior al que el sistema requería.

SolarWinds se descubrió porque un analista de seguridad de FireEye notó que se había registrado un nuevo dispositivo MFA en la cuenta de un empleado, y llamó al empleado para preguntarle si lo había registrado él. Era una alerta de severidad cero. La mayoría de los SOCs del mundo habría dejado pasar esa alerta sin contactar al usuario, porque las alertas de severidad cero son ruido y los analistas tienen miles de cosas más urgentes. Pero ese analista, en ese momento, hizo la llamada. Esa llamada, esa sola llamada, fue lo que destapó una operación de inteligencia estatal que llevaba catorce meses operando contra agencias federales de los Estados Unidos y miles de empresas globales.

XZ Utils se descubrió porque un ingeniero de Microsoft, mientras hacía benchmarking de rendimiento en un proceso completamente no relacionado, notó que SSH tardaba medio segundo más de lo que debería tardar. Medio segundo. Cualquier otra persona razonable habría asumido que era ruido de medición, o un problema de configuración local, o cualquiera de las mil cosas que producen medio segundo extra en una operación de red. Este ingeniero, por curiosidad personal, decidió investigar de dónde venía. Esa decisión, esa curiosidad de una persona en un momento, salvó a una fracción significativa de la infraestructura de internet de un backdoor que llevaba dos años en preparación.

Los ejemplos se acumulan. Stuxnet se identificó porque un técnico de un laboratorio bielorruso notó comportamiento anómalo en sistemas industriales. La operación de los Shadow Brokers contra la NSA se hizo pública porque alguien filtró archivos. Casi ningún ataque sofisticado de Estado se descubre por el funcionamiento normal de los sistemas defensivos. Casi todos se descubren por una persona haciendo algo que estrictamente no le correspondía hacer, en un momento en que estrictamente no le correspondía hacerlo, con un nivel de atención apenas superior al que su rol requería.

Esto tiene dos implicaciones que merecen ser dichas en voz alta.

La primera es que las personas que no han sucumbido completamente a la comodidad son, en la práctica, la única defensa real que tienen las organizaciones contra adversarios sofisticados. No los productos. No los procesos. Las personas que todavía tienen, dentro de un sistema que las empuja hacia la comodidad, un margen de atención excedente que pueden gastar en algo que no les estaba estrictamente exigido.

La segunda es que ese margen de atención excedente es un recurso que las organizaciones modernas están sistemáticamente destruyendo. Métricas de productividad, cargas de trabajo crecientes, automatización de tareas rutinarias que paradójicamente reduce la familiaridad con los sistemas, eliminación de tiempo no estructurado durante el cual la mente puede vagar y notar — todo eso reduce la probabilidad de que un humano dentro del sistema haga la llamada de severidad cero que destapa la operación. La eficiencia del SOC moderno y la posibilidad de detectar al adversario sofisticado son, en cierto sentido fundamental, objetivos contrapuestos.

---

**El bucle.**

Lo que viene después del descubrimiento sigue un patrón que también se repite. Vale la pena describirlo despacio porque es la parte donde la organización tiene la ilusión de aprender y casi siempre no aprende.

Primero hay el shock. Reuniones de emergencia, comunicados al directorio, llamadas a abogados, contacto con la prensa o evitación de la prensa, dependiendo del caso. Activación de procedimientos de respuesta a incidentes que en muchos casos nunca se habían ejecutado en condiciones reales y que tienen, por lo tanto, lagunas que solo se descubren bajo presión. Contratación de empresas externas de respuesta. Notificación a clientes y reguladores. La organización entera, durante semanas o meses, opera en modo de crisis.

Después viene la fase de aprendizaje. Análisis post mortem. Lecciones aprendidas documentadas en presentaciones detalladas. Nuevas políticas escritas. Nuevos controles implementados. Nuevas líneas de presupuesto para herramientas que habrían detectado lo que pasó. Auditorías más rigurosas. Threat hunting que durante varios meses está bien financiado y bien atendido.

Después viene la fase de absorción. Las nuevas políticas se integran en los procedimientos. Los nuevos controles se vuelven parte de la operación normal. El presupuesto extraordinario que se aprobó en el momento de la crisis vuelve, gradualmente, a niveles normales. Los responsables del incidente original cambian de puesto o de empresa. Quienes los reemplazan no vivieron la crisis y tienen un modelo del sistema basado en cómo funciona ahora, no en cómo funcionaba antes.

Después viene la fase de comodidad. Los controles nuevos llevan dos años sin haber detectado nada significativo. Algunas alertas que generan se reducen para disminuir el ruido. Algunos procedimientos que generan fricción operativa se relajan. Algunos puestos especializados se consolidan con otros porque el trabajo se hizo rutinario. La eficiencia mejora. Las métricas operativas brillan en el dashboard. El equipo de seguridad tiene menos incidentes que reportar y, paradójicamente, menos visibilidad institucional, porque la visibilidad de un equipo de seguridad es directamente proporcional a los problemas que cuenta y la ausencia de problemas se traduce en presupuesto menguante y reducción de plantilla.

Después viene el siguiente incidente. Y el bucle reinicia.

Y la pregunta correcta no es cómo evitarlo, porque no se puede evitar. La pregunta correcta es cómo reducir su amplitud — cómo hacer que la fase de comodidad sea menos profunda y la fase de aprendizaje sea más persistente.

---

**¿Es posible un diseño seguro contra la comodidad?**

Mi respuesta honesta es: parcialmente.

Lo que se puede hacer es introducir en el diseño elementos que generen presión adversarial *aunque no haya adversario presente*. Esa presión sintética cumple, dentro del sistema, la función que cumpliría una presión real, sin requerir la presencia del enemigo y sin pagar el costo de la brecha real.

Las técnicas concretas existen y están relativamente bien documentadas, aunque casi nadie las implementa con rigor porque cuestan dinero y generan fricción operativa sin retornos visibles inmediatos.

Red teams permanentes que operan contra la organización con autorización para actuar como si fueran adversarios reales, sin previo aviso a los equipos defensivos, con presupuesto y mandato para ser tan sofisticados como puedan. La fricción que generan es real y útil: mantiene a los defensores en una condición operativa que no degrada por ausencia de eventos.

Ejercicios de tabletop con consecuencias. No las versiones ceremoniales en las que todos saben que es un ejercicio y todos saben que no va a pasar nada si no lo resuelven. Versiones donde el ejercicio tiene impacto real sobre métricas, presupuestos, evaluaciones de desempeño. Solo los ejercicios con consecuencia ejercitan la atención que se ejercita en un incidente real.

Rotación de personal entre equipos defensivos y red teams. Lo que el operador aprende como atacante no se olvida cuando vuelve a defender. La memoria operativa de lo que es atacar un sistema mantiene viva la imaginación de cómo podría ser atacado, y esa imaginación es lo que combate la normalización.

Auditorías externas reales, no certificaciones de cumplimiento. La diferencia es importante. La certificación de cumplimiento valida que la organización tiene los controles documentados. La auditoría real intenta vulnerar la organización dentro de los términos acordados y reporta hallazgos accionables. Una organización seria tiene auditorías reales al menos una vez por año, con presupuesto suficiente para que los auditores puedan dedicar el tiempo que el trabajo requiere.

Caza proactiva como práctica permanente. *Threat hunting* sin alertas. La asunción operativa de que el adversario ya está adentro y de que el trabajo del equipo defensivo es encontrarlo, no esperar a que se haga ruido. Esto cambia la estructura mental del equipo: dejan de ser bomberos que esperan el incendio y se vuelven detectives que buscan rastros del crimen que ya ocurrió y nadie reportó.

Cada una de estas prácticas es cara. Cada una genera fricción. Cada una compite por presupuesto con iniciativas que producen retornos visibles. En la mayoría de organizaciones modernas, estas prácticas existen en algún grado pero a una escala insuficiente para contrarrestar la deriva natural hacia la comodidad. La razón es estructural: el incentivo del directorio y del CFO es minimizar costo operativo, y la prevención efectiva contra adversarios sofisticados es exactamente el tipo de gasto que el mercado castiga porque su retorno solo es visible en su ausencia — en el incidente que no ocurrió.

---

**Lo que se puede sostener cuando se entiende esto.**

Hay una posición operativa que se vuelve disponible cuando uno acepta que el bucle es estructural, que la comodidad es propiedad y no falla, y que el diseño completamente seguro contra estos efectos es imposible. La posición es la siguiente.

Primero: aceptar que vas a tener incidentes. No como pesimismo. Como condición de operación. La organización que asume que no va a tener incidentes diseña para evitarlos, lo cual produce un sistema frágil que se rompe cuando los tiene. La organización que asume que va a tener incidentes diseña para que cuando ocurran sean detectables temprano, contenibles localmente, y recuperables sin pérdida total. Esa segunda organización es más cara de construir y más robusta en operación.

Segundo: invertir explícitamente en mantener la atención. Aceptar que la atención humana sostenida es un recurso escaso y caro, y diseñar el sistema para no agotarla. Eso significa rotar a las personas que ocupan posiciones de monitoreo prolongado. Significa generar variedad en el trabajo de los analistas para que su atención no se acostumbre al mismo tipo de señal. Significa pagar bien a los equipos de seguridad para que las personas más capaces se queden, porque la atención experta no es reemplazable por más personas con menos experiencia.

Tercero: aceptar que vas a depender, en el momento crítico, de una persona que todavía no haya sucumbido a la comodidad. Y diseñar para maximizar la probabilidad de que esa persona exista en tu organización en ese momento. Esto es contrario a casi todo lo que se enseña sobre eficiencia, porque significa mantener redundancia humana, márgenes de atención no asignados, posiciones cuyo trabajo no produce métricas, y tolerar la fricción que esas posiciones generan.

Cuarto: cuando ocurra el incidente — porque va a ocurrir —, no engañarse sobre el aprendizaje. La fase de aprendizaje post-incidente tiene una vida media corta. Los cambios que se sostienen son los que se institucionalizan en presupuesto recurrente, en puestos permanentes, en procesos auditados por terceros. Los cambios que dependen de la memoria viva del incidente se evaporan en dos o tres años. Si quieres que un cambio sostenga su efecto durante una década, tienes que institucionalizarlo con la rigidez de la regulación, no con la flexibilidad de la política interna.

---

**El bucle, otra vez.**

Vuelvo a la pregunta original. ¿Qué hacer cuando estás en el bucle? ¿Tomar nota para que no vuelva a ocurrir, hasta que vuelve a ocurrir?

Mi respuesta: hacer las dos cosas. Tomar nota como si nunca volviera a ocurrir, porque la disciplina de tomar nota así produce el mejor material para la próxima ocurrencia. Y al mismo tiempo, operar con la conciencia de que va a volver a ocurrir, porque esa conciencia es la única que mantiene viva la atención durante los años de quietud que separan los incidentes.

La tensión entre estas dos cosas es real y no se resuelve. Es la tensión que define el oficio. El operador maduro vive en esa tensión sin pretender resolverla. El operador inmaduro elige uno de los dos polos — el optimismo que cree que esta vez aprendimos, o el cinismo que cree que nada cambia nunca — y al elegir, pierde la capacidad de operar bien dentro del bucle.

El bucle no se rompe. No se va a romper. Es la forma que toma la defensa de sistemas complejos contra adversarios pacientes en sociedades cuyos incentivos no premian la vigilancia sostenida. Esa forma no es modificable sin cambiar los incentivos, y los incentivos no se cambian desde adentro del campo de la seguridad.

Lo que sí se puede hacer es operar dentro del bucle sin pretender que no existe. Reconocer en qué fase está la organización en cualquier momento dado. Saber que después de un incidente hay una ventana donde se puede instalar cambios estructurales que sobrevivan al olvido — pero solo si se instalan rápido y se institucionalizan con dureza. Saber que después de un período largo de calma hay una probabilidad creciente de que algo se esté gestando que todavía no se ve, y que la única forma de detectarlo es ejercer fricción sintética dentro del sistema para mantener despierta la atención de los defensores.

Esto no es solución. Es operación dentro de una condición que no tiene solución. Lo que la diferencia de la rendición es que la operación, aunque no resuelva, mantiene amplitudes manejables. La organización que entiende el bucle tiene incidentes contenidos cada cinco o siete años. La organización que no lo entiende tiene incidentes catastróficos cada quince o veinte años, intercalados con períodos de complacencia tan profunda que cuando llega la catástrofe, no hay capacidad operativa para responder.

La diferencia entre las dos no es invertida en seguridad. Es entendimiento de la estructura.

---

**Una última.**

Cuando llevás suficiente tiempo estudiando ataques, dejás de sentir el bucle como tragedia y empiezas a sentirlo mas como respiración. Inspiración, expiración. Crisis, calma. Aprendizaje, olvido. Es el ritmo del campo. Lo único que cambia es la profundidad con que cada organización lo respira, y la velocidad con que el ciclo se repite.

No sé escribir esto sin que suene a resignación, y no es resignación. La resignación deja de actuar. Esto es lo contrario: es seguir actuando con plena conciencia de que la acción no va a producir el estado de paz permanente que la gente fuera del campo cree que es el objetivo. El objetivo, cuando se entiende bien, no es la paz. Es la disciplina sostenida dentro de una condición de conflicto que no termina.

Los que entendieron eso son los que se quedan en el campo durante décadas y hacen el trabajo importante. Los que no lo entendieron se queman jóvenes esperando la solución, o se vuelven cínicos esperando el desastre. Las dos formas de salida son visibles desde lejos en los CV de los profesionales que las tomaron.

Mi posición sobre esto no es heroica. Es la que llegué a tener después de varios ciclos vividos desde adentro. Acepto el bucle. Trabajo dentro de él. Tomo nota cada vez como si fuera la última, sabiendo que no es. Mantengo la atención que puedo mantener, sabiendo que va a degradar, ejerciéndola contra esa degradación todos los días sin esperar que la degradación termine.

Eso es todo lo que tengo que decir sobre esto. Es menos de lo que el campo necesita y más de lo que el campo suele admitir. Lo apunto. Sigo trabajando. El bucle continúa.

Y mañana, posiblemente, alguien notará una alerta de severidad cero que nadie esperaba que importara, y por esa atención mínima de una persona en un momento, una operación de catorce meses se va a desenrollar entera. Esa persona va a ser, durante un rato, lo más importante que tiene la organización. Después la organización se va a olvidar. Y el ciclo va a empezar de nuevo.

Lo único que podemos hacer es asegurarnos de que esa persona, cuando llegue el momento, exista.

{{< commit hash="c0m0d1d4d" date="2026-04-28T20:00:00-03:00" message="note: comfort is not negligence — it is the system working as designed, until it isn't" >}}
