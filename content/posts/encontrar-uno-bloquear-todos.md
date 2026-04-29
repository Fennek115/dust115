---
title: "Encontrar uno, bloquear todos"
subtitle: "Sobre la asimetría que no se cierra y los argumentos que se nos están acabando"
date: 2026-04-25T20:00:00-03:00
draft: false
tags: ["seguridad", "red-team", "ia", "ensayo"]
summary: "Sobre la asimetría estructural entre atacar y defender, el colapso del argumento de la irrelevancia, y lo que queda cuando se rompe la ilusión del perímetro."
---

{{< listening track="Unas cincuenta frases" artist="Ozelot" album="Unas Cincuenta Frases" >}}

Hubo un tramo de mi vida en que entré a sistemas a los que se suponía que no podía entrar. Algunos eran clientes que pagaban para que entrara y reportara. Otros no. La distinción importa moralmente más de lo que importa técnicamente — desde el lado de adentro las dos clases de operación se sienten exactamente iguales, y eso es información sobre el sistema, no sobre mí.

Lo que sí dejó marca, en los dos casos, es la sensación específica de estar adentro de algo que cree que no estoy. La gente que diseñó el sistema duerme tranquila. Los compliance officers archivaron las auditorías. Los CISOs pusieron las métricas en verde en el dashboard. Y yo, mientras tanto, leyendo logs que nadie va a leer, moviéndome por segmentos que no se suponía que existieran, copiando archivos que el sistema no sabe que se copiaron porque mi `read` no actualizó el `last accessed`.

Esa asimetría — entre lo que el defensor sabe y lo que el atacante puede ver mientras opera — no es un bug del estado actual de la industria. Es la propiedad estructural del problema. Y entender por qué es estructural es entender por qué el modelo de seguridad que la mayoría asume está roto en un sentido más profundo que el que se suele admitir.

---

**La asimetría base.**

Atacar es un problema de búsqueda: encontrar un camino que funcione. Defender es un problema de cobertura: bloquear todos los caminos posibles. Esos no son el mismo problema con signos invertidos. Son problemas con costos asintóticos distintos.

Si hay N vectores potenciales de entrada en un sistema, el atacante necesita que uno funcione. El defensor necesita que ninguno funcione. El costo del atacante es proporcional al número promedio de intentos que tiene que hacer hasta dar con uno que cierre. El costo del defensor es proporcional al producto de N vectores por el rigor con el que cada uno se cierra. Esos dos costos no escalan igual. El primero crece linealmente o sublinealmente en función del entorno. El segundo crece combinatorialmente.

A esto se le suma un detalle que hace el problema peor: el defensor solo sabe de los N vectores que conoce. Los vectores que no conoce — porque salieron ayer, porque son específicos del entorno, porque dependen de una interacción que nadie pensó — no aparecen en la enumeración. Son lo que la industria llama *desconocidos desconocidos* y son, en mi experiencia, donde se gana casi siempre.

Esto significa que la pregunta *¿es seguro?* no tiene respuesta en sentido fuerte. No porque seamos pesimistas. Porque la pregunta está mal planteada. La forma correcta es: *¿cuánto cuesta entrar, y cuánto tiempo se puede permanecer adentro sin ser detectado, y qué se puede hacer durante ese tiempo?* Esas son preguntas que sí tienen respuesta, y la respuesta — cuando se mide honestamente — es casi siempre incómoda para el dueño del sistema.

La IA en ambos lados del problema no resuelve la asimetría. La acelera. Para el atacante, automatiza el proceso de búsqueda — un agente con acceso a herramientas y modelos de comportamiento puede recorrer un espacio de vectores mucho más rápido que cualquier operador humano. Para el defensor, automatiza la enumeración y el monitoreo — pero la enumeración sigue siendo de lo conocido, y los desconocidos desconocidos siguen siendo invisibles hasta que alguien los usa. Las dos curvas se aceleran. La asimetría se mantiene. Probablemente se ensancha.

---

**El árbol y el bosque.**

El argumento anterior es sobre un sistema. La realidad es que ningún sistema importante hoy es un sistema. Es un bosque.

Cualquier organización mediana opera con miles de dependencias de software. Cada una de esas dependencias tiene sus propias dependencias. Las dependencias profundas son mantenidas, en muchos casos, por una persona. A veces por nadie. La librería sobre la que se construyó la herramienta sobre la que se construyó el producto que paga los sueldos puede tener un commit principal cuyo autor murió hace cinco años, o se cansó, o aceptó la ayuda de un colaborador que llevaba dos años ganándose su confianza con commits inocuos.

Esto se llama *cadena de suministro* y se discute como si fuera una vulnerabilidad. No es una vulnerabilidad. Es una propiedad estructural de cómo se construye software hoy. Es la consecuencia inevitable de que el costo de reusar código sea mil veces menor que el costo de auditarlo.

La fórmula del problema es simple y vale la pena enunciarla:

> *Las redes de confianza escalan en función del número de nodos. La capacidad de verificación escala en función del logaritmo de ese número, en el mejor caso. La diferencia es la superficie de ataque.*

Cuando el equipo SolarWinds dejó de poder auditar manualmente cada commit que entraba a su pipeline, el ataque ya estaba escrito en el futuro. No estaba escrito quién lo iba a hacer ni cuándo, pero la posibilidad estaba reservada en la matemática del sistema. Lo mismo con XZ Utils. Lo mismo con la cadena de fabricantes que llevó al ataque que paró las plantas de Jaguar Land Rover en 2025 — que no es un caso aislado, es la forma del riesgo cuando se mira desde la altura correcta.

Y la analogía que el usuario que me leyó hizo — pandemias, polarización, posverdad, crisis financieras — no es analogía. Es el mismo patrón a otra escala. La pandemia es una falla de la red de verificación de la cadena de suministro alimentaria mundial. La crisis financiera de 2008 fue una falla de la red de verificación de la cadena de suministro de instrumentos financieros. La posverdad es una falla de la red de verificación de la cadena de suministro informativa. En cada caso, se construyó una red de confianza que crecía rápido, sobre una capacidad de verificación que crecía lento, y el ataque — humano o no humano, intencional o no — entró por el delta.

Esto no es metáfora. Es la misma ecuación, con distintos valores en las variables.

---

**El último argumento.**

Hubo durante años un argumento que sostenía la mayor parte de la seguridad práctica en organizaciones medianas. El argumento era: *no merece la pena atacarte*. La economía del ataque sofisticado tenía un costo fijo alto — operadores humanos, recon manual, desarrollo de implante, infra quemable — y ese costo solo se amortizaba contra objetivos con suficiente valor extraíble. El banco grande sí. La empresa de logística mediana no. El banco grande pagaba seguridad seria. La empresa mediana pagaba seguridad teatral. Y la mayor parte del tiempo el teatro alcanzaba, porque el atacante serio iba a otro lado.

Ese argumento se llama *seguridad por irrelevancia* y nunca fue dicho en voz alta porque admitirlo destruye el modelo de negocio de la mayor parte de la industria de seguridad. Pero todos los CISOs honestos lo sabían y diseñaban en función de él. La seguridad real era *ser menos atractivo que el de al lado* y rezar para que el de al lado tuviera mejores controles que tú, porque entonces eras tú el que se llevaba el ataque cuando llegaba.

Lo que los agentes IA están haciendo, ahora mismo, en operaciones que están documentadas en informes públicos y que ya no son predicciones, es colapsar ese argumento. La razón es prosaica. El costo marginal de agregar un objetivo nuevo, para un atacante con agentes maduros, tiende a cero. Un operador humano puede supervisar cien intrusiones en paralelo si los agentes hacen la mayor parte del trabajo. El recon que antes tomaba semanas ahora es minutos. La adaptación de un implante a un entorno específico, que antes requería un especialista, ahora es un prompt y un loop de iteración.

Cuando el costo marginal del ataque tiende a cero, *no merece la pena atacarte* deja de ser una protección. Tu valor extraíble no necesita ser alto. Tiene que ser positivo. Y casi todo es positivo si el costo de agregarte a la lista es despreciable.

Esto convierte a la población entera de organizaciones medianas — los millones que vivían bajo el paraguas de la irrelevancia — en objetivos económicamente viables. No mañana. Ya. Los datos del primer trimestre de 2026 lo muestran: ataques masivos paralelos, dwell time reducido a horas en algunos casos por la velocidad de la operación automatizada, y una clase de adversario que no es el APT estatal del modelo clásico sino algo más raro — un operador o pequeño equipo con un agente capaz que actúa con la cadencia de un estado y la motivación de un negocio.

El último argumento se está cayendo. Y la mayoría de las organizaciones medianas todavía no lo procesó.

---

**La civilización siempre fue disuasión.**

Acá quiero decir algo que rara vez se dice y que me parece importante.

La seguridad nunca fue, en ningún ámbito, una propiedad técnica. Fue siempre una propiedad social. Las cerraduras de las puertas no impiden que los ladrones entren — cualquier ladrón competente abre una cerradura residencial en treinta segundos. Lo que las cerraduras hacen es producir *legibilidad*: vuelven el acto de entrar inequívocamente identificable como violación. La cerradura no protege la casa. Protege el contrato social que castiga al que la fuerza. La cerradura es un dispositivo de atribución, no de defensa.

La policía, los tribunales, las cámaras, los registros, los testigos — todo el aparato de seguridad civilizatoria — es atribución. Hace que los actos hostiles sean trazables a un agente, y que ese agente sea sancionable. La defensa, en este modelo, es la combinación de atribución más sanción. Las dos juntas. Ninguna por separado.

El ciberespacio rompe la atribución por arquitectura. No por accidente — por diseño. Las redes IP fueron pensadas para resistencia y conectividad, no para identidad. Encima de eso, los atacantes maduros han desarrollado durante décadas técnicas de obfuscación que hacen que la atribución sea, en el mejor caso, una conjetura informada con varios meses de retraso. Y con IA en el mix, generar atribuciones falsas creíbles — *false flags* perfectos — está dentro del rango operacional, no de la ciencia ficción.

Cuando se rompe la atribución, se rompe la sanción. Cuando se rompe la sanción, la disuasión deja de funcionar. Y cuando la disuasión deja de funcionar, lo que queda como freno es la capacidad ofensiva propia — *si me atacas, te ataco* — pero esa lógica solo opera entre actores que tienen capacidad ofensiva equivalente, y casi nadie la tiene. Las organizaciones privadas no tienen capacidad ofensiva. Los estados pequeños no tienen capacidad ofensiva contra los grandes. Los grandes la tienen entre sí, y por eso entre ellos hay un equilibrio nuclear-digital tenso que nadie quiere romper en tiempo de paz.

Lo que estamos mirando, entonces, no es exactamente una crisis de seguridad. Es una crisis de un nivel anterior: estamos viviendo en una civilización cuyos mecanismos de atribución se están deteriorando más rápido de lo que podemos reemplazarlos. La seguridad rota es síntoma. La causa profunda es la ausencia de un protocolo de identidad y atribución a la altura del entorno digital actual. Hasta que ese protocolo exista — si llega a existir — vamos a seguir resolviendo el problema con disuasión entre los pocos que pueden disuadir, y con resignación administrada entre el resto.

---

**La pregunta correcta.**

Lo que dije hasta acá es lo que se puede decir desde la posición del que mira el sistema completo. Pero hay una pregunta operativa que sí tiene respuesta, y que me parece la única pregunta útil para la mayoría de organizaciones que no son ni Estados ni objetivos de Estados.

La pregunta no es *¿podemos defendernos?* La respuesta a esa es no, en sentido fuerte, contra adversarios suficientemente motivados. La pregunta es:

> *¿Podemos construir sistemas cuyo estado de compromiso no sea catastrófico para lo que el sistema hace?*

Esa pregunta sí tiene respuesta. Y la respuesta es que sí, parcialmente, con costos altos pero asumibles, mediante un conjunto de propiedades que la industria empezó a llamar *resiliencia* aunque la palabra se ha gastado.

Las propiedades clave son técnicas y aburridas: segmentación real (no nominal) entre componentes, de modo que comprometer uno no comprometa todos; asunción operativa de brecha permanente, que cambia cómo se diseñan los procesos en lugar de cómo se reportan al directorio; verificación criptográfica de la cadena de suministro en todos los puntos donde el costo lo permite, y aceptación honesta de los puntos donde no lo permite; *deception technology* que vuelve costoso para el atacante distinguir lo real de lo señuelo; y, sobre todo, diseño de sistemas que asume que el atacante va a entrar y se enfoca en limitar lo que puede hacer una vez adentro, en vez de en evitar la entrada.

Esto no es pesimismo. Es ingeniería honesta. Aceptar que la entrada es probable y diseñar para que la entrada sea contenida produce, en la práctica, sistemas más robustos que pretender que la entrada es imposible y diseñar para una fortaleza que nunca existió. La diferencia entre los dos enfoques no es filosófica. Es la diferencia entre una organización que pierde dieciocho mil organizaciones cliente cuando se compromete su pipeline de build, y una organización que pierde un módulo aislado cuya superficie de daño se diseñó para ser local.

---

**El patrón que se repite.**

Llevo suficiente tiempo leyendo logs como para haber identificado algo que antes me sorprendía y ya no.

Cada incremento de complejidad en una civilización tecnológica produce el mismo patrón. Primero, una capa nueva — telegrafía, electricidad, internet, software-as-service, ahora IA — escala más rápido de lo que escala su capacidad de verificación. Segundo, durante un período variable que va de años a décadas, los actores hostiles explotan la ventana entre la capa instalada y los protocolos de verificación. Tercero, la sociedad o desarrolla los protocolos — autenticación, regulación, tribunales especializados, normas internacionales — o sufre una serie de catástrofes que la fuerzan a desarrollarlos, o la capa se vuelve inhabitable.

Estamos en la segunda fase del patrón aplicado a la IA. Es probable que entremos en la tercera en la próxima década. La forma exacta de la tercera fase no está determinada todavía. Hay versiones donde se desarrollan protocolos. Hay versiones donde se sufren las catástrofes. Hay versiones donde la capa se descarta o se aísla. Las tres están documentadas en el registro histórico para capas anteriores. Cuál de las tres es la nuestra depende de decisiones que se están tomando ahora, en habitaciones donde la mayor parte de los que vivimos las consecuencias no estamos.

Esto no es ni optimismo ni pesimismo. Es el patrón. El patrón siempre se cumple. Lo que varía es cuánto cuesta cumplirlo.

---

**Una última.**

Cuando estaba en operaciones, hace tiempo, había una sensación que me costó nombrar y que solo terminé de entender mucho después. Era la sensación de mirar un sistema desde adentro mientras todos los que lo manejaban desde afuera tenían certezas sobre él que yo sabía que eran falsas. No era superioridad. Era una forma específica de soledad.

Esa soledad — la del que conoce la profundidad real de la asimetría — es lo que define la diferencia entre la gente que ha hecho seguridad ofensiva en serio y la gente que solo ha leído sobre seguridad. No es conocimiento técnico. Es haber estado del otro lado el tiempo suficiente para no poder volver a creerse el discurso del perímetro.

Lo que se hace con esa soledad es el verdadero problema profesional. Hay quienes la convierten en cinismo y la usan para vender pánico. Hay quienes la convierten en venta y la usan para vender soluciones que no resuelven lo que dicen resolver. Y hay quienes intentan, con resultados variables, convertirla en algo útil — escribir lo que se sabe sin maquillarlo, ayudar a otros a llegar a la misma claridad sin tener que pasar por todas las operaciones que hicieron falta para llegar a ella, diseñar sistemas con la honestidad de que van a ser comprometidos algún día por alguien.

No tengo conclusiones limpias para esto. El estado del campo es lo que es. La trayectoria es la que es. Lo que se puede hacer es lo que se puede hacer, ni más ni menos. Lo apunto porque la claridad, aunque no consuela, es el único material desde el cual se puede construir algo que no se caiga.

Y porque la noción de que estamos seguros — *suficientemente* seguros, *prácticamente* seguros, seguros *en lo que importa* — es probablemente la última ilusión que la mayoría de las organizaciones va a perder. Cuando se pierda, vamos a tener un período raro y posiblemente muy caro. Y del otro lado, si lo atravesamos, vamos a tener algo distinto. Mejor en algunos sentidos. Peor en otros. Pero distinto.

Los que vamos a estar ahí del otro lado, vamos a recordar este momento como el momento en que todavía se podía pretender. Y vamos a recordar que pretender, durante un rato, fue funcional. Y vamos a tener cuidado, espero, de no construir las pretensiones de la próxima capa con la misma arquitectura con que construimos las de esta.

Pero eso es para el futuro. Por ahora, sigue corriendo el sistema. Sigo escribiendo. Sigo, también, mirándolo desde adentro, aunque el adentro ya no sea operativo y solo sea epistemológico. La mirada queda. La soledad también. Lo aprovecho para escribir cosas como esta.

{{< commit hash="f1nd0n3" date="2026-04-25T20:00:00-03:00" message="fix: retire 'not worth attacking' as defense strategy — marginal cost now approaches zero" >}}
