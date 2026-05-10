---
title: "La guerra que no se declara"
summary: "Sobre el objetivo real del conflicto digital y dónde termina lo que llamamos seguridad"
date: 2026-05-10
draft: false
tags: ["ciberguerra", "supply-chain", "confianza", "ensayo"]
---

{{< listening track="Holy Wars... The Punishment Is Due" artist="Megadeth" album="Rust in Peace" >}}

Hay una pregunta que casi nunca se hace en serio en este oficio, y que es la única que importa: *¿para qué sirve la ciberguerra?* No técnicamente — eso se contesta con manuales de operaciones — sino estratégicamente, civilizatoriamente. ¿Cuál es el objetivo real de invertir miles de horas-hombre, millones de dólares y décadas de inteligencia en mantener implantes durmientes en infraestructura ajena que tal vez nunca se activen?

La respuesta corta es: no es lo que parece.

La respuesta larga es lo que voy a tratar de escribir hoy.

---

**El objetivo no es destruir. El objetivo es tener.**

Cuando un Estado mantiene implantes activos en la red eléctrica, el sistema bancario, la cadena de suministro de chips o las comunicaciones militares de otro Estado, casi nunca los usa. No los necesita usar. El implante hace su trabajo por el solo hecho de existir.

Esto es contraintuitivo si uno piensa la guerra cinéticamente. En guerra cinética, un arma sin disparar es un arma desperdiciada — el costo de mantenerla es real, y solo el uso justifica el costo. En guerra digital es exactamente al revés. El implante usado se quema. La detección que sigue al uso clausura el vector. La operación termina y hay que empezar de cero, con nuevos vectores, nuevos arsenales, nuevos meses de paciencia. El implante durmiente, en cambio, se conserva. Y mientras se conserva, hace algo que el implante usado no puede hacer: *condiciona la conducta del adversario sin necesidad de actuar*.

A esto los analistas serios lo llaman *destrucción mutua asegurada digital*. Es la versión cibernética de lo que en guerra fría se llamó MAD nuclear, pero opera con una diferencia importante. La disuasión nuclear funcionaba por la certeza pública del arsenal — los misiles eran fotografiables, contables, contemplables desde un satélite. La disuasión digital funciona, paradójicamente, por la certeza privada y la negabilidad pública. Los implantes son secretos para la población general y conocidos entre las cancillerías. El equilibrio se sostiene en que ambos lados saben que el otro tiene, sin que nadie tenga que admitirlo. Y como nadie lo admite, cuando uno se activa hay una ventana de plausibilidad para negar y otra para responder, y esa ambigüedad es exactamente lo que hace que la disuasión funcione.

El objetivo, entonces, no es destruir infraestructura. El objetivo es poseer la posibilidad de destruirla, y dejar que esa posibilidad — sabida y no dicha — modifique las decisiones políticas, comerciales y militares del otro lado. La ciberguerra no es preparación para la guerra. Es la forma que ha tomado la diplomacia entre potencias en una era donde la guerra abierta entre nucleares es inviable.

Lo cual significa algo incómodo: la ciberguerra no se declara porque nunca se va a declarar. Es la condición permanente, no el evento excepcional.

---

**El espionaje industrial: la otra mitad de la ecuación.**

Si la primera mitad de la operación es preposicionar leverage estratégico, la segunda es algo más mundano y más rentable: robar conocimiento.

Las operaciones de espionaje industrial estatal son, en términos de retorno sobre inversión, posiblemente las más eficientes que ha habido nunca. Por menos de lo que cuesta desarrollar un programa nuclear propio, un Estado puede acceder a décadas de investigación de un competidor, ahorrarse las ramas de desarrollo que ya se sabe que no llevan a ningún lado, copiar los diseños finales, y entrar al mercado o al teatro militar con tecnología equivalente a una fracción del costo.

Esto no es teoría. Es lo que pasó con la transferencia de tecnología de semiconductores hacia ciertos competidores asiáticos. Es lo que pasó con la transferencia de diseños de aeronaves de combate. Es lo que está pasando ahora con investigación farmacéutica, modelos de inteligencia artificial, y técnicas de manufactura avanzada. El cálculo es brutal: la inversión en operaciones cibernéticas de espionaje industrial se amortiza en años, no en décadas, y produce ventajas competitivas que el mercado no podría haber generado en el mismo período.

A los efectos de un observador detenido, la ciberguerra tiene entonces dos caras simultáneas. La cara visible — implantes, sabotajes, ataques de ransomware atribuibles — es el teatro estratégico. La cara invisible — espionaje continuo, copia silenciosa de propiedad intelectual, mapeo de redes corporativas — es la operación económica. Ambas dependen del mismo arsenal, los mismos operadores, las mismas técnicas. Pero sirven a objetivos distintos, y entender la diferencia es importante porque la defensa contra una no es la defensa contra la otra.

---

**Catorce meses adentro.**

Hay un caso que se ha vuelto canónico y que vale la pena mirar despacio, porque concentra en un solo evento todas las propiedades estructurales del problema.

En septiembre de 2019, un grupo de operadores que más tarde se atribuiría al Servicio de Inteligencia Exterior ruso accedió por primera vez al entorno de desarrollo de SolarWinds, una empresa de software de monitoreo de red usada por aproximadamente trescientas mil organizaciones en el mundo, incluyendo agencias federales estadounidenses y varias de las empresas más grandes del planeta. No hicieron nada destructivo en esa primera entrada. Probaron si podían insertar código en el pipeline de compilación. La prueba salió bien. La replicaron meses después con el código real.

En febrero de 2020 desplegaron SUNBURST: aproximadamente cuatro mil líneas de código malicioso insertadas en una DLL legítima de la plataforma Orion, firmada con los certificados digitales legítimos de SolarWinds. Entre marzo y junio, esa actualización envenenada se distribuyó a unas dieciocho mil organizaciones que la instalaron como instalan todas sus actualizaciones — con un clic, sin sospecha, porque la firma era correcta y la fuente era confiable.

SUNBURST permanecía dormido catorce días después de la instalación. Después empezaba a hacer beacon usando consultas DNS disfrazadas como tráfico legítimo de la telemetría de Orion. Los subdominios consultados eran generados algorítmicamente y codificaban, dentro de la consulta, el dominio de Active Directory de la víctima — de modo que los operadores podían identificar exactamente qué red había sido infectada y decidir si merecía atención. Si la red no era interesante, le ordenaban al malware que se autodestruyera. Si lo era, descargaban un dropper de segunda etapa y empezaban el trabajo real.

De las dieciocho mil organizaciones infectadas, los operadores eligieron entrar activamente en aproximadamente cincuenta. El resto era cobertura — campo de camuflaje masivo para esconder a los blancos reales entre las víctimas accesorias. Entre los blancos reales había departamentos del gobierno estadounidense, empresas tecnológicas críticas, y una empresa de seguridad llamada FireEye que tenía la mala suerte de ser exactamente el tipo de empresa que podía descubrir lo que estaba pasando.

La operación duró catorce meses sin detección. Se descubrió por accidente. Un empleado de seguridad de FireEye notó que un nuevo dispositivo se había registrado en la cuenta de un empleado para la autenticación de dos factores. El empleado no había registrado ese dispositivo. Esa alerta — clasificada inicialmente como severidad cero, lo mínimo posible — fue la única hebra que, tirada hasta el final, desenrolló toda la operación.

Si no hubiera sido por esa registracion de MFA — un detalle minúsculo notado por un humano atento — la operación habría continuado. Los rusos siguen, casi seguro, dentro de otras cadenas de suministro que todavía no se descubrieron. SolarWinds es el caso que conocemos. Es el único caso de toda una clase de eventos cuya frecuencia real es desconocida y, estructuralmente, desconocible.

---

**Lo que SolarWinds enseña que casi nadie quiere aceptar.**

La lección obvia es técnica: hay que verificar la cadena de suministro, implementar Zero Trust, hacer threat hunting proactivo, asumir compromiso. Todo eso es correcto y todo eso está documentado en el mejor material técnico que se ha producido sobre el tema. No voy a repetirlo aquí porque ya está repetido en mil lados.

La lección menos obvia, y más importante, es esta: **la vulnerabilidad no estaba en el código de SolarWinds. Estaba en la confianza que dieciocho mil organizaciones depositaban en SolarWinds.**

Esto parece una distinción retórica y no lo es. Una vulnerabilidad en el código es algo que se parchea. Una vulnerabilidad en la topología de confianza es algo que solo se cierra cambiando cómo se construye software, cómo se distribuye, cómo se verifica, y cómo se reparte el privilegio entre las miles de partes que hoy participan en producir el stack tecnológico de cualquier organización moderna.

La superficie de ataque, en este modelo, no es perimetral. No tiene firewall. No tiene dirección IP. La superficie de ataque es el grafo de relaciones de confianza que tu organización ha tejido — con tus proveedores, con los proveedores de tus proveedores, con los mantenedores de las bibliotecas open source que tus desarrolladores importan sin pensar, con los servicios SaaS a los que diste tokens OAuth hace cuatro años, con los sistemas que firman tus binarios, con los repositorios desde donde bajás tus dependencias.

Ese grafo no es técnico en sentido estricto. Es sociopolítico-económico. Es el tejido de la economía digital moderna. Y como cualquier tejido construido por millones de actores sin un plan central, tiene puntos débiles que ningún auditor individual puede mapear completamente. Es estructural. No es bug.

Lo que hicieron los rusos con SolarWinds — lo que después hicieron otros con XZ Utils, con CCleaner, con Axios, con cada cadena de suministro que vamos descubriendo después del hecho — no fue *explotar* la confianza. Fue *aprovechar* una propiedad estructural del sistema económico de producción de software. Es como si alguien me dijera que es un atacante muy hábil porque sabe respirar el aire que está ahí.

---

**El humano como vector: cuando los sistemas se endurecen, los atacantes bajan.**

Cuando los sistemas se vuelven difíciles de atacar técnicamente, los atacantes no se rinden. Se mueven hacia abajo, a la capa que sigue siendo blanda. Y la capa que sigue siendo blanda — siempre, en todos los casos — es la humana.

El caso de XZ Utils ilustra esto con una claridad casi pedagógica. XZ es una biblioteca de compresión que se ejecuta en, literalmente, cientos de millones de servidores Linux en el mundo. Está mantenida, como muchas bibliotecas críticas del ecosistema open source, por una persona — un mantenedor solitario, no remunerado, que la sostiene como pasatiempo o como deber autoasignado, sin que ninguna institución se haya hecho cargo de proveerle apoyo proporcional al impacto que su trabajo tiene en la infraestructura global.

Un atacante — atribuido tentativamente a un servicio de inteligencia estatal, sin atribución definitiva pública — pasó aproximadamente dos años haciendo ingeniería social contra ese mantenedor. No le hackeó la máquina. No le robó las credenciales. Le ganó la confianza. Empezó a contribuir parches útiles. Empezó a ayudar con el mantenimiento. Empezó a ser, para el mantenedor agotado, exactamente el tipo de ayudante voluntario que cualquier proyecto open source agradece sin reservas. Después de dos años de generar capital social legítimo, el atacante tenía permisos de commit sobre el código fuente. Y entonces insertó un backdoor en un upstream que se habría propagado a millones de servidores.

Lo detectaron por casualidad — un ingeniero de Microsoft notó una anomalía de medio segundo en el rendimiento de SSH durante un benchmark. Una anomalía de rendimiento. Casi nada. Si ese ingeniero hubiera estado un poco más ocupado, o un poco menos curioso, ese backdoor estaría hoy ejecutándose en producción en buena parte de la internet.

La parte técnica del ataque XZ era modesta. La parte social era extraordinaria. Y la parte social no se defiende con un firewall, con un EDR, con threat hunting, con detección por comportamiento, con ningún producto que se pueda vender. Se defiende, si se defiende, con cosas que no pertenecen al dominio de la ciberseguridad: con políticas de gobernanza open source que el mundo todavía no construyó, con redundancia humana en el mantenimiento de software crítico que ningún Estado ha pagado, con reconocimiento de que las bibliotecas que sostienen la infraestructura global no pueden depender de un solo mantenedor agotado al que cualquier extraño persistente puede ganarse la voluntad.

XZ no es un problema de ciberseguridad. Es un problema de cómo el mundo decide pagar — y no paga — el mantenimiento del software del que depende para todo.

---

**El operador disciplinado.**

Hay un detalle del caso SolarWinds que me obsesiona y que quiero tratar con cuidado, porque dice algo sobre la naturaleza del adversario moderno que casi nunca se dice bien.

Los atacantes, una vez dentro de las redes objetivo, no usaron un backdoor universal tipo llave maestra. No usaron exploits ruidosos. No movieron lateralmente con herramientas conocidas. Usaron, en cada sistema al que accedieron, credenciales específicas y correctas para ese sistema. Robaron usuarios y contraseñas reales y se autenticaron como esos usuarios. Su tráfico, desde la perspectiva del defensor, era indistinguible del tráfico legítimo. No porque lo disfrazaran. Porque *era* legítimo, en todos los sentidos operativos relevantes excepto que la persona que estaba operando la cuenta no era la persona a la que la cuenta pertenecía.

Esto es operación de inteligencia, no hacking. Es la diferencia entre el ladrón que rompe la ventana y el ladrón que tiene la llave porque copió la del dueño mientras él dormía. Los dos entran. Solo el segundo entra de manera indistinguible del dueño.

Mandia, el CEO de FireEye que descubrió todo esto, dijo una frase que vale la pena considerar: *esto no fue un tiroteo al azar en la autopista. Fue un disparo de francotirador desde kilómetro y medio*. La metáfora es precisa. Los adversarios estatales maduros no operan en el modo en que los productos de ciberseguridad asumen que opera un atacante. Operan en un modo que se parece más al espionaje clásico — paciencia, disciplina, uso de la identidad de la víctima en lugar de ataque a la identidad de la víctima, evitación cuidadosa de cualquier comportamiento anómalo, autodestrucción del implante si la red no resulta interesante.

Contra ese tipo de operador, la pregunta de si tu EDR detecta o no detecta es secundaria. Tu EDR está mirando comportamientos anómalos. El comportamiento de este operador no es anómalo. Es perfectamente normal. Es, en algún sentido fuerte, *más* normal que el comportamiento de tus propios usuarios legítimos, que cometen errores, que abren correos sospechosos, que descargan cosas raras, que generan toda la fricción operativa que el ML de tu EDR está entrenado para tolerar como base de normalidad.

El operador disciplinado se esconde en el centro de tu distribución de comportamientos, no en la cola. Y nada de lo que tenés instalado está mirando el centro.

---

**¿Y entonces dónde termina la ciberseguridad?**

Acá llego a la pregunta que planteás y que es, en mi opinión, la pregunta más importante que el campo no se está haciendo en voz alta.

La ciberseguridad como disciplina nació con un mandato relativamente claro: proteger sistemas de información de accesos no autorizados, garantizar integridad de datos, sostener disponibilidad. Esa es la tríada CIA — *confidentiality, integrity, availability* — que cualquier estudiante de seguridad puede recitar. Es una buena tríada. Sigue siendo útil. Y es completamente insuficiente para describir lo que se le pide hoy a un equipo de seguridad maduro.

Lo que se le pide hoy a ese equipo, en la práctica, incluye: gobernanza de vendors (que es una función de procurement y legal); revisión de contratos con cláusulas de seguridad (que es función legal); educación de usuarios contra ingeniería social (que es función de RRHH y cultura organizacional); evaluación de riesgo geopolítico de proveedores (que es función de relaciones exteriores corporativas); auditoría de cumplimiento regulatorio (que es función de compliance); respuesta a incidentes que involucran comunicación pública (que es función de relaciones institucionales); investigación de personal interno potencialmente comprometido (que es función de seguridad física y RRHH); y, cada vez más, evaluación de la legitimidad de la cadena de suministro completa de software, incluyendo los repositorios open source de los que dependen las dependencias de tus dependencias (que es, técnicamente, una función que no tiene nombre porque la sociedad no la ha inventado todavía).

La ciberseguridad ha absorbido, por defecto, responsabilidades que no son suyas en sentido propio. Lo ha hecho porque nadie más las quería, porque eran responsabilidades nuevas que ninguna disciplina existente cubría, porque el incentivo del CISO es asegurarse de no ser culpado, y porque el equipo técnico era el único que entendía lo suficiente como para empezar a hacer algo. Pero el resultado es que el límite operativo de la ciberseguridad hoy es difuso, expandido y sobrecargado, y la persona en la silla del CISO está haciendo un trabajo que no se parece al trabajo para el que se formó.

¿Dónde *debería* terminar la ciberseguridad? Mi posición es la siguiente: la ciberseguridad debería terminar exactamente donde terminan los sistemas técnicos sobre los que tiene autoridad operativa real. Más allá de eso — gobernanza, cultura, geopolítica, regulación, gestión de la confianza institucional — son problemas que requieren autoridades, mandatos y disciplinas propias, y que la sociedad todavía no ha construido.

El problema es que mientras la sociedad no construye esas otras disciplinas, *alguien tiene que hacer ese trabajo*. Y la realidad práctica es que ese alguien va a seguir siendo el equipo de seguridad, con el manual operativo equivocado y los presupuestos equivocados, hasta que la presión sea tan grande que el resto de la organización admita que el problema es de la organización entera y no solo del departamento técnico.

---

**Sistemas o humanos.**

La pregunta de si el problema es de sistemas o de individuos es, en mi experiencia, mal planteada. No es ni una cosa ni la otra. Es un problema de las propiedades emergentes de un sistema sociotécnico donde sistemas e individuos están entrelazados de manera inseparable.

Pero si tuviera que pesarlo, diría que el peso ha estado, durante mucho tiempo, en la columna técnica, y que esa asignación de peso ya no es defendible.

Los sistemas técnicos se pueden endurecer. Hemos pasado treinta años endureciendo sistemas técnicos y los resultados son visibles — el atacante promedio de hoy se encuentra con un entorno significativamente más hostil que el de mil novecientos noventa y cinco. Eso es real y eso vale.

Pero el endurecimiento técnico empuja al atacante hacia la capa humana, que no se ha endurecido en la misma proporción. Esa capa humana incluye desde el usuario que hace clic en un enlace hasta el mantenedor agotado de una biblioteca open source crítica, desde la persona en RRHH que valida currículums sin verificar referencias hasta el ejecutivo que toma decisiones de compra de software basándose en una demo de cuarenta minutos. Todos esos son puntos donde la operación moderna de ataque entra, y casi ninguno de esos puntos tiene defensas comparables a las que tiene un servidor moderno.

El cambio que se necesita es cultural, organizacional y económico antes que técnico. La ciberseguridad puede ayudar a articular lo que se necesita, puede señalar dónde están los puntos críticos, puede proveer detección y respuesta cuando las cosas fallan. Pero no puede, sola, resolver un problema que es estructural a cómo construimos confianza en sociedades complejas.

---

**Una observación final desde el otro lado.**

Cuando uno ha operado, en algún momento de su vida, del lado del atacante — sea como red teamer pagado o en circunstancias menos formales — hay una sensación que no se olvida y que conviene nombrar.

Es la sensación de estar adentro de un sistema que cree que no estás. Toda la conversación pública sobre ciberseguridad, todas las certificaciones, todas las inversiones, todos los productos vendidos en RSA Conference, parten del supuesto implícito de que el defensor sabe cuándo está siendo atacado. Esa premisa es falsa. La premisa correcta es que el defensor sabe cuándo está siendo atacado *torpemente*. Los ataques sofisticados están dentro y se quedan dentro hasta que un detalle minúsculo, casi siempre humano, casi siempre por casualidad, abre una grieta por la que se ve algo.

SolarWinds estuvo catorce meses sin ser detectado. XZ Utils estuvo dos años infiltrándose. Stuxnet operó años antes de ser identificado. No sabemos cuánto duran las operaciones que todavía no se descubrieron — por definición, no sabemos.

Esto no debería leerse como pesimismo. Es la condición operativa real del campo, y aceptarla es la precondición para hacer un trabajo honesto. Pretender lo contrario — pretender que con suficiente inversión se puede llegar a un estado de seguridad estable contra adversarios estatales maduros — es lo que produce los presupuestos infinitos sin resultados proporcionales que han caracterizado al sector durante dos décadas.

La pregunta práctica, entonces, no es *cómo evitar la brecha*. Es *cómo construir sistemas cuya brecha eventual no sea catastrófica para lo que el sistema hace*. Esa pregunta tiene respuestas. No son cómodas, requieren reescribir buena parte de cómo se diseñan las organizaciones modernas, y son las únicas respuestas que sobreviven al contacto con la realidad operativa.

---

**Lo que queda por escribir.**

No tengo conclusión limpia para esto. El campo está en un punto de transición y casi nadie sabe hacia dónde. Hay tres trayectorias posibles que veo, sin certeza sobre cuál se va a realizar:

La primera es que la sociedad construya las disciplinas que hoy faltan — gobernanza de software open source, regulación efectiva de la cadena de suministro tecnológica, normas internacionales con dientes para la ciberguerra, mecanismos de atribución técnicamente robustos — y que la ciberseguridad se contraiga hacia su mandato original, dejando el resto a otros.

La segunda es que la presión técnica supere la capacidad humana de gobernanza y que se sufra una serie de catástrofes — colapsos de cadena de suministro a gran escala, ataques sincronizados a infraestructura crítica, fracturas de la confianza digital tan severas que la economía digital deje de funcionar en su forma actual.

La tercera es que se desarrollen capacidades defensivas basadas en IA con suficiente velocidad como para mantener una paridad asimétrica con las capacidades ofensivas que también están desarrollando IA, y que el conflicto digital se asiente en una nueva forma de equilibrio dinámico cuya geometría todavía no podemos imaginar bien.

Las tres están abiertas. Probablemente lo que ocurra sea una combinación de las tres en proporciones que dependerán de decisiones políticas que se están tomando ahora, en habitaciones a las que la mayor parte de los que vamos a vivir las consecuencias no tenemos acceso.

Mi trabajo, mientras tanto, sigue siendo el que era. Leer logs. Cazar señales. Diseñar sistemas con la honestidad de que van a ser comprometidos. Escribir cosas como esta, que no resuelven nada pero al menos no contribuyen al ruido del optimismo profesional. Y sostener, todos los días, la disciplina mental de no creer las certezas que mi industria vende y que mis colegas, muchos de ellos, han comprado.

La guerra que no se declara sigue. Va a seguir mientras existan Estados con capacidad ofensiva asimétrica, infraestructura digital crítica para la vida cotidiana, y la geometría actual de incentivos económicos y políticos que premia el ataque y subsidia mal la defensa.

No nos vamos a librar de ella. Lo que podemos hacer — lo único — es operar con los ojos abiertos, no pretender que el problema es más simple de lo que es, y reconocer dónde termina nuestra parte del trabajo y empieza el trabajo de otros que todavía no se ha empezado.

Eso es todo lo que tengo. Es menos de lo que se necesita. Es más de lo que se admite. Sigo escribiendo.

{{< commit hash="h0lyw4r5" date="2026-05-10T20:00:00-03:00" message="fix: replace assumed security with operational honesty — perimeter model deprecated, adversary already inside" >}}
