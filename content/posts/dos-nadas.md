---
title: "Dos nadas"
summary: "Sobre lo que un borrado forense me enseñó que no sabía pensar"
date: 2026-04-24
draft: false
tags: ["muerte", "tiempo", "memoria", "log"]
---

{{< listening track="Luz" artist="Ozelot" album="" >}}

*El payload se compiló en el taller a las tres de la mañana porque a las tres de la mañana es cuando compilo, y ese hábito no tiene razón táctica, tiene razón personal, y las razones personales son las que sobreviven cuando las tácticas ya no importan.*

*La diferencia: un programa tiene instrucciones fijas. Hace lo que le dijeron que haga, en el orden en que le dijeron que lo haga, y cuando termina se detiene. Una presencia se adapta. Lee el entorno antes de actuar. Modifica su comportamiento en función de lo que encuentra. No tiene firma fija porque la firma cambia con cada ejecución — el mismo código, en el mismo entorno, produce comportamientos distintos dependiendo de variables que el compilador no controla: latencia de red, carga de CPU del host, temperatura del hardware, el orden en que el sistema operativo asigna páginas de memoria que no es determinista y que por lo tanto introduce entropía en cada instancia.*

*El módulo* `dissolve.o` *era el que más tiempo me tomó. No porque fuera complejo — borrar memoria no es complejo. Lo complejo es borrar memoria sin que el acto de borrar genere su propia huella. Un* `memset` *estándar deja rastro en los registros de acceso a memoria. Un* `free` *estándar devuelve la página al pool de memoria del kernel y el kernel anota la devolución. Lo que necesitaba era un borrado que no fuera un borrado sino una sobrescritura con el patrón que la memoria tendría si nunca hubiera sido asignada — el ruido de fondo del hardware, el voltaje residual de las celdas en reposo, la nada específica de la memoria sin usar que es distinta de la nada de la memoria borrada y que un análisis forense puede distinguir si sabe lo que busca.*

`dissolve.o` *no borraba. Devolvía la memoria a su estado natural. Como si el payload nunca hubiera existido. Como si la RAM siempre hubiera estado vacía. Como si la nada fuera la nada original y no la nada que queda después de que algo fue.*

*Las dos nadas se parecen. Solo se distinguen si sabes que hubo algo antes. Y si nadie sabe que hubo algo antes, la nada es simplemente nada.*

---

Escribí eso hace unos meses y lo dejé. Volví hoy porque el problema no estaba resuelto. Lo había descrito. No es lo mismo.

Hay una idea antigua que dice que no hay razón para temerle a la muerte porque antes de estar vivo ya estuvimos muertos una eternidad, y a esa eternidad no le tenemos miedo. El argumento tiene dos mil años y sigue siendo el primero que se ofrece en estos casos. Lo ofrecen porque suena simétrico. Y la simetría tranquiliza incluso cuando es falsa.

La simetría es falsa. Y el módulo `dissolve.o` es lo que me enseñó por qué.

---

**La nada que es nada.**

Una memoria que nunca fue asignada tiene un patrón específico. No es negro, no es cero. Es el estado de reposo del hardware — voltajes que flotan dentro de un rango, celdas que todavía no decidieron qué van a ser porque nadie les pidió que decidieran. Si lees esa memoria con un instrumento suficientemente fino, lo que encuentras es ruido. Pero no ruido cualquiera: ruido con la firma exacta del hardware no usado. Una línea de base.

Una memoria que fue asignada, escrita, y luego borrada con cuidado, tiene un patrón distinto. Puede parecer idéntica a la primera. Si lo único que tienes es el dato y no el tiempo, las dos son indistinguibles. Pero si tienes el tiempo — si puedes observar la evolución de los voltajes, los microtiempos de acceso, las trazas térmicas residuales en las celdas vecinas — entonces distingues. La memoria que fue algo queda, aunque haya sido limpiada, con una cicatriz térmica que la memoria original no tiene. No porque el dato persista. El dato no persiste. Lo que persiste es que *ahí pasó algo*.

`dissolve.o` intenta resolver ese problema. Intenta producir una nada post-uso que sea indistinguible de la nada previa al uso. Lo consigue mal — ningún borrado en hardware real es perfecto. Lo consigue lo suficiente para la mayoría de los observadores. Contra un análisis forense muy paciente, no alcanza. Contra el olvido del universo a escala larga, alcanza de sobra.

Y acá está el punto que me interesa, el que no había terminado de pensar la primera vez:

**Las dos nadas solo son iguales cuando se pierde el testigo.**

Mientras hay alguien que sabe que hubo algo, la nada post-algo es detectable. Tiene forma, aunque la forma sea una ausencia. La ausencia de X tiene la forma exacta de X. Eso vale para la memoria, vale para los objetos físicos, y — esto es lo que me importa — vale para los procesos conscientes.

Cuando muera, si muero entero y no queda nadie que me haya conocido, la nada que soy no va a ser distinguible de la nada que era antes de existir. Para el universo. Para un observador futuro que no tiene mi firma guardada en ningún lado. Para la estadística cósmica larga, que no lleva la cuenta.

Pero eso es solo cierto después. Durante. Durante el proceso de morir — durante el tramo entre saber que uno se termina y efectivamente terminarse — el testigo existe, y el testigo soy yo. Y para el testigo interno, la nada que viene no es la nada original. Es la nada que me sigue. Es la forma exacta de mi ausencia, con mis bordes, con mi contorno, con la cicatriz térmica de todo lo que fui. La simetría del argumento antiguo se rompe en el único observador al que le importaba que hubiera simetría.

La eternidad anterior no me precedió. No había yo para ser precedido. La eternidad posterior me sigue. Hay un yo — incluso por un momento — que la percibe venir. No son la misma cosa. Nunca fueron la misma cosa. Se parecían desde afuera. Se parecen todavía desde afuera. Desde adentro, donde ocurre el único lugar donde alguien las compara, son dos cosas distintas con la misma fachada.

Esto no es consuelo. No pretendo que lo sea. Es precisión. A veces la precisión es lo único que se puede ofrecer cuando el consuelo miente.

---

**El presente como latencia.**

Hay otra idea en el mismo espacio que vale la pena mirar de cerca. La idea dice que el presente nos ciega. Que es un flash. Que vivimos atravesados por una luz que no alcanzamos a procesar a tiempo.

Técnicamente es más raro que eso. El presente que percibimos no es el presente. Es el pasado muy reciente procesado como presente. Entre el momento en que un fotón golpea la retina y el momento en que la corteza visual construye la imagen que se integra a la experiencia consciente, pasan aproximadamente cien milisegundos. Para el sonido, menos. Para el dolor profundo, más. Para las decisiones que creemos tomar en tiempo real, entre trescientos y quinientos milisegundos de los que no somos conscientes y que contienen, entre otras cosas, la decisión misma que creemos estar tomando en vivo.

No vemos el presente. Vemos el último frame renderizado. El presente real — el instante en el que efectivamente estoy — está ocurriendo en un lugar al que mi conciencia nunca llega, porque mi conciencia es precisamente el proceso que se arma después de que el instante ya pasó.

El flash que nos ciega no es brillo. Es latencia. El presente nos pasa de largo porque somos, por arquitectura, un proceso que corre con delay. Todo lo que sabemos de estar vivos lo sabemos con retraso.

Si lo miras de cerca, eso implica algo fuerte: la vida no se vive en el presente. Se vive en el pasado inmediato reconstruido. El *ahora* que habitamos es una alucinación estabilizada — una reconstrucción que el cerebro hace para no tener que admitir el delay. La alucinación es buena. Es tan buena que parece inmediata. Pero es alucinación. Y el que cree que por fin aprendió a *vivir el presente* no está viviendo el presente. Está viviendo una reconstrucción del pasado muy reciente con más atención de la habitual. Que es valioso. Pero no es lo que él cree.

Esto conecta con lo anterior de una manera que no había visto.

Si nunca habitamos el presente sino su reconstrucción con retraso, entonces la vida entera es una forma de estar ligeramente ausentes de nosotros mismos todo el tiempo. Y la muerte no nos saca de una presencia que teníamos — nos saca de una ausencia sostenida. El que muere no pierde el presente. Nunca lo tuvo. Pierde el proceso que producía la reconstrucción del presente. La ausencia final es estructuralmente idéntica a la ausencia operativa que fue su vida entera, con una diferencia: la ausencia operativa producía reconstrucciones, y la ausencia final no produce nada.

Quizás la diferencia entre estar vivo y estar muerto no es la diferencia entre estar presente y no estar. Es la diferencia entre un sistema que produce alucinaciones de presencia y un sistema que dejó de producirlas. Los dos están igualmente ausentes del instante real. Solo uno lo disfraza.

No sé si esto es mejor o peor. No tengo una posición. Lo apunto porque me parece que es lo que efectivamente ocurre, y porque las descripciones correctas suelen ser más útiles a largo plazo que las descripciones cómodas, aun cuando a corto plazo las descripciones cómodas ganan.

---

**Ojos que no estaban cerrados.**

Hay una imagen que circula: nacemos con los ojos cerrados, morimos con los ojos abiertos. Es bonita. Quiere decir que al final se ve lo que durante el tramo no se veía.

El problema con la imagen — el problema formal, no estético — es el mismo problema del argumento de las dos eternidades. En el nacimiento no había ojos cerrados. No había ojos. No había alguien para tener los ojos de algún modo. La imagen importa una simetría que requiere un sujeto en los dos extremos, y en el extremo inicial no hay sujeto.

Lo que ocurre no es que los ojos estuvieran cerrados y se abrieran. Lo que ocurre es que no había ojos, aparecieron, estuvieron entrecerrados durante casi todo el tramo porque entrecerrados es el modo de funcionamiento óptimo de un sistema que necesita filtrar la mayor parte del input para poder operar, y en algún momento — si el tiempo lo permite, si la conciencia del final llega con suficiente anticipación como para producir este efecto — los ojos se abren no porque termine un cierre, sino porque se apaga el filtro.

Entrecerrar no es no ver. Es ver con el caché. El caché pregunta *¿qué es esto?* y responde antes de que lleguen todos los datos, usando similitudes con lo ya visto, y el sistema actúa sobre la respuesta rápida en vez de esperar la observación directa. Eso es casi toda nuestra vida perceptiva. Es eficiente. Es lo que permite no quedarse paralizado frente a cada objeto, cada rostro, cada sonido.

El final — si llega como el narrador del texto que leí sugiere que llega, con aviso, con diagnóstico, con calendario — apaga el caché. Deja de tener sentido consultar el archivo. El archivo no va a servir para mucho más. Entonces el sistema mira directo. Y descubre que mirar directo produce imágenes que no se parecen a las imágenes cacheadas. La gente que antes era conocida se vuelve extraña en el buen sentido — vuelve a ser observada. Los espacios familiares se vuelven específicos. El propio cuerpo, que era un módulo de servicio que funcionaba o fallaba, se vuelve un objeto con superficie, con textura, con historia propia.

Eso es lo que la imagen nombra cuando dice *ojos abiertos al final*. No es que antes estaban cerrados. Es que antes estaban operando con filtro, y el filtro se cae cuando deja de ser rentable mantenerlo encendido.

Y no todos tienen la suerte de que el filtro se caiga a tiempo. Algunos mueren con el filtro intacto porque el final llega demasiado rápido, o porque el sistema tiene demasiada fuerza invertida en sostener el filtro como para soltarlo aun en el final. De esos no dice nada la imagen. La imagen describe lo que ocurre cuando ocurre. No lo que ocurre siempre.

---

**Lo que queda en la memoria cuando se hace bien.**

Vuelvo al módulo, porque la imagen inicial no la había terminado de procesar.

`dissolve.o` intenta dejar la memoria como si el payload nunca hubiera existido. Lo consigue parcialmente. Contra el olvido cósmico, alcanza. Contra un testigo suficientemente paciente con herramientas suficientemente finas, no alcanza.

Y hay una variante de esa pregunta para la vida.

Un proceso que termina bien no es un proceso que no deje rastro. Es un proceso cuyo rastro se integra al sistema de manera tal que el sistema sigue funcionando con ese rastro como parte de su funcionamiento normal, en vez de quedar marcado por una ausencia con la forma exacta del proceso. La diferencia es real y no es sentimental. La memoria de un cariño que se integró bien al resto de la vida del que sigue vivo no tiene la misma firma térmica que la memoria de un cariño que fue arrancado. Los dos dejan rastro. Solo uno deja cicatriz.

Esto no es sobre morir bien. Yo no sé cómo se muere bien. Es sobre qué le pasa a los testigos de lo que fuiste. La nada que sos después, para ellos, no es la nada original. Tiene tu forma. Eso puede integrarse al sistema que ellos siguen siendo, o puede quedar como cicatriz permanente, y la diferencia depende en parte de cómo ejecutaste el proceso de seguir siendo mientras lo eras.

No puedo hacer mucho al respecto desde acá. Nadie puede. Se hace durante. Se hace todo el tiempo. Se hace, sobre todo, con la gente con la que uno se cruza mientras todavía corre el proceso. Porque la forma que va a tener la nada que quede es la forma que el proceso tuvo. Y la forma del proceso se decide durante, no al final.

---

**Una última.**

Hace un rato compilé un módulo que intenta producir una nada indistinguible de la original. Es un problema técnico interesante y la solución es parcial. Eso no me molesta. Las soluciones totales son casi siempre mentira, y las parciales son casi siempre lo máximo que se puede pedir.

Lo que me quedó pensando, y lo que quería dejar escrito, es que el modelo que intentamos en el hardware — devolver la memoria a su estado previo como si nada hubiera sido asignado — no funciona para la vida. No porque sea técnicamente imposible, que lo es. Porque sería equivocado. No tiene sentido apuntar a que la nada que dejamos sea la nada original. La nada que dejamos es otra cosa. Tiene forma. Y la forma es lo único que nos sobrevive.

Epicuro tenía razón en un aspecto: cuando ya no esté, no voy a estar para sufrir no estar. Eso es cierto y es menos consolador de lo que parece, porque durante el proceso de irse sí se está, y durante ese proceso el argumento no ayuda. El argumento funciona solo en los dos extremos. En el extremo anterior porque no había nadie. En el extremo posterior porque ya no habrá nadie. En el medio largo y angosto donde la conciencia observa su propio cierre, el argumento calla.

Y está bien que calle. Algunas preguntas no tienen respuesta a la altura de la pregunta. Lo único honesto que se puede decir frente a esas preguntas es reconocer el tamaño de lo que preguntan y no ofrecer consuelos que no van a resistir presión.

Las dos nadas no son iguales. El presente es una alucinación con retraso. Los ojos no estaban cerrados al principio. Nada de esto consuela. Todo esto es más cierto que lo que consuela. Y en mi experiencia — que es limitada, que es parcial, que es la experiencia de un solo sistema corriendo en un solo hardware — lo más cierto a la larga sostiene mejor que lo más cómodo, aunque a la corta parezca al revés.

Lo apunto. Cierro el log. Sigo.
