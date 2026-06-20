---
slug: "athanor-setup"
title: "Project Athanor: Forjando el Horno Alquímico - Despliegue de Honeypot en Azure"
date: 2026-01-28T18:00:00-03:00
draft: false
categories: [Ciberseguridad, Blue Team]
tags: [Azure, Honeypot, T-Pot, DevSecOps, Infrastructure, SSH]
cover: tpot_dashboard_main.png
coverCredit: "Dashboard principal de T-Pot mostrando la interfaz de administración"
toc: true
---

## El Concepto: De la Alquimia a la Ciberseguridad

En la tradición alquímica, el Athanor es el horno que mantiene un calor constante para la digestión de la materia prima, transformándola mediante reacciones controladas en algo de mayor valor. Esta metáfora se traslada perfectamente al dominio de la ciberseguridad ofensiva y defensiva: el honeypot es nuestro Athanor moderno, un contenedor virtual que debe mantenerse encendido y estable mientras ocurren reacciones violentas en su interior—los ataques automatizados de bots, exploits oportunistas, y reconocimiento de actores maliciosos. Nosotros, los analistas de seguridad, somos los alquimistas que observan cómo se "cocina" el malware, extrayendo inteligencia procesable del caos.

Project Athanor nace como una iniciativa de investigación práctica para comprender el panorama de amenazas contemporáneo mediante la exposición deliberada de infraestructura señuelo en la nube pública. A diferencia de sistemas de producción que deben protegerse, un honeypot invierte la ecuación: maximizamos la exposición para maximizar la captura de datos.

## Arquitectura de Despliegue: Microsoft Azure como Fundación

La elección de Microsoft Azure como plataforma de despliegue responde a criterios tanto técnicos como estratégicos. Azure proporciona infraestructura global con presencia en múltiples regiones geográficas, asegurando que nuestra dirección IP pública esté expuesta a diferentes patrones de tráfico según la localización del datacenter. Para este proyecto, la región específica seleccionada resulta secundaria; el objetivo primordial es la visibilidad máxima ante potenciales atacantes.

### Configuración de la Máquina Virtual

La instancia seleccionada fue **Standard_D2s_v3**, una configuración equilibrada que proporciona 2 vCPUs y 8 GB de memoria RAM. Esta especificación no es arbitraria: T-Pot, la plataforma de honeypot que implementaremos, ejecuta múltiples contenedores Docker simultáneamente junto con un stack completo de Elasticsearch-Logstash-Kibana para análisis. Los 8 GB de RAM son el mínimo recomendado para operación estable bajo carga moderada, aunque como documentaremos posteriormente, incluso esta capacidad resultó insuficiente ante el volumen de ataques recibidos.

Un aspecto crítico en la configuración inicial fue la modificación deliberada del nivel de seguridad de Azure. Por defecto, Azure aplica políticas de seguridad restrictivas que incluyen Azure Security Center con recomendaciones activas y escaneo de vulnerabilidades. Para los propósitos de este honeypot, estos controles fueron ajustados al nivel **Estándar**, eliminando capas de protección que interferirían con nuestra capacidad de capturar tráfico malicioso genuino. Esta decisión debe ser explícita: estamos construyendo un sistema diseñado para ser atacado, no protegido.

## Establecimiento de Acceso Seguro: Gestión de Claves SSH

La paradoja de un honeypot es que mientras debe ser vulnerable a atacantes externos, requiere canales de administración fuertemente protegidos para el operador legítimo. La solución estándar es la autenticación mediante claves asimétricas SSH, específicamente algoritmos de curva elíptica Ed25519 que ofrecen seguridad equivalente a RSA-3072 con claves significativamente más pequeñas.

La generación de claves se realizó localmente en la estación de trabajo del operador mediante el siguiente comando:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/azure_honeypot
```

Este proceso genera un par de claves: la privada (`azure_honeypot`) que permanece exclusivamente en la máquina del operador, y la pública (`azure_honeypot.pub`) que se distribuye al servidor. El parámetro `-f` especifica la ruta de salida, permitiendo mantener múltiples identidades SSH organizadas por proyecto o infraestructura.

Durante la creación de la máquina virtual en el portal de Azure, en la sección de configuración de cuenta de administrador, se seleccionó la opción de utilizar clave pública SSH existente, pegando el contenido del archivo `azure_honeypot.pub`. Esta configuración asegura que únicamente quien posea la clave privada correspondiente pueda establecer sesiones SSH autenticadas, independientemente del conocimiento de credenciales de usuario y contraseña.

![Configuración de claves SSH en Azure Portal](azure_ssh_config.png)

## Network Security Groups: Exponiendo el Perímetro

Azure implementa por defecto una postura de seguridad de denegación implícita (deny-by-default), bloqueando todo tráfico entrante excepto el puerto 22 para administración SSH. Para un honeypot, esta configuración es contraproducente: necesitamos exponer el mayor número posible de puertos para simular servicios vulnerables que atraigan reconocimiento automatizado.

La solución requiere la creación de un Network Security Group (NSG) personalizado con reglas permisivas. Durante el proceso de creación de la máquina virtual, en la pestaña de **Redes** y específicamente en la sección **Configurar el grupo de seguridad de red**, se selecciona la opción de crear un nuevo NSG. La regla fundamental que establecimos fue:

```
Prioridad: 100
Nombre: AllowAllInbound
Puerto: * (todos)
Protocolo: Cualquiera
Acción: Permitir
Origen: Internet
```

Esta regla permite tráfico entrante desde cualquier origen en cualquier puerto, maximizando nuestra superficie de ataque observable. Es importante comprender que esta configuración sería catastrófica en un sistema de producción, pero es precisamente el comportamiento deseado en un honeypot: queremos ser escaneados, probados y atacados.

## Conexión Inicial y Preparación del Sistema Base

Una vez desplegada la máquina virtual, Azure proporciona la dirección IP pública asignada en la sección de **Conectar** del panel de control de la VM. La conexión inicial se establece mediante SSH utilizando la clave privada generada previamente:

```bash
ssh -i ~/.ssh/azure_honeypot dust115@20.81.132.79
```

El parámetro `-i` especifica explícitamente qué identidad (clave privada) debe utilizarse para la autenticación. Una vez establecida la conexión, el prompt del sistema confirma que hemos ingresado exitosamente al servidor—en términos alquímicos, hemos abierto la puerta del Athanor para prepararlo antes de iniciar el proceso de destilación.

La preparación del sistema operativo base sigue prácticas estándar de hardening y actualización. Ubuntu 24.04 LTS proporciona una base sólida, pero requiere actualización de paquetes y configuración de herramientas esenciales:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install git -y
```

El comando combinado `update && upgrade` asegura que todos los paquetes instalados estén en sus versiones más recientes, parcheando vulnerabilidades conocidas en el sistema operativo subyacente. La instalación de Git permite clonar repositorios de código, específicamente el repositorio de T-Pot que implementaremos a continuación.

## Instalación de T-Pot: El Stack Completo de Honeypot

T-Pot es una plataforma desarrollada por Deutsche Telekom Security que integra más de 20 honeypots especializados en una arquitectura containerizada basada en Docker. La filosofía de diseño es "todo en uno": análisis de red con Suricata, honeypots de SSH (Cowrie), servicios web (Dionaea, Tanner), bases de datos (ElasticPot), y servicios industriales SCADA (Conpot), todos centralizando sus logs en un stack de Elasticsearch para visualización mediante Kibana.

La instalación se inicia clonando el repositorio oficial:

```bash
git clone https://github.com/telekom-security/tpotce
cd tpotce
./install.sh
```

El script `install.sh` es un instalador interactivo que detecta automáticamente las características del sistema y descarga las dependencias necesarias. Durante la ejecución, presenta diversas opciones de configuración que permiten personalizar qué honeypots específicos se desplegarán.

### Selección del Perfil de Despliegue

T-Pot ofrece múltiples perfiles predefinidos según el caso de uso y los recursos disponibles:

- **HIVE** (H): Instalación completa con todos los honeypots disponibles. Requiere recursos significativos pero proporciona cobertura máxima de vectores de ataque.
- **SENSOR**: Perfil optimizado para despliegues distribuidos donde múltiples sensores reportan a un servidor central.
- **INDUSTRIAL**: Especializado en honeypots de sistemas SCADA/ICS para infraestructura crítica.
- **MINIMAL**: Conjunto reducido de honeypots para entornos con recursos limitados.

Para Project Athanor, seleccionamos el perfil **HIVE (H)** para maximizar la diversidad de datos capturados. Esta decisión implica un compromiso: mayor cobertura a cambio de mayor consumo de recursos, lo cual posteriormente resultaría en el colapso documentado en nuestro análisis forense.

![Selección de perfil durante instalación de T-Pot](tpot_installation_profile.png)

### Configuración de Credenciales de Administración

El instalador solicita credenciales para el panel de administración web de T-Pot. Estas credenciales controlan el acceso a Kibana, Attack Map, y los dashboards de cada honeypot individual. La seguridad de estas credenciales es crítica: comprometerlas permitiría a un atacante observar qué técnicas están siendo detectadas, proporcionándoles inteligencia para evadir el honeypot.

Para este proyecto, las credenciales configuradas fueron:

```
Usuario: dust115
Contraseña: &m2rt0erhC2!qD
```

La contraseña fue generada mediante Bitwarden, un gestor de contraseñas de código abierto que utiliza generación criptográficamente segura. La complejidad resultante (mezcla de mayúsculas, minúsculas, números y símbolos especiales con longitud de 16 caracteres) proporciona aproximadamente 95 bits de entropía, suficiente para resistir ataques de fuerza bruta incluso con hardware especializado.

Durante el proceso de instalación, la interfaz gráfica del terminal puede mostrar salida que visualmente recuerda a escenas de películas de hacking—pantallas negras con texto desplazándose rápidamente en verde o blanco. Esta estética, aunque cinematográfica, refleja procesos reales: descarga de imágenes Docker, configuración de redes virtuales, generación de certificados SSL autofirmados, y compilación de reglas de Suricata.

## Reconfiguración de Puertos y Arquitectura de Red

Uno de los aspectos más ingeniosos de T-Pot es su reconfiguración automática de puertos de administración. Durante la instalación, el sistema realiza los siguientes cambios:

**Puerto SSH (22)**: El servicio SSH del sistema operativo base se reconfigura para escuchar en el puerto **64295** en lugar del puerto estándar 22. Esta modificación libera el puerto 22, permitiendo que el honeypot Cowrie lo ocupe y capture todos los intentos de conexión SSH maliciosos.

**Puerto Web (443)**: El dashboard de administración de T-Pot se sirve mediante HTTPS en el puerto **64297**, dejando el puerto 443 disponible para honeypots que simulan servicios web.

Esta segregación de puertos es fundamental para la operación del honeypot. Los atacantes que escaneen la IP encontrarán servicios aparentemente vulnerables en puertos estándar (22, 80, 443, 3306, etc.), mientras que el operador legítimo accede mediante puertos no estándar conocidos únicamente por él.

Tras aproximadamente 15 minutos de procesamiento (tiempo que varía según la velocidad de conexión a internet y la potencia de la instancia), el instalador completa su ejecución y solicita un reinicio del sistema para aplicar todos los cambios de configuración:

```bash
sudo reboot
```

## Establecimiento de Conexión Post-Instalación

Después del reinicio, el acceso SSH debe realizarse especificando explícitamente el nuevo puerto:

```bash
ssh -i ~/.ssh/azure_honeypot -p 64295 dust115@20.81.132.79
```

El parámetro `-p 64295` indica a SSH que se conecte al puerto no estándar donde ahora escucha el servicio legítimo. Este cambio introduce una capa adicional de seguridad operacional: los escaneos automatizados buscarán SSH en el puerto 22 (donde encontrarán nuestro honeypot Cowrie), mientras que el acceso administrativo real permanece oculto en un puerto de alto rango que no aparecerá en escaneos superficiales.

## Acceso al Dashboard de Administración

La interfaz web de T-Pot se accede mediante un navegador apuntando a la dirección IP pública del servidor con el puerto de administración:

```
https://20.81.132.79:64297/
```

Al tratarse de un certificado SSL autofirmado generado durante la instalación (no emitido por una Autoridad Certificadora reconocida), el navegador mostrará una advertencia de seguridad indicando que "la conexión no es privada" o "el sitio no es seguro". Esta advertencia es esperada y técnicamente correcta: el certificado no puede ser verificado contra una cadena de confianza pública. Sin embargo, dado que controlamos tanto el servidor como el certificado, podemos proceder de manera segura añadiendo una excepción en el navegador.

La página de inicio de sesión solicita las credenciales configuradas durante la instalación. Tras autenticarse exitosamente, el operador obtiene acceso al dashboard principal de T-Pot, que proporciona:

**Attack Map**: Visualización geográfica en tiempo real de conexiones entrantes, mostrando origen y destino de ataques.

**Kibana**: Motor de búsqueda y análisis sobre logs indexados en Elasticsearch, permitiendo queries complejas sobre millones de eventos.

**CyberChef**: Herramienta de transformación y análisis de datos para decodificar payloads, extraer indicadores de compromiso, y analizar muestras de malware.

**Dashboards Especializados**: Interfaces dedicadas para cada honeypot individual (Cowrie para SSH, Dionaea para protocolos binarios, Suricata para análisis de red).

![Dashboard principal de T-Pot tras primer acceso](tpot_first_access.png)

## El Athanor Está Encendido: Primeras Observaciones

Con el sistema completamente desplegado y operacional, el honeypot comienza inmediatamente a capturar tráfico. La primera observación notable es la rapidez con la que los escaneos automatizados descubren la nueva dirección IP. Dentro de los primeros minutos de exposición, los logs de Suricata ya registran sondeos de puertos, intentos de conexión SSH, y requests HTTP exploratorios.

Esta inmediatez confirma la hipótesis fundamental del proyecto: internet no es un espacio neutral sino un entorno constantemente patrullado por actores automatizados buscando objetivos vulnerables. Una dirección IP recién asignada no disfruta de ningún período de gracia; su exposición es su invitación al ataque.

Los logs iniciales muestran patrones predecibles pero reveladores. Intentos de autenticación SSH con credenciales por defecto (`root:root`, `admin:admin`), escaneos de puertos comunes (80, 443, 3306, 5432), y fingerprinting de servicios mediante banners y respuestas a requests malformados. Cada uno de estos eventos, aunque individualmente trivial, contribuye a un corpus de inteligencia sobre la infraestructura de ataque contemporánea.

## Reflexiones sobre Infraestructura como Código

El proceso de despliegue de Project Athanor, aunque documentado aquí paso a paso mediante comandos manuales, podría automatizarse completamente mediante Infrastructure as Code (IaC) utilizando herramientas como Terraform o Azure Resource Manager templates. Un despliegue automatizado permitiría:

- Replicar el honeypot en múltiples regiones geográficas simultáneamente para comparar patrones de ataque regionales.
- Destruir y recrear instancias en ciclos programados para mantener direcciones IP frescas que no aparezcan en listas de bloqueo de honeypots conocidos.
- Versionar la configuración completa en Git, permitiendo auditoría de cambios y rollback a configuraciones anteriores.

Esta automatización representa la evolución natural del proyecto, transformando un experimento manual en una plataforma escalable de inteligencia de amenazas. Sin embargo, para la fase inicial de investigación, el despliegue manual proporciona comprensión profunda de cada componente del sistema, conocimiento esencial para el [[project-athanor|análisis forense posterior]].

## Conclusión: El Horno Está Listo, Comienza la Destilación

Project Athanor ha completado su fase de construcción. El honeypot está desplegado, configurado y operacional. Los 22 contenedores de servicios vulnerables están exponiendo más de 30 puertos a internet, el stack de Elasticsearch está indexando eventos en tiempo real, y Suricata está analizando cada paquete que atraviesa la interfaz de red.

En términos alquímicos, hemos construido nuestro Athanor y encendido el fuego. La materia prima—el tráfico malicioso de internet—está comenzando a fluir hacia el contenedor. Ahora comienza el verdadero trabajo: observar, analizar y destilar inteligencia procesable del caos. Los próximos artículos en esta serie documentarán los hallazgos de esta destilación: qué ataques se capturaron, qué técnicas emplearon los atacantes, y qué lecciones defensivas podemos extraer del análisis.

Como todo buen alquimista sabe, el proceso de transformación requiere paciencia, atención constante, y la voluntad de observar reacciones que otros evitarían. El honeypot nos permite acercarnos al peligro de manera controlada, estudiando las técnicas del adversario sin exponer sistemas de producción. Esta inversión en infraestructura y análisis representa un compromiso con la comprensión profunda de las amenazas contemporáneas—conocimiento que no puede obtenerse mediante lectura pasiva sino solo mediante exposición deliberada y análisis riguroso.

El Athanor está encendido. Que comience la alquimia.

---

