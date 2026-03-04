#!/bin/bash
# =============================================================
# CÓDICE DEL POLVO — Generador de Capítulos para Hugo
# Ejecutar desde la raíz del proyecto Hugo:
#   bash generar_codice.sh
# Crea todos los archivos en content/posts/
# =============================================================

POSTS_DIR="content/posts"
mkdir -p "$POSTS_DIR"

# Fecha base de publicación (modifica según quieras)
# Formato: YYYY-MM-DDThh:mm:ss-03:00
# Un capítulo por semana desde esta fecha
BASE_DATE="2025-03-01"

# Función para calcular fecha relativa (días desde base)
fecha() {
  local semanas=$1
  local dias=$(( semanas * 7 ))
  date -d "$BASE_DATE + $dias days" "+%Y-%m-%dT03:00:00-03:00" 2>/dev/null \
    || python3 -c "
from datetime import datetime, timedelta
d = datetime.strptime('$BASE_DATE', '%Y-%m-%d') + timedelta(days=$dias)
print(d.strftime('%Y-%m-%dT03:00:00-03:00'))
"
}

# =============================================================
# Función principal para crear cada capítulo
# Uso: crear_cap SEMANA SLUG TITULO SUBTITULO TRACK ARTISTA ALBUM ERA LIBRO CAPNUM SUMMARY
# =============================================================
crear_cap() {
  local semana=$1
  local slug=$2
  local titulo=$3
  local track=$4
  local artista=$5
  local album=$6
  local era=$7
  local libro=$8
  local capnum=$9
  local summary="${10}"
  local hash="${11}"
  local fecha_pub
  fecha_pub=$(fecha "$semana")

  local filepath="$POSTS_DIR/${slug}.md"

  cat > "$filepath" << FRONTMATTER
---
title: "${titulo}"
date: ${fecha_pub}
draft: false
tags: ["códice", "${era}"]
series: ["Códice del Polvo"]
summary: "${summary}"
---

{{< listening track="${track}" artist="${artista}" album="${album}" >}}

<!-- ============================================================ -->
<!-- ASCII ART: pega tu arte ASCII aquí dentro del shortcode      -->
<!-- ============================================================ -->
{{< ascii >}}
[tu ascii aquí]
{{< /ascii >}}

<!-- ============================================================ -->
<!-- CONTENIDO: pega el texto del capítulo aquí                   -->
<!-- ============================================================ -->



{{< commit hash="${hash}" date="${fecha_pub}" message="[añade tu mensaje de commit aquí]" >}}
FRONTMATTER

  echo "✓ Creado: $filepath"
}

# =============================================================
# ERA I — EL ZORRO ANTHROPOMÓRFICO
# =============================================================

crear_cap 0 \
  "codice-00-nota-de-archivo" \
  "Códice del Polvo — Nota de Archivo" \
  "Arriving Somewhere But Not Here" "Porcupine Tree" "Deadwing" \
  "zorro-era" "—" "00" \
  "Este documento fue encontrado en una terminal abandonada. No tiene firmas digitales." \
  "a0000000"

crear_cap 1 \
  "codice-01-el-zorro-sin-nombre" \
  "Códice | I — El Zorro Sin Nombre" \
  "The Sound of Muzak" "Porcupine Tree" "In Absentia" \
  "zorro-era" "I" "01" \
  "Fui uno de los Umbra Caudati. Viví, que es diferente a estar vivo." \
  "b1a9f82"

crear_cap 2 \
  "codice-02-script-heredado" \
  "Códice | II — La Ejecución del Script Heredado" \
  "Fear of a Blank Planet" "Porcupine Tree" "Fear of a Blank Planet" \
  "zorro-era" "I" "02" \
  "Mi padre trabajó treinta años en la misma empresa. Me entregó un sobre." \
  "c2b8e91"

crear_cap 3 \
  "codice-03-despertar-incompleto" \
  "Códice | III — El Momento del Despertar Incompleto" \
  "Sleep Together" "Porcupine Tree" "Fear of a Blank Planet" \
  "zorro-era" "I" "03" \
  "Hubo un día en que me detuve frente a un espejo. No fue un momento dramático." \
  "d3c7d00"

crear_cap 4 \
  "codice-04-nigredo" \
  "Códice | IV — Nigredo" \
  "Bleed" "Meshuggah" "obZen" \
  "zorro-era" "II" "04" \
  "La oscuridad me tragó no para borrarme, sino para gestarme de nuevo." \
  "e4d6c11"

crear_cap 5 \
  "codice-05-tres-hijos" \
  "Códice | V — Los Tres Hijos de la Libertad" \
  "The Void" "Haken" "Affinity" \
  "zorro-era" "II" "05" \
  "El tercer hijo de la Libertad nació muerto. Eso me dio una paz extraña." \
  "f5e5b22"

crear_cap 6 \
  "codice-06-renacimiento-en-la-nada" \
  "Códice | VI — El Renacimiento en la Nada" \
  "Blackwater Park" "Opeth" "Blackwater Park" \
  "zorro-era" "II" "06" \
  "Darse cuenta del ciclo no lo rompe. La consciencia es irrelevante para una realidad indiferente." \
  "06f4a33"

# =============================================================
# ERA II — EL SKULL FOX / VALLE DE LA SOMBRA
# =============================================================

crear_cap 8 \
  "codice-07-el-despertar-del-polvo" \
  "Códice | VII — El Despertar del Polvo" \
  "I" "Meshuggah" "obZen" \
  "skull-fox-era" "III" "07" \
  "El abismo tiene memoria. Lo que emergió del sedimento no tenía piel para esconderse." \
  "17a3944"

crear_cap 9 \
  "codice-08-sesion-de-hacking" \
  "Códice | VIII — Sesión de Hacking en una Noche Vacía" \
  "Closer" "Nine Inch Nails" "The Downward Spiral" \
  "skull-fox-era" "III" "08" \
  "La pantalla parpadeaba violeta sobre negro. Encontré un nombre que me hizo detenerme." \
  "28b4055"

crear_cap 10 \
  "codice-09-el-vagabundo" \
  "Códice | IX — El Vagabundo de los Siete Mil Años" \
  "L'Via L'Viaquez" "The Mars Volta" "Frances the Mute" \
  "skull-fox-era" "III" "09" \
  "Comencé a vagar. No porque tuviera un destino, sino porque moverse parecía más honesto." \
  "39c5166"

crear_cap 11 \
  "codice-10-las-siete-cadenas" \
  "Códice | X — Las Siete Cadenas" \
  "Vermilion Pt. 2" "Slipknot" "Vol. 3: The Subliminal Verses" \
  "skull-fox-era" "III" "10" \
  "No son las cadenas que se ven. Son las otras. Las que no hacen ruido al cerrarse." \
  "40d6277"

crear_cap 12 \
  "codice-11-la-guitarra" \
  "Códice | XI — La Guitarra y el Silencio" \
  "Anesthesia (Pulling Teeth)" "Metallica" "Kill 'Em All" \
  "skull-fox-era" "III" "11" \
  "Tocaba en el Valle. El sonido no viajaba a ningún lugar. Lo tocaba igual." \
  "51e7388"

crear_cap 13 \
  "codice-12-script-kiddie" \
  "Códice | XII — El Script Kiddie" \
  "Foulbrood" "HEALTH" "Vol. 4: Slaves of Fear" \
  "skull-fox-era" "III" "12" \
  "Buscaba llave, no mapa. Seguirá buscando. Probable que encuentre algo peor. Clásico." \
  "62f8499"

crear_cap 14 \
  "codice-13-operacional" \
  "Códice | XIII — Lo Que Significa Ser Operacional" \
  "Rational Gaze" "Meshuggah" "Nothing" \
  "skull-fox-era" "III" "13" \
  "Ya muerto, por lo menos puedo beber café frío sin existencializarlo." \
  "73095a0"

crear_cap 15 \
  "codice-14-acompanar-sin-salvar" \
  "Códice | XIV — Acompañar Sin Salvar" \
  "The Greatest Show on Earth" "Nightwish" "Endless Forms Most Beautiful" \
  "skull-fox-era" "III" "14" \
  "No salvo a nadie. Acompañar no requiere que yo sepa a dónde va el otro." \
  "840a6b1"

crear_cap 16 \
  "codice-15-lo-que-el-valle-no-sabe" \
  "Códice | XV — Lo Que el Valle No Sabe Que Es" \
  "Coma" "Haken" "The Mountain" \
  "skull-fox-era" "III" "15" \
  "Si el Valle era tránsito, había una salida. Si había salida, tenía vulnerabilidades." \
  "951b7c2"

# =============================================================
# ERA III — EL PROTOGEN / POST-CYBERPUNK
# Vesper: P-1 a P-4  |  Dust: D-1 a D-4  |  Epílogo
# Nota: slugs con puntos (1.5, 2.5, 2.7) usan guión en el slug
# =============================================================

crear_cap 18 \
  "codice-p1-naturaleza-en-hexadecimal" \
  "Códice | P-1 — Naturaleza en Hexadecimal" \
  "Caméléon" "Igorrr" "Spirituality and Distortion" \
  "protogen-era" "P" "P-1" \
  "La ciudad habla antes de que yo decida escucharla. No es metáfora. Es protocolo." \
  "a62c8d3"

crear_cap 19 \
  "codice-p2" \
  "Códice | P-2" \
  "Mea Culpa" "Igorrr" "Spirituality and Distortion" \
  "protogen-era" "P" "P-2" \
  "[añade tu summary aquí]" \
  "b73d9e4"

crear_cap 20 \
  "codice-p3" \
  "Códice | P-3" \
  "Downfall" "Igorrr" "Spirituality and Distortion" \
  "protogen-era" "P" "P-3" \
  "[añade tu summary aquí]" \
  "c84eaf5"

crear_cap 21 \
  "codice-p4" \
  "Códice | P-4" \
  "Hollow Tree" "Igorrr" "Savage Sinusoid" \
  "protogen-era" "P" "P-4" \
  "[añade tu summary aquí]" \
  "d95fb06"

crear_cap 22 \
  "codice-d1" \
  "Códice | D-1" \
  "The Observant" "Haken" "Affinity" \
  "protogen-era" "D" "D-1" \
  "[añade tu summary aquí]" \
  "e06gc17"

crear_cap 23 \
  "codice-d1-5" \
  "Códice | D-1.5" \
  "The Architect" "Haken" "Affinity" \
  "protogen-era" "D" "D-1.5" \
  "[añade tu summary aquí]" \
  "f17hd28"

crear_cap 24 \
  "codice-d2" \
  "Códice | D-2" \
  "God of Empty Nights" "Septicflesh" "Codex Omega" \
  "protogen-era" "D" "D-2" \
  "[añade tu summary aquí]" \
  "028ie39"

crear_cap 25 \
  "codice-d2-5" \
  "Códice | D-2.5" \
  "Portrait of the Young Man" "Haken" "The Mountain" \
  "protogen-era" "D" "D-2.5" \
  "[añade tu summary aquí]" \
  "139jf40"

crear_cap 26 \
  "codice-d2-7" \
  "Códice | D-2.7" \
  "Nil Recurring" "Porcupine Tree" "Nil Recurring EP" \
  "protogen-era" "D" "D-2.7" \
  "[añade tu summary aquí]" \
  "240kg51"

crear_cap 27 \
  "codice-d3a" \
  "Códice | D-3a" \
  "Nataraja" "Igorrr" "Spirituality and Distortion" \
  "protogen-era" "D" "D-3a" \
  "[añade tu summary aquí]" \
  "351lh62"

crear_cap 28 \
  "codice-d3b" \
  "Códice | D-3b" \
  "Sinner's Sake" "Igorrr" "Spirituality and Distortion" \
  "protogen-era" "D" "D-3b" \
  "[añade tu summary aquí]" \
  "462mi73"

crear_cap 29 \
  "codice-d3c" \
  "Códice | D-3c" \
  "Paranoid Android" "Radiohead" "OK Computer" \
  "protogen-era" "D" "D-3c" \
  "[añade tu summary aquí]" \
  "573nj84"

crear_cap 30 \
  "codice-d4" \
  "Códice | D-4" \
  "Crystallized" "The xx" "xx" \
  "protogen-era" "D" "D-4" \
  "[añade tu summary aquí]" \
  "684ok95"

crear_cap 32 \
  "codice-epilogo-pulvis" \
  "Códice | Epílogo — Pulvis" \
  "Catalogue of Sunsets" "Steven Wilson" "The Harmony Codex" \
  "protogen-era" "—" "∞" \
  "Desde el principio. Entonces." \
  "0x4A7F"

echo ""
echo "=============================================="
echo "✓ Todos los capítulos generados en $POSTS_DIR/"
echo "  Abre cada archivo y pega el contenido."
echo ""
echo "  El ASCII va DENTRO de {{< ascii >}} ... {{< /ascii >}}"
echo "  El texto del cap va después del shortcode ASCII."
echo "=============================================="
