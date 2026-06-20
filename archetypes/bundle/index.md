---
title: '{{ replace (replaceRE "^[0-9]{4}-[0-9]{2}-[0-9]{2}-" "" .File.ContentBaseName) "-" " " | title }}'
slug: '{{ replaceRE "^[0-9]{4}-[0-9]{2}-[0-9]{2}-" "" .File.ContentBaseName }}'
date: {{ .Date }}
draft: true
tags: []
summary: ""
---

<!--
  Post con imágenes (page bundle). Estándar del blog:
  1. Las imágenes van en ESTA MISMA carpeta (junto a index.md).
  2. Se referencian con ruta RELATIVA, solo el nombre del archivo:
        ![texto alternativo](mi-imagen.png)
     o con el shortcode figure (caption + crédito):
        {{< figure src="mi-imagen.png" alt="..." caption="..." credit="..." >}}
  Nunca uses rutas absolutas tipo /img/... : romperían al cambiar de dominio.
-->
