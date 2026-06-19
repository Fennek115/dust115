# Shortcodes

Referencia de los shortcodes del tema: qué hacen, parámetros y ejemplos. Los
archivos viven en `layouts/shortcodes/` y su estilo en `assets/css/skin/` (los
cuatro nuevos en `07-shortcodes.css`). Paleta y reglas: tokens `--vm-*` y «glow
only on intent».

> Sintaxis Hugo: `{{</* nombre */>}}` para los que NO procesan markdown interno,
> `{{%/* nombre */%}}` para los que sí. Acá todos usan `{{< >}}`.

| Shortcode | Resumen |
|-----------|---------|
| `listening` | Bloque «escuchando ahora» (track/artist/album) |
| `ascii` | Envuelve arte ASCII/braille con tamaño correcto |
| `commit` | Pie estilo commit de git |
| `codice-list` | Lista capítulos por rango de `weight` |
| `callout` | Aviso destacado (info/tip/warning/danger) |
| `command` | Bloque de comando copiable |
| `figure` | Imagen con caption + crédito |
| `badge` | Etiqueta inline de color por token |
| `tlp` | Banner Traffic Light Protocol |

---

## listening

Bloque «lo que estoy escuchando» con borde de acento.

| Parámetro | Req. | Descripción |
|-----------|------|-------------|
| `track`   | sí   | Nombre del tema |
| `artist`  | sí   | Artista |
| `album`   | no   | Álbum |

```text
{{< listening track="Bleed" artist="Meshuggah" album="obZen" >}}
```

## ascii

Envuelve arte ASCII / braille en un `<pre>` con el tamaño correcto.

```text
{{< ascii >}}
⠀⠀⢀⣴⣶⣶⣦⡀
⠀⢰⣿⠟⠛⠿⣿⣧
{{< /ascii >}}
```

## commit

Pie estilo commit de git.

| Parámetro | Req. | Descripción |
|-----------|------|-------------|
| `hash`    | sí   | Hash corto |
| `date`    | sí   | Fecha |
| `message` | no   | Mensaje |

```text
{{< commit hash="a7d9f82" date="2025-02-08 03:47" message="Eternal recurrence" >}}
```

## codice-list

Lista los capítulos de una sección cuyo `weight` cae en un rango (pensado para un
índice semi-automático que no se desincroniza al agregar/quitar capítulos).

| Parámetro | Req. | Descripción |
|-----------|------|-------------|
| `min`     | sí   | Límite inferior del `weight` |
| `max`     | sí   | Límite superior del `weight` |

```text
{{< codice-list min="1000" max="1999" >}}
```

## callout

Aviso destacado. Procesa markdown interno. Color por tipo.

| Parámetro | Req. | Valores | Descripción |
|-----------|------|---------|-------------|
| `type`    | no   | `info` (default), `tip`, `warning`, `danger` | Color del borde |

```text
{{< callout type="warning" >}}
Esto **desactiva** controles. Usar solo en el lab.
{{< /callout >}}
```

Colores: info=violeta, tip=verde, warning=naranja, danger=rojo.

## command

Bloque de comando copiable. El prompt es decorativo (no se copia); el botón copia
solo el comando. El script de copia se inyecta una vez por página vía `Page.Store`.

| Parámetro | Req. | Descripción |
|-----------|------|-------------|
| `prompt`  | no   | Prompt a la izquierda (default `$`) |
| (interno) | sí   | El comando |

```text
{{< command >}}nxc smb 10.10.4.0/24 --gen-relay-list relay.txt{{< /command >}}
{{< command prompt="PS>" >}}Get-Process | ? { $_.CPU -gt 100 }{{< /command >}}
```

## figure

Imagen con caption y crédito. Si `src` coincide con un recurso del page bundle lo
resuelve; si no, usa la ruta tal cual (útil para `/algo.png` en `static/`).
**Sobrescribe el `figure` nativo de Hugo** — renombralo si necesitás el nativo.

| Parámetro | Req. | Descripción |
|-----------|------|-------------|
| `src`     | sí   | Archivo del bundle o ruta estática |
| `alt`     | no   | Texto alternativo (default = `caption`) |
| `caption` | no   | Pie |
| `credit`  | no   | Crédito (línea tenue) |

```text
{{< figure src="diagrama.png" alt="Arquitectura" caption="Flujo" credit="Autor" >}}
```

## badge

Etiqueta inline de color por token. Color por parámetro o posicional.

| Parámetro | Req. | Valores |
|-----------|------|---------|
| `color` / posicional | no | `accent` (default), `purple`, `green`, `teal`, `red`, `pink`, `orange`, `yellow` |

```text
{{< badge red >}}CRÍTICO{{< /badge >}} {{< badge green >}}resuelto{{< /badge >}}
```

## tlp

Banner TLP (Traffic Light Protocol). Solo banner o con nota interna.

| Parámetro | Req. | Valores |
|-----------|------|---------|
| `level` / posicional | no | `clear` (default), `green`, `amber`, `red` |

```text
{{< tlp amber >}}distribución limitada — solo el equipo{{< /tlp >}}
{{< tlp red >}}{{< /tlp >}}
```

---

## Mantenimiento

- Todo el color sale de tokens `--vm-*` (`assets/css/tokens/colors.css`), así que
  claro/oscuro se resuelven solos.
- El CSS de `command`/`figure`/`badge`/`tlp` está en `assets/css/skin/07-shortcodes.css`.
