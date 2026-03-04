#!/usr/bin/env python3
"""
fix_dates.py — Asigna fechas secuenciales al frontmatter Hugo
siguiendo el orden narrativo del Códice del Polvo.

Actualiza tanto el campo `date:` del frontmatter como el shortcode
{{< commit ... date="..." >}} si existe.

Uso:
    python fix_dates.py [directorio] [opciones]

Opciones:
    --start    Fecha de inicio (default: 2020-01-01)
    --step     Días entre cada entrada (default: 7)
    --tz       Timezone offset (default: -03:00)
    --hour     Hora del día HH:MM:SS (default: 03:00:00)
    --dry-run  Muestra los cambios sin aplicarlos

Ejemplo:
    python fix_dates.py ./content/codice --dry-run
    python fix_dates.py ./content/codice --start 2019-06-01 --step 5
"""

import os
import re
import sys
import argparse
from datetime import datetime, timedelta

# ─────────────────────────────────────────────────────────────
# ORDEN NARRATIVO CANÓNICO
# Edita esta lista si añades o reordenas entradas.
# ─────────────────────────────────────────────────────────────
NARRATIVE_ORDER = [
    # ERA I — El Zorro Anthropomórfico
    "codice-00-nota-de-archivo.md",
    "codice-01-el-zorro-sin-nombre.md",
    "codice-02-script-heredado.md",
    "codice-03-despertar-incompleto.md",
    "codice-03b-el-unico-lugar-donde-no-pensaba.md",
    "codice-04-nigredo.md",
    "codice-05-tres-hijos.md",
    "codice-06-renacimiento-en-la-nada.md",

    # ERA II — El Skull Fox / Valle de la Sombra
    "codice-07-el-despertar-del-polvo.md",
    "codice-08-sesion-de-reconocimiento.md",
    "codice-09-el-vagabundo.md",
    "codice-09a-preambulo.md",
    "codice-10-las-siete-cadenas.md",
    "codice-10a-lo-que-el-agua.md",
    "codice-10b-calx.md",
    "codice-10c-nadie-me-dijo.md",
    "codice-11-la-guitarra.md",
    "codice-12-script-kiddie.md",
    "codice-13-operacional.md",
    "codice-13b-cafe-y-sedimento.md",
    "codice-14-acompanar-sin-salvar.md",
    "codice-14b-a-donde-vas-cuando-caes.md",
    "codice-14c-la-forma-en-que-se-van.md",
    "codice-15-lo-que-el-valle-no-sabe.md",

    # ERA III — El Protogen / Post-Cyberpunk
    # Vesper
    "codice-p1-naturaleza-en-hexadecimal.md",
    "codice-p2.md",
    "codice-p3.md",
    "codice-p4.md",
    # Dust
    "codice-d1.md",
    "codice-d1-5.md",
    "codice-d1-5b-cambiamos-con-las-estaciones.md",
    "codice-d2.md",
    "codice-d2-5.md",
    "codice-d2-7.md",
    "codice-d3a.md",
    "codice-d3b.md",
    "codice-d3c.md",
    "codice-d4.md",

    # Epilogos
    "codice-epilogo-preludio-el-peso-del-vacio.md",
    "codice-epilogo-pulvis.md",
]

# Archivos que nunca se tocan
ALWAYS_EXCLUDE = {"primer-post.md"}

# ─────────────────────────────────────────────────────────────
# Regex
# ─────────────────────────────────────────────────────────────
FRONTMATTER_DATE_RE = re.compile(
    r'^(date:\s*)(["\']?)(\S+?)(["\']?)\s*$',
    re.MULTILINE
)

COMMIT_SHORTCODE_RE = re.compile(
    r'({{<\s*commit\b[^>]*?\bdate=")[^"]*(")',
    re.DOTALL
)


def format_date(dt, tz):
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + tz


def update_content(content, new_date):
    changes = []

    def replace_fm(m):
        changes.append("frontmatter")
        return f"{m.group(1)}{new_date}"

    content = FRONTMATTER_DATE_RE.sub(replace_fm, content, count=1)

    def replace_commit(m):
        changes.append("commit shortcode")
        return f"{m.group(1)}{new_date}{m.group(2)}"

    content = COMMIT_SHORTCODE_RE.sub(replace_commit, content)

    return content, changes


def parse_args():
    p = argparse.ArgumentParser(
        description="Asigna fechas secuenciales (orden narrativo) al frontmatter Hugo."
    )
    p.add_argument("directory", nargs="?", default=".",
                   help="Directorio con los archivos .md")
    p.add_argument("--start",   default="2026-01-01",
                   help="Fecha de inicio YYYY-MM-DD (default: 2020-01-01)")
    p.add_argument("--step",    type=int, default=7,
                   help="Dias entre cada entrada (default: 7)")
    p.add_argument("--tz",      default="-03:00",
                   help="Timezone offset (default: -03:00)")
    p.add_argument("--hour",    default="03:00:00",
                   help="Hora del dia HH:MM:SS (default: 03:00:00)")
    p.add_argument("--dry-run", action="store_true",
                   help="Solo muestra los cambios, no escribe nada")
    return p.parse_args()


def main():
    args = parse_args()
    directory = args.directory

    if not os.path.isdir(directory):
        print(f"ERROR: '{directory}' no es un directorio valido.")
        sys.exit(1)

    try:
        h, m, s = args.hour.split(":")
        current_date = datetime.strptime(args.start, "%Y-%m-%d").replace(
            hour=int(h), minute=int(m), second=int(s)
        )
    except ValueError as e:
        print(f"ERROR parseando fecha/hora: {e}")
        sys.exit(1)

    step = timedelta(days=args.step)

    # Detectar .md que existen pero no estan en el orden narrativo
    all_md = {f for f in os.listdir(directory) if f.endswith(".md")}
    ordered_set = set(NARRATIVE_ORDER)
    untracked = sorted(all_md - ordered_set - ALWAYS_EXCLUDE)

    mode_label = "DRY RUN  " if args.dry_run else "APLICANDO"
    print(f"\n[{mode_label}] fix_dates.py — Codice del Polvo")
    print(f"Directorio : {os.path.abspath(directory)}")
    print(f"Inicio     : {format_date(current_date, args.tz)}")
    print(f"Step       : {args.step} dias\n")
    print(f"  {'ARCHIVO':<55} {'FECHA ASIGNADA':<30} CAMBIOS")
    print("  " + "-" * 95)

    processed = 0
    missing = []

    for filename in NARRATIVE_ORDER:
        filepath = os.path.join(directory, filename)

        if not os.path.exists(filepath):
            missing.append(filename)
            new_date = format_date(current_date, args.tz)
            print(f"  {'[NO ENCONTRADO] ' + filename:<55} {new_date:<30} —")
            current_date += step
            continue

        new_date = format_date(current_date, args.tz)

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        new_content, changes = update_content(content, new_date)
        change_label = " + ".join(changes) if changes else "sin campo date"

        print(f"  {filename:<55} {new_date:<30} {change_label}")

        if changes and not args.dry_run:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(new_content)

        processed += 1
        current_date += step

    print()

    if untracked:
        print("Archivos NO en el orden narrativo (no modificados):")
        for f in untracked:
            print(f"  · {f}")
        print()

    if missing:
        print("Entradas del orden narrativo NO encontradas en el directorio:")
        for f in missing:
            print(f"  · {f}")
        print()

    if args.dry_run:
        print("DRY RUN completado — ningun archivo fue modificado.")
        print("Ejecuta sin --dry-run para aplicar los cambios.")
    else:
        print(f"Listo. {processed} archivos actualizados.")


if __name__ == "__main__":
    main()
