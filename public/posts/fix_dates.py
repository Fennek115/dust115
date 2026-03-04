#!/usr/bin/env python3
"""
fix_dates.py — Asigna fechas únicas y secuenciales al frontmatter Hugo
leyendo el orden narrativo directamente desde el índice (codice.md).

Uso:
    python fix_dates.py [directorio] [opciones]

Opciones:
    --index    Ruta al archivo índice (default: busca codice.md en el directorio)
    --start    Fecha de inicio YYYY-MM-DD (default: 2020-01-01)
    --step     Días entre cada entrada, mínimo 1 (default: 7)
    --tz       Timezone offset (default: -03:00)
    --hour     Hora del día HH:MM:SS (default: 03:00:00)
    --dry-run  Muestra los cambios sin aplicarlos

Ejemplo:
    python fix_dates.py ./content/codice --dry-run
    python fix_dates.py ./content/codice --start 2019-06-01 --step 3
    python fix_dates.py ./content/codice --index ./content/codice.md
"""

import os
import re
import sys
import argparse
from datetime import datetime, timedelta

# Archivos que nunca se tocan aunque estén en el directorio
ALWAYS_EXCLUDE = {"codice.md", "primer-post.md", "_index.md"}

# ─────────────────────────────────────────────────────────────
# Regex
# ─────────────────────────────────────────────────────────────
# Extrae el slug final de links tipo: [Título](/dust115/posts/codice-01-.../)
LINK_RE = re.compile(r'\[.*?\]\([^)]+/posts/([^/)]+)/?')

FRONTMATTER_DATE_RE = re.compile(
    r'^(date:\s*)(["\']?)(\S+?)(["\']?)\s*$',
    re.MULTILINE
)
COMMIT_SHORTCODE_RE = re.compile(
    r'({{<\s*commit\b[^>]*?\bdate=")[^"]*(")',
    re.DOTALL
)


# ─────────────────────────────────────────────────────────────
# Parsear el índice
# ─────────────────────────────────────────────────────────────
def parse_index(index_path):
    """Lee el codice.md y devuelve la lista ordenada de nombres de archivo."""
    with open(index_path, "r", encoding="utf-8") as f:
        content = f.read()

    slugs = LINK_RE.findall(content)
    filenames = [f"{slug}.md" for slug in slugs]

    # Eliminar duplicados manteniendo orden
    seen = set()
    result = []
    for f in filenames:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result


# ─────────────────────────────────────────────────────────────
# Actualizar contenido
# ─────────────────────────────────────────────────────────────
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


def format_date(dt, tz):
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + tz


# ─────────────────────────────────────────────────────────────
# Args
# ─────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="Fechas unicas y secuenciales para Hugo — Codice del Polvo."
    )
    p.add_argument("directory", nargs="?", default=".",
                   help="Directorio con los archivos .md")
    p.add_argument("--index",   default=None,
                   help="Ruta al archivo indice (default: busca codice.md en el directorio)")
    p.add_argument("--start",   default="2020-01-01",
                   help="Fecha de inicio YYYY-MM-DD (default: 2020-01-01)")
    p.add_argument("--step",    type=int, default=7,
                   help="Dias entre entradas, minimo 1 (default: 7)")
    p.add_argument("--tz",      default="-03:00",
                   help="Timezone offset (default: -03:00)")
    p.add_argument("--hour",    default="03:00:00",
                   help="Hora del dia HH:MM:SS (default: 03:00:00)")
    p.add_argument("--dry-run", action="store_true",
                   help="Solo muestra los cambios, no escribe nada")
    return p.parse_args()


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    directory = args.directory

    if not os.path.isdir(directory):
        print(f"ERROR: '{directory}' no es un directorio valido.")
        sys.exit(1)

    # Step mínimo 1 para garantizar unicidad
    step_days = max(1, args.step)
    if step_days != args.step:
        print(f"AVISO: --step ajustado a 1 (minimo para garantizar fechas unicas).")

    # Encontrar el índice
    index_path = args.index
    if index_path is None:
        candidates = [
            os.path.join(directory, "codice.md"),
            os.path.join(directory, "_index.md"),
        ]
        for c in candidates:
            if os.path.exists(c):
                index_path = c
                break

    if index_path is None or not os.path.exists(index_path):
        print("ERROR: No se encontro el archivo indice.")
        print("  Usa --index ./ruta/al/codice.md para especificarlo.")
        sys.exit(1)

    print(f"Indice: {os.path.abspath(index_path)}")
    narrative_order = parse_index(index_path)

    if not narrative_order:
        print("ERROR: No se encontraron links en el indice.")
        sys.exit(1)

    # Fecha inicial
    try:
        h, m, s = args.hour.split(":")
        current_date = datetime.strptime(args.start, "%Y-%m-%d").replace(
            hour=int(h), minute=int(m), second=int(s)
        )
    except ValueError as e:
        print(f"ERROR parseando fecha/hora: {e}")
        sys.exit(1)

    step = timedelta(days=step_days)

    # Archivos sin rastrear
    all_md = {f for f in os.listdir(directory) if f.endswith(".md")}
    ordered_set = set(narrative_order)
    untracked = sorted(all_md - ordered_set - ALWAYS_EXCLUDE)

    mode_label = "DRY RUN  " if args.dry_run else "APLICANDO"
    print(f"\n[{mode_label}] fix_dates.py — Codice del Polvo")
    print(f"Directorio : {os.path.abspath(directory)}")
    print(f"Inicio     : {format_date(current_date, args.tz)}")
    print(f"Step       : {step_days} dias  ({len(narrative_order)} entradas)\n")
    print(f"  {'#':<4} {'ARCHIVO':<52} {'FECHA ASIGNADA':<30} CAMBIOS")
    print("  " + "─" * 100)

    processed = 0
    missing = []

    for i, filename in enumerate(narrative_order, 1):
        filepath = os.path.join(directory, filename)
        new_date = format_date(current_date, args.tz)

        if not os.path.exists(filepath):
            missing.append(filename)
            print(f"  {i:<4} {'[NO ENCONTRADO] ' + filename:<52} {new_date:<30} —")
            current_date += step
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        new_content, changes = update_content(content, new_date)
        change_label = " + ".join(changes) if changes else "sin campo date"

        print(f"  {i:<4} {filename:<52} {new_date:<30} {change_label}")

        if changes and not args.dry_run:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(new_content)

        processed += 1
        current_date += step

    # Resumen
    print()

    if untracked:
        print(f"  {len(untracked)} archivos NO en el indice (no modificados):")
        for f in untracked:
            print(f"    · {f}")
        print()

    if missing:
        print(f"  {len(missing)} entradas del indice NO encontradas en el directorio:")
        for f in missing:
            print(f"    · {f}")
        print()

    if args.dry_run:
        print("  DRY RUN completado — ningun archivo fue modificado.")
        print("  Ejecuta sin --dry-run para aplicar los cambios.")
    else:
        print(f"  Listo. {processed} archivos actualizados.")


if __name__ == "__main__":
    main()
