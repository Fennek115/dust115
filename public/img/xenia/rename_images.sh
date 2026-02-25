#!/bin/bash
# rename_images.sh
# Renombra las imágenes para que sean compatibles con Hugo
# Los ":" en nombres de archivo causan problemas en muchos sistemas
# Ejecutar desde la carpeta donde están las imágenes

# Crea la carpeta de destino si no existe
mkdir -p renamed

for file in *; do
    # Reemplaza ":" por "-", espacios por "_", y elimina caracteres problemáticos
    newname=$(echo "$file" | sed 's/:/-/g; s/ /_/g; s/<3//g; s/(//g; s/)//g')
    if [ "$file" != "$newname" ]; then
        cp "$file" "renamed/$newname"
        echo "  $file -> $newname"
    else
        cp "$file" "renamed/$newname"
    fi
done

echo ""
echo "Archivos renombrados en ./renamed/"
echo "Copia el contenido de ./renamed/ a /static/img/xenia/ en tu proyecto Hugo"
