# Deteccion_de-Ransomware_en_Archivos_Ejecutables_de_Windows

Detección de Ransomware en Archivos Ejecutables de Windows
Proyecto de análisis y detección de ransomware en archivos ejecutables de Windows mediante técnicas de machine learning y análisis de características PE.

## Descripción
Sistema desarrollado en Python que permite identificar posibles amenazas de ransomware en archivos ejecutables mediante el análisis de sus características y estructura.

## Características principales

- Análisis completo de archivos PE (Portable Executable)

- Extracción de características relevantes para detección de malware

- Modelo de machine learning entrenado para clasificación

- Interfaz de línea de comandos fácil de usar

- Procesamiento rápido y eficiente

## Tablero y estado del modelo 🔍

- **Comprobación de salud de la API:** La interfaz incluye un botón **"Probar API"** (junto a "Guardar") que llama a `GET /api` para verificar si el backend está conectado; también existe el endpoint `GET /api` que devuelve `{ "message": "API funcionando correctamente" }`.

- **Estado del modelo:** Añadimos `GET /model_status` que devuelve información segura sobre `model.pkl` sin intentar cargarlo (ejemplo de respuesta: `{ "model": {"exists": true, "size": 123456, "mtime": 1700000000.0}, "loaded_in_memory": false }`). Útil para comprobar que el fichero del modelo está presente y ver si ya fue cargado en memoria.

- **Pruebas locales rápidas:**
  1. pip install -r requirements.txt
  2. uvicorn main:app --reload
  3. Abrir http://localhost:8000/ y usar **Probar API** o consultar `http://localhost:8000/model_status`.

- **Despliegue en Render:** Después de push, revisa los logs de deploy (Build & Runtime). Si ves mensajes `Worker (pid) was sent SIGTERM`, revisa la carga del modelo y considera aumentar timeout o memoria; el repositorio ya contiene mitigaciones (lazy-load y reducción a 1 worker en `render.yaml`).

---

## Preparar y subir a GitHub

Sigue estos pasos para subir el proyecto a GitHub (suponiendo que ya tienes Git y una cuenta configurada):

1. Inicializa (si no está iniciado):

   ```bash
   git init
   git add .
   git commit -m "Inicial: proyecto clasificador ransomware"
   ```

2. Crea un repo en GitHub (por ejemplo `detencion-ransomware`) y añade el remoto:

   ```bash
   git remote add origin https://github.com/<tu-usuario>/<tu-repo>.git
   git branch -M main
   git push -u origin main
   ```

3. Buenas prácticas antes del push:
   - Asegúrate de que `model.pkl` no se suba (añádelo a `.gitignore` si corresponde).
   - Incluye `stats.db` y otros ficheros generados en `.gitignore`.

4. Archivos útiles que puedes añadir al repo:
   - `PRODUCTION.md`: instrucciones de despliegue (Render, variables de entorno SMTP, DATABASE_URL, etc.).

---



