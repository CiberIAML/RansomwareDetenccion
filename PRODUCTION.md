# Despliegue y configuración (Render / Producción)

Este documento resume los pasos y variables que recomendamos configurar al desplegar en producción (por ejemplo en Render.com):

## Variables de entorno importantes
- `DATABASE_URL` (opcional): URL de la base de datos Postgres si no quieres usar SQLite local.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `DEST_EMAIL`: para el envío de notificaciones de comentarios (opcional).
- `STATS_DB`: si quieres indicar otra ruta para la DB SQLite.
- `RENDER_EXTERNAL_URL` o similar: no requerido, pero útil para configurar notificaciones.

## Recomendaciones
1. No subir `model.pkl` al repositorio si es sensible (añádelo a `.gitignore`). En su lugar, sube el archivo a un storage seguro y descárgalo en el build o carga desde una URL segura.
2. Ajusta la cantidad de workers y tiempo de espera: para despliegues en Render se recomienda usar Gunicorn con Uvicorn workers y un timeout mayor (ej. 120s) cuando el proceso de arranque puede tardar o si dependencias pesadas se instalan. En `render.yaml` ya sugerimos ese cambio.
3. Si la aplicación consume mucha memoria al importar paquetes (pandas / scikit-learn), reduce a **1 worker** y considera aumentar el plan de instancia en Render (la instancia free es muy limitada).
4. Habilita variables de entorno `SMTP_*` solo si quieres recibir notificaciones por correo.

## Diagnóstico y pasos para corregir el error "Worker was sent SIGTERM / Timed Out"
- Causa frecuente: el worker no responde durante el tiempo de espera del servicio (timeout) o se queda corto de memoria.
- Pasos recomendados:
  1. **Aumentar timeout:** usa Gunicorn y especifica `--timeout 120` (ya aplicado en `render.yaml`).
  2. **Reducir workers:** mantener `--workers 1` si hay poca memoria.
  3. **Revisar dependencias:** instala versiones ligeras y evita compilaciones largos durante build; revisa la salida del build para detectar pasos lentos.
  4. **Revisar logs de runtime:** en Render, mira tanto los logs de deploy (build) como los de runtime; si ves `MemoryError` o excepciones durante import, considera optimizar imports (carga perezosa) o subir a un plan con más memoria.
  5. **Comprobación de salud temprana:** `healthCheckPath: /api` verifica que el servicio responde; `GET /model_status` es útil para verificar la presencia de `model.pkl` sin cargarlo.

## Comandos útiles
- Restart manual del servicio en Render (panel) y revisar logs tras cada deploy.
- Localmente prueba:
  ```bash
  pip install -r requirements.txt
  gunicorn -k uvicorn.workers.UvicornWorker main:app -b 0.0.0.0:8000 --timeout 120 --workers 1 --log-level debug
  ```

---

---
