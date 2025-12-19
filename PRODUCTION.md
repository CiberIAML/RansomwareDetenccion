# Despliegue y configuración (Render / Producción)

Este documento resume los pasos y variables que recomendamos configurar al desplegar en producción (por ejemplo en Render.com):

## Variables de entorno importantes
- `DATABASE_URL` (opcional): URL de la base de datos Postgres si no quieres usar SQLite local.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `DEST_EMAIL`: para el envío de notificaciones de comentarios (opcional).
- `STATS_DB`: si quieres indicar otra ruta para la DB SQLite.
- `RENDER_EXTERNAL_URL` o similar: no requerido, pero útil para configurar notificaciones.

## Recomendaciones
1. No subir `model.pkl` al repositorio si es sensible (añadir a `.gitignore`). En su lugar, sube el archivo a un storage seguro y descarga en el build o carga desde una URL segura.
2. Ajusta la cantidad de workers y tiempo de espera en Render si el proceso de carga del modelo requiere más tiempo o memoria.
3. Habilita variables de entorno `SMTP_*` solo si quieres recibir notificaciones por correo.

## Comandos para ver logs y debug
- Revisa logs de deploy en el panel de Render.
- Revisa logs de runtime (stdout/stderr) para ver errores de inicialización o carga del modelo.

## Pasos rápidos para desplegar
1. Empuja tu repo a GitHub.
2. Crea nuevo servicio en Render conectando a tu repo.
3. Configura las variables de entorno y el build command (ej: `pip install -r requirements.txt` y `uvicorn main:app --host 0.0.0.0 --port $PORT`).
4. Revisa el build y luego el servicio en Runtime. Si la app se cae en startup, revisa los logs y el tamaño del proceso.

---
