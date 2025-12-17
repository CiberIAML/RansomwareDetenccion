Despliegue en Render (pasos rápidos)

1) Conectar repo en GitHub con Render
   - En Render dashboard -> New -> Web Service
   - Selecciona el repositorio: https://github.com/CiberIAML/RansomwareDetenccion/tree/main
   - Branch: `main`
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT`
   - Health check path: `/api`

2) Variables de entorno (Environment) (importante)
   - SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, DEST_EMAIL (para envío de comentarios)
   - STATS_DB = `/data/stats.db` (solo para pruebas locales con SQLite; en producción **usar Postgres**)

3) (Recomendado) Usar PostgreSQL gestionado por Render
   - New -> Hosted Database -> PostgreSQL
   - Añade la base de datos y copia la `DATABASE_URL` que Render proporciona
   - En el servicio web, crea una variable `DATABASE_URL` con esa URL (p. ej. `postgres://user:pass@host:5432/dbname`)
   - El código ya usa SQLAlchemy y detecta `DATABASE_URL`; al desplegar, las tablas se crearán automáticamente si no existen.

Nota: Si tienes datos en `stats.db` y quieres migrarlos, exporta los datos (JSON/CSV) y luego impórtalos en la nueva base de datos; puedo ayudarte a generar instrucciones para eso si lo deseas.

4) Archivos añadidos
   - `render.yaml` incluido para deploy infra-as-code (autoDeploy: true)
   - `DEPLOY_RENDER.md` con pasos rápidos

5) Push desde tu máquina
   - git add .
   - git commit -m "chore: prepare for render deploy (render.yaml, db endpoints, UI improvements)"
   - git push origin main

Si quieres, hago la migración a Postgres y modifico el código para usar `DATABASE_URL` con SQLAlchemy y pequeñas migraciones; dime si autorizas ese cambio y lo implemento.