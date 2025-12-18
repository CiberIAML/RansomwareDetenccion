from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import joblib
import tempfile

import os
import sqlite3
import smtplib
from email.message import EmailMessage
from typing import Optional
import logging

from metadata_extractor import extract_metadata

# ---------------------------
# Inicializar FastAPI
# ---------------------------

app = FastAPI()

# Habilitar CORS para permitir peticiones desde el frontend (ajusta allow_origins en producción)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],            # Cambiar por tu dominio en producción
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Cargar el modelo (lazy load para evitar tiempos largos/uso de memoria al arrancar)
# ---------------------------

model = None

def load_model():
    """Carga el modelo desde disco. Usa mmap_mode cuando sea posible para reducir memoria.
    Se invoca de forma perezosa en la primera petición."""
    global model
    if model is not None:
        return
    try:
        # Intentamos usar mmap_mode para mapas de memoria si el modelo lo soporta
        try:
            model = joblib.load("model.pkl", mmap_mode='r')
            logging.info('Model loaded with mmap_mode')
        except TypeError:
            # mmap_mode no soportado por versiones antiguas / tipos
            model = joblib.load("model.pkl")
            logging.info('Model loaded without mmap_mode')
    except Exception as e:
        logging.exception('Error loading model: %s', e)
        # Re-raise para que los handlers de endpoints puedan notificar correctamente
        raise


def get_model():
    if model is None:
        load_model()
    return model

FEATURE_COLUMNS = [
    "Machine",
    "DebugSize",
    "DebugRVA",
    "MajorImageVersion",
    "MajorOSVersion",
    "ExportRVA",
    "ExportSize",
    "IatVRA",  # name from metadata_extractor
    "MajorLinkerVersion",
    "MinorLinkerVersion",
    "NumberOfSections",
    "SizeOfStackReserve",
    "DllCharacteristics",
    "ResourceSize",
    "BitcoinAddresses"
]

# ---------------------------
# Modelo entrada manual
# ---------------------------


class ManualInput(BaseModel):
    Machine: int
    DebugSize: int
    DebugRVA: int
    MajorImageVersion: int
    MajorOSVersion: int
    ExportRVA: int
    ExportSize: int
    IatVRA: int
    MajorLinkerVersion: int
    MinorLinkerVersion: int
    NumberOfSections: int
    SizeOfStackReserve: int
    DllCharacteristics: int
    ResourceSize: int
    BitcoinAddresses: int


# ---------------------------
# Database (SQLAlchemy) helpers — Postgres in production, SQLite fallback
# ---------------------------
DB_PATH = os.getenv('STATS_DB', 'stats.db')
DATABASE_URL = os.getenv('DATABASE_URL')  # e.g. postgres://user:pass@host:port/dbname

from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, func
from sqlalchemy.orm import declarative_base, sessionmaker

# Create engine: prefer DATABASE_URL, otherwise use local SQLite file
if DATABASE_URL:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
else:
    engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


class Event(Base):
    __tablename__ = 'events'
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, nullable=False, index=True)
    ts = Column(DateTime(timezone=True), server_default=func.now())


class Comment(Base):
    __tablename__ = 'comments'
    id = Column(Integer, primary_key=True, index=True)
    text = Column(Text, nullable=False)
    ts = Column(DateTime(timezone=True), server_default=func.now())
    email_sent = Column(Boolean, default=False)


def init_db():
    # create tables if they don't exist
    Base.metadata.create_all(bind=engine)


def insert_event(event_type: str):
    db = SessionLocal()
    try:
        ev = Event(event_type=event_type)
        db.add(ev)
        db.commit()
    finally:
        db.close()


def add_comment_to_db(text: str, email_sent: int = 0):
    db = SessionLocal()
    try:
        c = Comment(text=text, email_sent=bool(email_sent))
        db.add(c)
        db.commit()
        db.refresh(c)
        return c.id
    finally:
        db.close()


def get_comments_from_db(limit: int = 50):
    db = SessionLocal()
    try:
        rows = db.query(Comment).order_by(Comment.id.desc()).limit(limit).all()
        return [{'id': r.id, 'text': r.text, 'ts': r.ts.isoformat(), 'email_sent': bool(r.email_sent)} for r in rows]
    finally:
        db.close()


def clear_comments_db():
    db = SessionLocal()
    try:
        db.query(Comment).delete()
        db.commit()
    finally:
        db.close()


def get_stats_from_db():
    db = SessionLocal()
    try:
        visits = db.query(Event).filter(Event.event_type == 'visit').count()
        files_tested = db.query(Event).filter(Event.event_type.like('test_%')).count()
        benign = db.query(Event).filter(Event.event_type == 'test_benign').count()
        ransomware = db.query(Event).filter(Event.event_type == 'test_ransomware').count()
        not_applicable = db.query(Event).filter(Event.event_type == 'test_not_applicable').count()
        return {
            'visits': visits,
            'files_tested': files_tested,
            'benign': benign,
            'ransomware': ransomware,
            'not_applicable': not_applicable
        }
    finally:
        db.close()


# ---------------------------
# Email helper (SMTP)
# ---------------------------

SMTP_HOST = os.getenv('SMTP_HOST')
SMTP_PORT = int(os.getenv('SMTP_PORT', '0')) if os.getenv('SMTP_PORT') else None
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASS = os.getenv('SMTP_PASS')
DEST_EMAIL = os.getenv('DEST_EMAIL')


def send_comment_email(text: str) -> bool:
    if not SMTP_HOST or not SMTP_PORT or not DEST_EMAIL:
        return False
    try:
        msg = EmailMessage()
        msg['Subject'] = 'Nuevo comentario - Clasificador de Ransomware'
        msg['From'] = SMTP_USER or 'noreply@example.com'
        msg['To'] = DEST_EMAIL
        msg.set_content(f"Nuevo comentario:\n\n{text}")

        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
                if SMTP_USER and SMTP_PASS:
                    server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.ehlo()
                if SMTP_PORT == 587:
                    server.starttls()
                if SMTP_USER and SMTP_PASS:
                    server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
        return True
    except Exception as e:
        logging.exception('Error sending email: %s', e)
        return False


# Inicializar DB y hacer comprobaciones al iniciar la app
@app.on_event("startup")
def on_startup():
    logging.info("Startup: initializing application")
    # Inicializar la base de datos de forma segura
    try:
        init_db()
        logging.info("Database initialized successfully")
    except Exception as e:
        logging.exception("Database initialization failed: %s", e)

    # Información sobre el archivo del modelo (sin cargarlo)
    try:
        from pathlib import Path
        p = Path("model.pkl")
        if p.exists():
            st = p.stat()
            logging.info("Model file present: size=%d bytes, mtime=%s", st.st_size, st.st_mtime)
        else:
            logging.warning("Model file 'model.pkl' not found at startup")
    except Exception as e:
        logging.exception("Error checking model file metadata: %s", e)

    logging.info("Startup complete")

# ---------------------------
# ENDPOINTS API
# ---------------------------

@app.get("/api")
def root():
    return {"message": "API funcionando correctamente"}


@app.post("/predict")
async def predict(file: UploadFile = File(...)):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name

        data = extract_metadata(tmp_path)
        if data is None:
            insert_event('test_not_applicable')
            return {"error": "No se pudieron extraer metadatos del archivo."}

        df = pd.DataFrame([data], columns=FEATURE_COLUMNS)
        try:
            m = get_model()
            pred = m.predict(df)[0]
        except Exception as e:
            # registrar error en test
            insert_event('test_error')
            raise HTTPException(status_code=500, detail=f"Error al predecir: {e}")

        label = "benign" if pred == 1 else "ransomware"

        # registrar evento
        insert_event('test_' + ("benign" if label == 'benign' else "ransomware"))

        return {"prediction": label, "features": data}

    except Exception as e:
        insert_event('test_error')
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict_manual")
def predict_manual(data: ManualInput):

    df = pd.DataFrame([data.dict()], columns=FEATURE_COLUMNS)
    try:
        m = get_model()
        pred = m.predict(df)[0]
    except Exception as e:
        insert_event('test_error')
        raise HTTPException(status_code=500, detail=f"Error al predecir: {e}")

    label = "benign" if pred == 1 else "ransomware"

    # registrar evento
    insert_event('test_' + ("benign" if label == 'benign' else "ransomware"))

    return {"prediction": label, "features": data.dict()}


# ---------------------------
# Comentarios y estadisticas
# ---------------------------

class CommentIn(BaseModel):
    text: str


@app.post('/comment')
def post_comment(payload: CommentIn):
    text = payload.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail='Empty comment')

    sent = 1 if send_comment_email(text) else 0
    cid = add_comment_to_db(text, sent)
    return {'id': cid, 'text': text, 'email_sent': bool(sent)}


@app.get('/comments')
def get_comments(limit: Optional[int] = 50):
    return get_comments_from_db(limit)


@app.post('/comments/clear')
def clear_comments():
    clear_comments_db()
    return {'ok': True}


@app.post('/visit')
def visit():
    insert_event('visit')
    return {'ok': True}


@app.get('/stats')
def stats():
    return get_stats_from_db()


# ---------------------------
# Model status (no carga del modelo)
# ---------------------------
from pathlib import Path

@app.get('/model_status')
def model_status():
    """Devuelve metadata de `model.pkl` y si el modelo está ya cargado en memoria.
    NO intenta cargar el modelo en disco (safe read-only check).
    """
    p = Path("model.pkl")
    info = { 'exists': p.exists() }
    if p.exists():
        try:
            st = p.stat()
            info.update({ 'size': st.st_size, 'mtime': st.st_mtime })
        except Exception as e:
            info.update({ 'stat_error': str(e) })
    return { 'model': info, 'loaded_in_memory': model is not None }



# ---------------------------
# SERVIR FRONTEND
# ---------------------------

# Ruta principal → index.html
@app.get("/")
def frontend():
    return FileResponse("static/index.html")


# Carpeta de archivos estáticos
app.mount("/static", StaticFiles(directory="static"), name="static")

