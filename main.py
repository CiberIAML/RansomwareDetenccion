from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import pandas as pd
import joblib
import tempfile

import os
import sqlite3
import smtplib
from email.message import EmailMessage
from typing import Optional

from metadata_extractor import extract_metadata

# ---------------------------
# Inicializar FastAPI
# ---------------------------

app = FastAPI()

# ---------------------------
# Cargar el modelo
# ---------------------------

model = joblib.load("model.pkl")

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
        print('Error sending email:', e)
        return False


# Inicializar DB al iniciar la app
init_db()

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
            pred = model.predict(df)[0]
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
        pred = model.predict(df)[0]
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
# SERVIR FRONTEND
# ---------------------------

# Ruta principal → index.html
@app.get("/")
def frontend():
    return FileResponse("static/index.html")


# Carpeta de archivos estáticos
app.mount("/static", StaticFiles(directory="static"), name="static")

