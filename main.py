from fastapi import FastAPI, UploadFile, File, HTTPException, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import joblib
import tempfile
import os
import sqlite3
import smtplib
import logging
from email.message import EmailMessage
from typing import Optional
from pathlib import Path
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, func
from sqlalchemy.orm import declarative_base, sessionmaker

# Importar extractor local
from metadata_extractor import extract_metadata

# ---------------------------
# Configuración y Modelos Pydantic (Definidos al inicio)
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

class CommentIn(BaseModel):
    text: str

# ---------------------------
# Inicializar FastAPI
# ---------------------------

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Configuración de Base de Datos
# ---------------------------
DB_PATH = os.getenv('STATS_DB', 'stats.db')
DATABASE_URL = os.getenv('DATABASE_URL')

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
    Base.metadata.create_all(bind=engine)

# ---------------------------
# Carga del Modelo ML
# ---------------------------
model = None

def get_model():
    global model
    if model is None:
        try:
            model = joblib.load("model.pkl")
            logging.info('Modelo cargado correctamente.')
        except Exception as e:
            logging.error(f'Error al cargar model.pkl: {e}')
            raise HTTPException(status_code=500, detail="Modelo no disponible.")
    return model

FEATURE_COLUMNS = [
    "Machine", "DebugSize", "DebugRVA", "MajorImageVersion", "MajorOSVersion",
    "ExportRVA", "ExportSize", "IatVRA", "MajorLinkerVersion", "MinorLinkerVersion",
    "NumberOfSections", "SizeOfStackReserve", "DllCharacteristics", "ResourceSize",
    "BitcoinAddresses"
]

# ---------------------------
# Helpers (DB y Email)
# ---------------------------
def insert_event(event_type: str):
    with SessionLocal() as db:
        ev = Event(event_type=event_type)
        db.add(ev)
        db.commit()

def add_comment_to_db(text: str, email_sent: bool = False):
    with SessionLocal() as db:
        c = Comment(text=text, email_sent=email_sent)
        db.add(c)
        db.commit()
        db.refresh(c)
        return c.id

def get_stats_from_db():
    with SessionLocal() as db:
        return {
            'visits': db.query(Event).filter(Event.event_type == 'visit').count(),
            'files_tested': db.query(Event).filter(Event.event_type.like('test_%')).count(),
            'benign': db.query(Event).filter(Event.event_type == 'test_benign').count(),
            'ransomware': db.query(Event).filter(Event.event_type == 'test_ransomware').count(),
            'not_applicable': db.query(Event).filter(Event.event_type == 'test_not_applicable').count()
        }

# Variables de entorno para Email y Admin
ADMIN_TOKEN = os.getenv('ADMIN_TOKEN')

def _check_admin_token(token: str) -> bool:
    return ADMIN_TOKEN and token == ADMIN_TOKEN

@app.on_event("startup")
def on_startup():
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
        os.remove(tmp_path) # Limpieza

        if data is None:
            insert_event('test_not_applicable')
            return {"error": "No se pudieron extraer metadatos."}

        df = pd.DataFrame([data], columns=FEATURE_COLUMNS)
        pred = get_model().predict(df)[0]
        label = "benign" if pred == 1 else "ransomware"
        insert_event(f'test_{label}')

        return {"prediction": label, "features": data}
    except Exception as e:
        insert_event('test_error')
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict_manual")
def predict_manual(data: ManualInput):
    try:
        df = pd.DataFrame([data.dict()], columns=FEATURE_COLUMNS)
        pred = get_model().predict(df)[0]
        label = "benign" if pred == 1 else "ransomware"
        insert_event(f'test_{label}')
        return {"prediction": label, "features": data.dict()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/comment')
def post_comment(payload: CommentIn):
    text = payload.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail='Comentario vacío')
    
    # Aquí puedes integrar send_comment_email si está configurado
    cid = add_comment_to_db(text, email_sent=False)
    return {'id': cid, 'text': text}

@app.get('/comments')
def get_comments(limit: int = 50):
    with SessionLocal() as db:
        rows = db.query(Comment).order_by(Comment.id.desc()).limit(limit).all()
        return [{'id': r.id, 'text': r.text, 'ts': r.ts.isoformat()} for r in rows]

@app.post('/visit')
def visit():
    insert_event('visit')
    return {'ok': True}

@app.get('/stats')
def stats():
    return get_stats_from_db()

# --- Admin Endpoints ---
@app.get('/admin/auth')
def admin_auth(x_admin_token: Optional[str] = Header(None)):
    if not _check_admin_token(x_admin_token):
        raise HTTPException(status_code=403, detail='Token inválido')
    return {'ok': True}

# Servir Frontend
@app.get("/")
def frontend():
    index_path = Path("static/index.html")
    if index_path.exists():
        return FileResponse(index_path)
    return {"error": "index.html no encontrado en carpeta static"}

app.mount("/static", StaticFiles(directory="static"), name="static")