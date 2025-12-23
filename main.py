from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Header
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
import logging
from email.message import EmailMessage
from typing import Optional, List
from pathlib import Path

from metadata_extractor import extract_metadata

# Configuración de Logging
logging.basicConfig(level=logging.INFO)

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
# Modelo y Predicción (Lazy Load)
# ---------------------------
model = None

def load_model():
    global model
    if model is not None:
        return
    try:
        # Intento de carga optimizada
        model = joblib.load("model.pkl")
        logging.info('Modelo cargado exitosamente.')
    except Exception as e:
        logging.error(f'Error cargando el modelo: {e}')
        raise

def get_model():
    if model is None:
        load_model()
    return model

FEATURE_COLUMNS = [
    "Machine", "DebugSize", "DebugRVA", "MajorImageVersion", 
    "MajorOSVersion", "ExportRVA", "ExportSize", "IatVRA", 
    "MajorLinkerVersion", "MinorLinkerVersion", "NumberOfSections", 
    "SizeOfStackReserve", "DllCharacteristics", "ResourceSize", "BitcoinAddresses"
]

class ManualInput(BaseModel):
    Machine: int; DebugSize: int; DebugRVA: int; MajorImageVersion: int
    MajorOSVersion: int; ExportRVA: int; ExportSize: int; IatVRA: int
    MajorLinkerVersion: int; MinorLinkerVersion: int; NumberOfSections: int
    SizeOfStackReserve: int; DllCharacteristics: int; ResourceSize: int
    BitcoinAddresses: int

# ---------------------------
# Base de Datos (SQLAlchemy)
# ---------------------------
DB_PATH = os.getenv('STATS_DB', 'stats.db')
DATABASE_URL = os.getenv('DATABASE_URL')

from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session

if DATABASE_URL:
    # Ajuste para compatibilidad con Heroku/Render postgres:// -> postgresql://
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
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

# Dependencia para obtener la DB en los endpoints (Mejor práctica)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)

# ---------------------------
# Utilidades de Correo y Admin
# ---------------------------
ADMIN_TOKEN = os.getenv('ADMIN_TOKEN')

def _check_admin_token(token: str) -> bool:
    if not ADMIN_TOKEN: return False
    return token == ADMIN_TOKEN

def send_comment_email(text: str) -> bool:
    host = os.getenv('SMTP_HOST')
    port = int(os.getenv('SMTP_PORT', '0'))
    if not host or not port: return False
    try:
        msg = EmailMessage()
        msg['Subject'] = 'Nuevo comentario - Ransomware AI'
        msg['From'] = os.getenv('SMTP_USER', 'noreply@ai.com')
        msg['To'] = os.getenv('DEST_EMAIL')
        msg.set_content(text)
        with smtplib.SMTP(host, port) as server:
            if port == 587: server.starttls()
            server.login(os.getenv('SMTP_USER'), os.getenv('SMTP_PASS'))
            server.send_message(msg)
        return True
    except: return False

@app.on_event("startup")
def on_startup():
    init_db()

# ---------------------------
# ENDPOINTS API (CORREGIDOS)
# ---------------------------

@app.get("/api")
def root():
    return {"status": "online", "message": "API funcionando"}

@app.post("/predict")
async def predict(file: UploadFile = File(...), db: Session = Depends(get_db)):
    tmp_path = None
    try:
        # Guardar archivo temporal
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name

        # Extraer metadatos
        data = extract_metadata(tmp_path)
        
        if data is None:
            db.add(Event(event_type='test_not_applicable'))
            db.commit()
            return {"error": "El archivo no es un ejecutable PE válido."}

        # Predicción
        df = pd.DataFrame([data], columns=FEATURE_COLUMNS)
        m = get_model()
        pred = m.predict(df)[0]
        label = "benign" if pred == 1 else "ransomware"

        # Registrar evento
        db.add(Event(event_type=f'test_{label}'))
        db.commit()

        return {"prediction": label, "features": data}

    except Exception as e:
        db.add(Event(event_type='test_error'))
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # --- CORRECCIÓN CRÍTICA: Borrar siempre el archivo temporal ---
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

@app.post('/comment')
def post_comment(payload: CommentIn, db: Session = Depends(get_db)):
    text = payload.text.strip()
    if not text: raise HTTPException(status_code=400, detail='Comentario vacío')
    
    sent = send_comment_email(text)
    new_comment = Comment(text=text, email_sent=sent)
    db.add(new_comment)
    db.commit()
    return {"ok": True}

@app.get('/stats')
def get_stats(db: Session = Depends(get_db)):
    return {
        'visits': db.query(Event).filter(Event.event_type == 'visit').count(),
        'files_tested': db.query(Event).filter(Event.event_type.like('test_%')).count(),
        'ransomware': db.query(Event).filter(Event.event_type == 'test_ransomware').count(),
        'benign': db.query(Event).filter(Event.event_type == 'test_benign').count()
    }

# ---------------------------
# SERVIR FRONTEND (CORREGIDO)
# ---------------------------

# Importante: Estas rutas van al final para no interferir con los endpoints
@app.get("/")
def read_index():
    # Busca el index.html dentro de la carpeta static
    index_path = os.path.join("static", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({"error": "index.html no encontrado en carpeta /static"}, status_code=404)

app.mount("/static", StaticFiles(directory="static"), name="static")