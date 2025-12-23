# Importaciones de FastAPI para crear la API, manejar archivos y errores
from fastapi import FastAPI, UploadFile, File, HTTPException, Header
# Para servir archivos como imágenes, CSS o JS
from fastapi.staticfiles import StaticFiles
# Para enviar respuestas de archivos (HTML) o respuestas JSON al navegador
from fastapi.responses import FileResponse, JSONResponse
# Para permitir que el frontend se comunique con el backend desde distintos dominios
from fastapi.middleware.cors import CORSMiddleware
# Pydantic ayuda a validar que los datos enviados por el usuario sean correctos
from pydantic import BaseModel
# Librerías para manejo de datos, carga de la IA y archivos temporales
import pandas as pd
import joblib
import tempfile
import os
import logging
from typing import Optional
from pathlib import Path
# SQLAlchemy es el motor para conectar y manejar la base de datos (SQL)
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Intento de importar el extractor de metadatos PE que creaste
try:
    from metadata_extractor import extract_metadata
except ImportError:
    logging.error("No se encontró metadata_extractor.py")

# ---------------------------
# Configuración de Base de Datos
# ---------------------------
# Obtiene la URL de la base de datos desde las variables de entorno (Render)
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    # Si estamos en Render/Postgres, ajustamos el nombre del protocolo para SQLAlchemy
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    engine = create_engine(DATABASE_URL)
else:
    # Si es local, crea un archivo llamado stats.db automáticamente (SQLite)
    engine = create_engine("sqlite:///stats.db", connect_args={"check_same_thread": False})

# Configuramos la "fábrica" de sesiones para hacer consultas a la base de datos
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Clase base para que nuestros modelos hereden y se conviertan en tablas SQL
Base = declarative_base()

# Tabla para guardar eventos como visitas y cantidad de análisis realizados
class Event(Base):
    __tablename__ = 'events'
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, nullable=False, index=True) # Ejemplo: 'visit', 'test_benigno'
    ts = Column(DateTime(timezone=True), server_default=func.now()) # Fecha y hora automática

# Tabla para guardar los comentarios de los usuarios
class Comment(Base):
    __tablename__ = 'comments'
    id = Column(Integer, primary_key=True, index=True)
    text = Column(Text, nullable=False)
    ts = Column(DateTime(timezone=True), server_default=func.now())
    email_sent = Column(Boolean, default=False)

# ---------------------------
# Modelos Pydantic (Validación de datos de entrada)
# ---------------------------
# Define qué números debe enviar el usuario si quiere hacer una prueba manual
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

# Define que un comentario solo debe traer un campo de texto
class CommentIn(BaseModel):
    text: str

# ---------------------------
# Inicializar FastAPI
# ---------------------------
app = FastAPI(title="Ransomware Detector API")

# Configuración de seguridad CORS para que tu web funcione en el navegador sin bloqueos
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Carga del Modelo ML
# ---------------------------
model = None
# Lista exacta de columnas que el modelo espera recibir (en el mismo orden)
FEATURE_COLUMNS = [
    "Machine", "DebugSize", "DebugRVA", "MajorImageVersion", "MajorOSVersion",
    "ExportRVA", "ExportSize", "IatVRA", "MajorLinkerVersion", "MinorLinkerVersion",
    "NumberOfSections", "SizeOfStackReserve", "DllCharacteristics", "ResourceSize",
    "BitcoinAddresses"
]

# Función "Lazy Load" para cargar el archivo .pkl solo cuando se necesite (ahorra RAM)
def get_model():
    global model
    if model is None:
        model_path = Path("model.pkl")
        if not model_path.exists():
            logging.error("model.pkl NO encontrado en el servidor")
            raise HTTPException(status_code=500, detail="Archivo de modelo no encontrado.")
        try:
            model = joblib.load(model_path) # Carga la IA a la memoria
            logging.info('Modelo cargado correctamente.')
        except Exception as e:
            logging.error(f'Error al cargar model.pkl: {e}')
            raise HTTPException(status_code=500, detail="Error al cargar el modelo.")
    return model

# ---------------------------
# Helpers (Funciones de apoyo)
# ---------------------------
# Función rápida para insertar eventos en la base de datos
def insert_event(event_type: str):
    try:
        with SessionLocal() as db:
            ev = Event(event_type=event_type)
            db.add(ev)
            db.commit()
    except Exception as e:
        logging.error(f"Error DB insert_event: {e}")

# Se ejecuta al encender el servidor: crea las tablas si no existen
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

# ---------------------------
# ENDPOINTS API (Las rutas de tu servidor)
# ---------------------------

# Ruta simple para verificar que la API está viva
@app.get("/api")
def api_status():
    return {"message": "API funcionando correctamente"}

# Ruta para recibir un archivo .exe y analizarlo con la IA
@app.post("/predict")
async def predict(file: UploadFile = File(...)):
    try:
        # 1. Crea un archivo temporal para guardar lo que subió el usuario
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name

        # 2. Extrae los metadatos técnicos del archivo usando metadata_extractor.py
        data = extract_metadata(tmp_path)
        
        # 3. Borra el archivo temporal del servidor (por seguridad y espacio)
        if os.path.exists(tmp_path):
            os.remove