from fastapi import FastAPI, UploadFile, File
from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import pandas as pd
import joblib
import tempfile

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
    "IatVRA",
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
            return {"error": "No se pudieron extraer metadatos del archivo."}

        df = pd.DataFrame([data], columns=FEATURE_COLUMNS)
        pred = model.predict(df)[0]
        label = "benign" if pred == 1 else "ransomware"

        return {"prediction": label, "features": data}

    except Exception as e:
        return {"error": str(e)}


@app.post("/predict_manual")
def predict_manual(data: ManualInput):

    df = pd.DataFrame([data.dict()], columns=FEATURE_COLUMNS)
    pred = model.predict(df)[0]
    label = "benign" if pred == 1 else "ransomware"

    return {"prediction": label, "features": data.dict()}

# main.py (AGREGAR ESTO AL FINAL DEL ARCHIVO)

# --------------------------
# Configuración para servir el Frontend (index.html)
# --------------------------

## 1. Montar el directorio estático
app.mount("/static", StaticFiles(directory="."), name="static")

# 2. Ruta Raíz ("/")
@app.get("/")
async def serve_index():
    return FileResponse('index.html')
