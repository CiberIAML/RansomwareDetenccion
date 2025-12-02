
import joblib
import numpy as np
from flask import Flask, request, render_template
import pefile # Necesario para analizar el archivo PE

# Lista de características en el ORDEN EXACTO del entrenamiento
FEATURE_KEYS = [
    'Machine', 'DebugSize', 'DebugRVA', 'MajorImageVersion', 'MajorOSVersion',
    'ExportRVA', 'ExportSize', 'IatVRA', 'MajorLinkerVersion', 'MinorLinkerVersion',
    'NumberOfSections', 'SizeOfStackReserve', 'DllCharacteristics', 'ResourceSize',
    'BitcoinAddresses'
]

# 1. Cargar el Modelo y el Escalador
try:
    model = joblib.load('modelo_malware.pkl')
    scaler = joblib.load('scaler.pkl')
except FileNotFoundError:
    print("Error al cargar modelos. Asegúrate de que los archivos PKL estén en la carpeta.")
    exit()

# 2. Función de Extracción de Características PE
def extract_pe_features(file_bytes):
    # Inicializar las 15 características con valor 0 por defecto
    features = {key: 0 for key in FEATURE_KEYS}
    
    try:
        pe = pefile.PE(data=file_bytes, fast_load=True)
    except pefile.PEFormatError:
        raise ValueError("El archivo no es un archivo PE válido (EXE, DLL).")
    except Exception as e:
        # Esto captura cualquier otro error al cargar el binario
        raise ValueError(f"Error al cargar el archivo PE: {e}")

    # --- 1. Extraer Encabezado de Archivo (Seguro) ---
    if hasattr(pe, 'FILE_HEADER'):
        features['Machine'] = pe.FILE_HEADER.Machine
        features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections

    # --- 2. Extraer Cabecera Opcional ---
    if hasattr(pe, 'OPTIONAL_HEADER'):
        opt_header = pe.OPTIONAL_HEADER
        
        # Versiones y Características (Estos son seguros si OPTIONAL_HEADER existe)
        features['MajorImageVersion'] = opt_header.MajorImageVersion
        features['MajorOSVersion'] = opt_header.MajorOperatingSystemVersion
        features['MajorLinkerVersion'] = opt_header.MajorLinkerVersion
        features['MinorLinkerVersion'] = opt_header.MinorLinkerVersion
        features['SizeOfStackReserve'] = opt_header.SizeOfStackReserve
        features['DllCharacteristics'] = opt_header.DllCharacteristics

        # --- 3. Bloque TRY-EXCEPT para DataDirectory (CORRECCIÓN CRÍTICA DE ATTRIBUTEERROR) ---
        try:
            # Debug
            dir_debug = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']
            if opt_header.DataDirectory[dir_debug].VirtualAddress != 0:
                features['DebugRVA'] = opt_header.DataDirectory[dir_debug].VirtualAddress
                features['DebugSize'] = opt_header.DataDirectory[dir_debug].Size
            
            # Export Table
            dir_export = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
            if opt_header.DataDirectory[dir_export].VirtualAddress != 0:
                features['ExportRVA'] = opt_header.DataDirectory[dir_export].VirtualAddress
                features['ExportSize'] = opt_header.DataDirectory[dir_export].Size

            # IAT (Import Address Table)
            dir_import = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
            features['IatVRA'] = opt_header.DataDirectory[dir_import].VirtualAddress
            
            # Resources
            dir_resource = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
            if opt_header.DataDirectory[dir_resource].VirtualAddress != 0:
                features['ResourceSize'] = opt_header.DataDirectory[dir_resource].Size

        except AttributeError:
            # Si DataDirectory no existe, los valores permanecen en 0.
            pass
        except Exception:
            # Otros errores de lectura, los valores permanecen en 0.
            pass
    
    features['BitcoinAddresses'] = 0 # Se mantiene en 0 (requiere análisis de strings más profundo).
    
    pe.close()
    
    # Devuelve la lista de valores en el ORDEN EXACTO del modelo
    return [features[key] for key in FEATURE_KEYS]

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

# 3. Ruta de Predicción (Maneja AMBAS entradas: Archivo y Manual)
@app.route('/predict', methods=['POST'])
def predict():
    try:
        # --- LÓGICA DE SUBIDA DE ARCHIVO ---
        if 'pe_file' in request.files and request.files['pe_file'].filename != '':
            pe_file = request.files['pe_file']
            file_bytes = pe_file.read()
            features = extract_pe_features(file_bytes)
            source = "Archivo PE"
        
        # --- LÓGICA DE ENTRADA MANUAL ---
        elif 'Machine' in request.form:
            data = request.form.to_dict()
            features = [float(data[key]) for key in FEATURE_KEYS]
            source = "Entrada Manual"
            
        else:
            return render_template('index.html', prediction_text='Error: Debe subir un archivo o llenar los 15 campos.')

        # --- Lógica de Predicción Común ---
        features_array = np.array(features).reshape(1, -1)
        scaled_features = scaler.transform(features_array) 
        prediction = model.predict(scaled_features)[0]
        
        # Mapear el resultado (1=Benigno, 0=Malware)
        if prediction == 1:
            resultado = f"✅ Archivo Benigno (Seguro) - Fuente: {source}"
        else:
            resultado = f"🔴 ¡POSIBLE MALWARE! (Malicioso) - Fuente: {source}"
            
        return render_template('index.html', prediction_text=resultado)
        
    except ValueError as ve:
        return render_template('index.html', prediction_text=f'Error de datos: {ve}')
    except Exception as e:
        return render_template('index.html', prediction_text=f'Error inesperado: {e}')

if __name__ == "__main__":
    app.run(debug=True)