import pefile
import re


def extract_metadata(file_path):
    # Inicializar las características con 0 para manejarlas si fallan
    features = {
        "Machine": 0, "DebugSize": 0, "DebugRVA": 0, "MajorImageVersion": 0,
        "MajorOSVersion": 0, "ExportRVA": 0, "ExportSize": 0, "IatVRA": 0,
        "MajorLinkerVersion": 0, "MinorLinkerVersion": 0, "NumberOfSections": 0,
        "SizeOfStackReserve": 0, "DllCharacteristics": 0, "ResourceSize": 0,
        "BitcoinAddresses": 0
    }
    
    try:
        pe = pefile.PE(file_path, fast_load=True)

        # Basic PE header fields
        features["Machine"] = pe.FILE_HEADER.Machine
        features["NumberOfSections"] = pe.FILE_HEADER.NumberOfSections
        
        opt_header = pe.OPTIONAL_HEADER
        features["MajorLinkerVersion"] = opt_header.MajorLinkerVersion
        features["MinorLinkerVersion"] = opt_header.MinorLinkerVersion
        features["MajorImageVersion"] = opt_header.MajorImageVersion
        features["MajorOSVersion"] = opt_header.MajorOperatingSystemVersion
        features["SizeOfStackReserve"] = opt_header.SizeOfStackReserve
        features["DllCharacteristics"] = opt_header.DllCharacteristics

        # Directorios de Datos (Envuelto en try-except para manejar archivos PE incompletos)
        data_dir = opt_header.DATA_DIRECTORY

        try:
            # Export table (Index 0)
            features["ExportSize"] = data_dir[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].Size
            features["ExportRVA"] = data_dir[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress
        except (AttributeError, IndexError): pass
        
        try:
            # Import Address Table (IAT) (Index 1) - Índice 1 es la dirección correcta para IAT.
            features["IatVRA"] = data_dir[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress
        except (AttributeError, IndexError): pass

        try:
            # Resources (Index 2)
            features["ResourceSize"] = data_dir[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].Size
        except (AttributeError, IndexError): pass

        try:
            # Debug info (Index 6)
            features["DebugSize"] = data_dir[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].Size
            features["DebugRVA"] = data_dir[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].VirtualAddress
        except (AttributeError, IndexError): pass

        # Bitcoin address detection
        with open(file_path, "rb") as f:
            content = f.read().decode('latin-1', errors='ignore')

        btc_matches = re.findall(r"([13][a-km-zA-HJ-NP-Z1-9]{25,34})", content)
        features["BitcoinAddresses"] = len(set(btc_matches))
        
        pe.close()
        return features

    except pefile.PEFormatError:
        print("Error: Archivo no es un formato PE válido.")
        return None
    except Exception as e:
        print("Error extrayendo metadatos:", e)
        return None