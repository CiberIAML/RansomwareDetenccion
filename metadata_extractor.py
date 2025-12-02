import pefile
import re


def extract_metadata(file_path):
    try:
        pe = pefile.PE(file_path)

        # Basic PE header fields
        Machine = pe.FILE_HEADER.Machine
        NumberOfSections = pe.FILE_HEADER.NumberOfSections
        MajorLinkerVersion = pe.OPTIONAL_HEADER.MajorLinkerVersion
        MinorLinkerVersion = pe.OPTIONAL_HEADER.MinorLinkerVersion
        MajorImageVersion = pe.OPTIONAL_HEADER.MajorImageVersion
        MajorOSVersion = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        SizeOfStackReserve = pe.OPTIONAL_HEADER.SizeOfStackReserve
        DllCharacteristics = pe.OPTIONAL_HEADER.DllCharacteristics

        # Debug info
        DebugSize = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size
        DebugRVA = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress

        # Export table
        ExportSize = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size
        ExportRVA = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress

        # Import Address Table (IAT)
        IatVRA = pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress

        # Resources
        ResourceSize = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size

        # Bitcoin address detection
        with open(file_path, "rb") as f:
            content = f.read().decode('latin-1', errors='ignore')

        btc_matches = re.findall(r"([13][a-km-zA-HJ-NP-Z1-9]{25,34})", content)
        BitcoinAddresses = len(set(btc_matches))

        return {
            "Machine": Machine,
            "DebugSize": DebugSize,
            "DebugRVA": DebugRVA,
            "MajorImageVersion": MajorImageVersion,
            "MajorOSVersion": MajorOSVersion,
            "ExportRVA": ExportRVA,
            "ExportSize": ExportSize,
            "IatVRA": IatVRA,   # ← CORRECTO
            "MajorLinkerVersion": MajorLinkerVersion,
            "MinorLinkerVersion": MinorLinkerVersion,
            "NumberOfSections": NumberOfSections,
            "SizeOfStackReserve": SizeOfStackReserve,
            "DllCharacteristics": DllCharacteristics,
            "ResourceSize": ResourceSize,
            "BitcoinAddresses": BitcoinAddresses
        }

    except Exception as e:
        print("Error extrayendo metadatos:", e)
        return None
