import os
from .entropy import file_entropy
from .api_detector import scan_keywords
import numpy as np


def extract_features(file_path):
    """
    Extract features from a file for ML model prediction.
    
    Features (for entropy-based model):
    - entropy: Shannon entropy of file content
    - crypto_hits: Count of crypto API references
    - file_hits: Count of file manipulation API references  
    - ransom_hits: Count of ransom-related keywords
    - file_size: Size of the file in bytes
    
    Returns a feature array compatible with the trained model.
    Currently returns 5 features for entropy-based model.
    """
    entropy = file_entropy(file_path)

    crypto_hits, file_hits, ransom_hits = scan_keywords(file_path)

    file_size = os.path.getsize(file_path)

    # Return 5 features as per project requirements
    return [
        entropy,
        crypto_hits,
        file_hits,
        ransom_hits,
        file_size
    ]


def extract_pe_features(file_path):
    """
    Extract PE (Portable Executable) file features for the ML model.
    These are the 14 features the model was trained on.
    
    Note: This returns default values for non-PE files since the model
    was trained on PE features only.
    """
    try:
        # Try to read PE headers for actual features
        with open(file_path, "rb") as f:
            data = f.read()
            
        # Check if it's a PE file (starts with MZ)
        if not data.startswith(b"MZ"):
            # Return default values for non-PE files
            return [0] * 14
            
        # Extract basic PE info - these are placeholder values
        # In a real implementation, you'd parse the PE headers
        features = [
            0,  # DebugSize
            0,  # DebugRVA
            0,  # MajorImageVersion
            0,  # MajorOSVersion
            0,  # ExportRVA
            0,  # ExportSize
            0,  # IatVRA
            0,  # MajorLinkerVersion
            0,  # MinorLinkerVersion
            0,  # NumberOfSections
            0,  # SizeOfStackReserve
            0,  # DllCharacteristics
            0,  # ResourceSize
            0,  # BitcoinAddresses
        ]
        
        return features
        
    except Exception:
        return [0] * 14
