from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import joblib
import numpy as np
from pathlib import Path
import shutil
import time
import networkx as nx
import logging
import pefile

# PDF genome library
try:
    from pdf_genome import PdfGenome
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="Malware Detection API",
    description="PDF & PE Malware Detection",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Upload config
UPLOAD_FOLDER = Path("uploads")
UPLOAD_FOLDER.mkdir(exist_ok=True)
ALLOWED_EXTENSIONS = {"pdf", "exe"}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

# Load PDF model and selected features
pdf_model = None
pdf_selected_features = [
    'avg_clustering_coefficient',
    'avg_degree',
    'degree_assortativity',
    'density',
    'num_leaves',
    'num_nodes'
]

# Load PE model and selected features
pe_model = None
pe_selected_features = [
    'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData',
    'AddressOfEntryPoint', 'NumberOfSymbols', 'NumberOfSections',
    'TimeDateStamp', 'MajorLinkerVersion', 'MinorLinkerVersion',
    'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
    'MajorImageVersion', 'MinorImageVersion', 'Subsystem', 'DllCharacteristics'
]

@app.on_event("startup")
async def load_models():
    global pdf_model, pe_model
    try:
        # PDF model
        pdf_data = joblib.load("pdf_malware_model.joblib")
        if isinstance(pdf_data, dict) and 'model' in pdf_data:
            pdf_model = pdf_data['model']
        elif hasattr(pdf_data, 'predict'):
            pdf_model = pdf_data
        logger.info("PDF model loaded ✅")
    except Exception as e:
        logger.error(f"Failed to load PDF model: {e}")

    try:
        # PE model
        pe_data = joblib.load("pe_binary_model.joblib")
        if isinstance(pe_data, dict) and 'model' in pe_data:
            pe_model = pe_data['model']
        elif hasattr(pe_data, 'predict'):
            pe_model = pe_data
        logger.info("PE model loaded ✅")
    except Exception as e:
        logger.error(f"Failed to load PE model: {e}")

def extract_pdf_features(file_path: str):
    """Extract graph-based features from a PDF file (only 6 used)."""
    if not PDF_AVAILABLE:
        return None
    try:
        pdf_obj = PdfGenome.load_genome(file_path, pickleable=True)
        paths = PdfGenome.get_object_paths(pdf_obj)
        G = nx.DiGraph()
        for edge in paths:
            for i in range(len(edge)-1):
                G.add_edge(edge[i], edge[i+1])
        if G.number_of_nodes() == 0:
            return None

        children_count = [degree for _, degree in G.out_degree()]
        try:
            deg_assort = nx.degree_assortativity_coefficient(G.to_undirected())
            if np.isnan(deg_assort):
                deg_assort = 0.0
        except:
            deg_assort = 0.0

        features = {
            'num_nodes': G.number_of_nodes(),
            'num_leaves': sum(1 for _, deg in G.out_degree() if deg == 0),
            'avg_degree': sum(dict(G.degree()).values()) / G.number_of_nodes(),
            'density': nx.density(G),
            'avg_clustering_coefficient': nx.average_clustering(G.to_undirected()),
            'degree_assortativity': deg_assort
        }
        return features
    except Exception as e:
        logger.error(f"PDF feature extraction failed: {e}")
        return None

def extract_pe_features(file_path: str):
    """Extract 15 PE header features."""
    try:
        features = {}
        with pefile.PE(file_path) as pe:
            # COFF header
            features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
            features['TimeDateStamp'] = pe.FILE_HEADER.TimeDateStamp
            features['NumberOfSymbols'] = pe.FILE_HEADER.NumberOfSymbols
            # Optional header
            opt = pe.OPTIONAL_HEADER
            features['SizeOfCode'] = opt.SizeOfCode
            features['SizeOfInitializedData'] = opt.SizeOfInitializedData
            features['SizeOfUninitializedData'] = opt.SizeOfUninitializedData
            features['AddressOfEntryPoint'] = opt.AddressOfEntryPoint
            features['MajorLinkerVersion'] = opt.MajorLinkerVersion
            features['MinorLinkerVersion'] = opt.MinorLinkerVersion
            features['MajorOperatingSystemVersion'] = opt.MajorOperatingSystemVersion
            features['MinorOperatingSystemVersion'] = opt.MinorOperatingSystemVersion
            features['MajorImageVersion'] = opt.MajorImageVersion
            features['MinorImageVersion'] = opt.MinorImageVersion
            features['Subsystem'] = opt.Subsystem
            features['DllCharacteristics'] = opt.DllCharacteristics
        return features
    except Exception as e:
        logger.error(f"PE feature extraction failed: {e}")
        return None

def get_file_size_readable(size_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"

@app.post("/api/scan")
async def scan_file(file: UploadFile = File(...)):
    start_time = time.time()
    file_ext = file.filename.split('.')[-1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        await file.close()
        raise HTTPException(400, "Unsupported file type")

    temp_path = UPLOAD_FOLDER / file.filename
    try:
        # Save file
        with open(temp_path, "wb") as buf:
            shutil.copyfileobj(file.file, buf)
        await file.close()

        if temp_path.stat().st_size > MAX_FILE_SIZE:
            temp_path.unlink()
            raise HTTPException(400, "File too large")

        # Extract features
        if file_ext == "pdf":
            features = extract_pdf_features(str(temp_path))
            model = pdf_model
            selected_features = pdf_selected_features
        else:  # exe
            features = extract_pe_features(str(temp_path))
            model = pe_model
            selected_features = pe_selected_features

        if features is None or model is None:
            temp_path.unlink()
            raise HTTPException(500, "Feature extraction or model failed")

        # Prediction
        feature_values = np.array([features[f] for f in selected_features]).reshape(1, -1)
        prediction = model.predict(feature_values)[0]
        probability = model.predict_proba(feature_values)[0]
        malicious_prob = float(probability[1])

        scan_time = time.time() - start_time
        file_size = get_file_size_readable(temp_path.stat().st_size)

        temp_path.unlink()  # safe deletion

        return JSONResponse({
            "filename": file.filename,
            "file_type": "PDF Document" if file_ext=="pdf" else "PE Binary",
            "file_size": file_size,
            "is_malicious": bool(prediction == 1),
            "malicious_probability": malicious_prob,
            "scan_time": f"{scan_time:.2f}s",
            "features": {f: float(features[f]) for f in selected_features}
        })

    except Exception as e:
        if temp_path.exists():
            try: temp_path.unlink()
            except: pass
        await file.close()
        raise HTTPException(500, f"Error: {e}")

@app.get("/api/health")
async def health_check():
    return {"status": "online", "pdf_model_loaded": pdf_model is not None, "pe_model_loaded": pe_model is not None}

@app.get("/")
async def root():
    return {"message": "Malware Detection API", "version": "1.0.0", "docs": "/docs"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
