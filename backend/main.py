import os
from pathlib import Path

import httpx
import magic
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Carrega variáveis de ambiente
load_dotenv()

app = FastAPI(title="VT Doc Guardian API")

# Libera o CORS para o frontend (Next.js rodará na porta 3000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
API_URL = "https://www.virustotal.com/api/v3"

# Validações mantidas do script antigo
MIN_FILE_SIZE = 512
MAX_FILE_SIZE = 32 * 1024 * 1024

SUPPORTED_MIME = {
    '.pdf': 'application/pdf',
    '.ppt': 'application/vnd.ms-powerpoint',
    '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    '.pps': 'application/vnd.ms-powerpoint',
    '.ppsx': 'application/vnd.openxmlformats-officedocument.presentationml.slideshow',
    '.odp': 'application/vnd.oasis.opendocument.presentation'
}


class AnalysisResponse(BaseModel):
    analysis_id: str
    filename: str
    status: str


@app.post("/upload", response_model=AnalysisResponse)
async def upload_document(file: UploadFile = File(...)):
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="Chave de API não configurada.")

    ext = Path(file.filename).suffix.lower()
    if ext not in SUPPORTED_MIME:
        raise HTTPException(status_code=400, detail=f"Extensão não suportada: {ext}")

    content = await file.read()
    file_size = len(content)

    if file_size < MIN_FILE_SIZE:
        raise HTTPException(status_code=400, detail="Arquivo muito pequeno.")
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="Arquivo excede limite de 32MB.")

    mime_detector = magic.Magic(mime=True)
    detected_mime = mime_detector.from_buffer(content)

    if detected_mime != SUPPORTED_MIME[ext]:
        raise HTTPException(status_code=400, detail="MIME type incorreto para a extensão informada.")

    async with httpx.AsyncClient(timeout=30.0) as client:
        files = {'file': (file.filename, content, detected_mime)}
        headers = {'x-apikey': VT_API_KEY}
        response = await client.post(f"{API_URL}/files", headers=headers, files=files)
        
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Erro na API do VirusTotal: {response.text}")
            
        data = response.json()
        analysis_id = data['data']['id']
        
    return AnalysisResponse(analysis_id=analysis_id, filename=file.filename, status="queued")


@app.get("/status/{analysis_id}")
async def get_status(analysis_id: str):
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="Chave de API não configurada.")

    headers = {'x-apikey': VT_API_KEY}
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{API_URL}/analyses/{analysis_id}", headers=headers)
        
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail="Falha ao checar status no VirusTotal")
            
        report = response.json()['data']
        status = report['attributes']['status']
        
        if status == 'completed':
            stats = report['attributes']['stats']
            return {
                "status": "completed",
                "stats": stats,
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "total_engines": sum(stats.values())
            }
        
        return {"status": status}
