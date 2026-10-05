import httpx
from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from app.core.config import settings
from app.schemas.analysis import AnalysisResponse, StatusResponse
from app.services.validator import (
    FileValidationError,
    compute_sha256,
    validate_document,
)
from app.services.virustotal import vt_service

router = APIRouter()


def get_http_client(request: Request) -> httpx.AsyncClient:
    client = getattr(request.app.state, "http_client", None)
    if client is None:
        raise HTTPException(
            status_code=500,
            detail="Cliente HTTP assíncrono não inicializado no servidor.",
        )
    return client


@router.post("/upload", response_model=AnalysisResponse)
async def upload_document(request: Request, file: UploadFile = File(...)):
    """
    Recebe o documento, valida sua integridade estrutural e executa a estratégia Hash-First.
    Se o arquivo já foi analisado pelo VirusTotal, retorna o veredito instantaneamente.
    """
    if not settings.VT_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="Chave de API do VirusTotal não configurada no servidor.",
        )

    if not file.filename:
        raise HTTPException(status_code=400, detail="Nome de arquivo inválido.")

    # Leitura em streaming com verificação progressiva de tamanho (evita estouro de RAM)
    chunk_size = 1024 * 64  # 64 KB
    content_chunks = []
    total_size = 0

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > settings.MAX_FILE_SIZE:
            max_mb = settings.MAX_FILE_SIZE // (1024 * 1024)
            raise HTTPException(
                status_code=400,
                detail=f"Arquivo excede o limite máximo permitido de {max_mb} MB.",
            )
        content_chunks.append(chunk)

    content = b"".join(content_chunks)

    # Validação rigorosa de extensão e assinatura MIME
    try:
        _, detected_mime = validate_document(file.filename, content)
    except FileValidationError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)

    sha256_hash = compute_sha256(content)
    client = get_http_client(request)

    # 1. Estratégia Hash-First: verificar se o arquivo já possui relatório pronto
    cached_report = await vt_service.check_hash(client, sha256_hash)
    if cached_report:
        return AnalysisResponse(
            analysis_id=sha256_hash,
            filename=file.filename,
            status="completed",
            sha256=sha256_hash,
            file_size=total_size,
            is_cached=True,
            stats=cached_report.get("stats"),
            malicious=cached_report.get("malicious", 0),
            suspicious=cached_report.get("suspicious", 0),
            total_engines=cached_report.get("total_engines", 0),
            verdict=cached_report.get("verdict"),
            detections=cached_report.get("detections", []),
        )

    # 2. Arquivo inédito: enviar para análise estática no VirusTotal
    analysis_id = await vt_service.upload_file(
        client, file.filename, content, detected_mime
    )

    return AnalysisResponse(
        analysis_id=analysis_id,
        filename=file.filename,
        status="queued",
        sha256=sha256_hash,
        file_size=total_size,
        is_cached=False,
    )


@router.get("/status/{analysis_id}", response_model=StatusResponse)
async def get_status(analysis_id: str, request: Request):
    """Consulta o andamento da análise pelo analysis_id."""
    if not settings.VT_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="Chave de API do VirusTotal não configurada no servidor.",
        )

    client = get_http_client(request)
    report = await vt_service.get_analysis_status(client, analysis_id)

    return StatusResponse(**report)
