from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gerencia o ciclo de vida do cliente HTTP com reaproveitamento de conexões."""
    app.state.http_client = httpx.AsyncClient(timeout=30.0)
    yield
    await app.state.http_client.aclose()


app = FastAPI(
    title="VT Doc Guardian API",
    description="Motor de quarentena e análise estática de documentos com VirusTotal v3",
    version="1.0.0",
    lifespan=lifespan,
)

# Configuração de CORS com restrição de origens
origins = settings.ALLOWED_ORIGINS
# Se "*" estiver presente, desliga credentials para conformidade com a especificação W3C
allow_creds = False if "*" in origins else True

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=allow_creds,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Inclui as rotas do documento
app.include_router(router)


@app.get("/health")
async def health_check():
    """Endpoint de checagem de saúde da API."""
    return {
        "status": "healthy",
        "api_configured": bool(settings.VT_API_KEY),
    }
