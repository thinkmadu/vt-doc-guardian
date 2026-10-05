from typing import Any, Dict, List, Optional
import httpx
from fastapi import HTTPException

from app.core.config import settings
from app.schemas.analysis import EngineDetection


class VirusTotalService:
    def __init__(self):
        self.api_key = settings.VT_API_KEY
        self.api_url = settings.API_URL

    def _get_headers(self) -> Dict[str, str]:
        if not self.api_key:
            raise HTTPException(
                status_code=500,
                detail="Chave de API do VirusTotal (VT_API_KEY) não configurada no servidor.",
            )
        return {"x-apikey": self.api_key}

    def _extract_detections(self, results: Dict[str, Any]) -> List[EngineDetection]:
        detections: List[EngineDetection] = []
        for engine_name, data in results.items():
            cat = data.get("category", "")
            if cat in ("malicious", "suspicious"):
                detections.append(
                    EngineDetection(
                        engine_name=engine_name,
                        category=cat,
                        result=data.get("result"),
                        method=data.get("method"),
                    )
                )
        return detections

    async def check_hash(
        self, client: httpx.AsyncClient, sha256: str
    ) -> Optional[Dict[str, Any]]:
        """
        Consulta rápida via SHA-256 para verificar se o arquivo já foi analisado globalmente.
        Evita re-upload de binários conhecidos e responde em milissegundos.
        """
        url = f"{self.api_url}/files/{sha256}"
        try:
            response = await client.get(url, headers=self._get_headers())
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Falha de conexão com a API do VirusTotal: {str(exc)}",
            )

        if response.status_code == 404:
            return None
        if response.status_code == 429:
            raise HTTPException(
                status_code=429,
                detail="Limite de requisições do VirusTotal excedido (4 req/min). Aguarde alguns segundos.",
            )
        if response.status_code != 200:
            return None

        file_data = response.json().get("data", {})
        attributes = file_data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total_engines = sum(stats.values()) if stats else 0

        verdict = "DANGER" if malicious > 0 else ("WARNING" if suspicious > 0 else "CLEAN")
        detections = self._extract_detections(results)

        return {
            "status": "completed",
            "stats": stats,
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total_engines,
            "verdict": verdict,
            "detections": detections,
        }

    async def upload_file(
        self, client: httpx.AsyncClient, filename: str, content: bytes, mime_type: str
    ) -> str:
        """Envia o arquivo para a fila de análise estática do VirusTotal."""
        url = f"{self.api_url}/files"
        files = {"file": (filename, content, mime_type)}

        try:
            response = await client.post(url, headers=self._get_headers(), files=files)
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Falha de conexão durante upload para o VirusTotal: {str(exc)}",
            )

        if response.status_code == 429:
            raise HTTPException(
                status_code=429,
                detail="Cota da API do VirusTotal atingida. Tente novamente em 1 minuto.",
            )
        if response.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=f"Erro retornado pela API do VirusTotal ({response.status_code}): {response.text}",
            )

        data = response.json()
        return data["data"]["id"]

    async def get_analysis_status(
        self, client: httpx.AsyncClient, analysis_id: str
    ) -> Dict[str, Any]:
        """Consulta o andamento de uma análise pelo seu identificador."""
        url = f"{self.api_url}/analyses/{analysis_id}"

        try:
            response = await client.get(url, headers=self._get_headers())
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Falha de conexão ao checar status no VirusTotal: {str(exc)}",
            )

        if response.status_code == 429:
            raise HTTPException(
                status_code=429,
                detail="Cota da API do VirusTotal atingida. Aguarde alguns segundos antes de consultar novamente.",
            )
        if response.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail="Falha ao checar status da análise no VirusTotal.",
            )

        report = response.json().get("data", {})
        attributes = report.get("attributes", {})
        status = attributes.get("status", "queued")

        if status == "completed":
            stats = attributes.get("stats", {})
            results = attributes.get("results", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total_engines = sum(stats.values()) if stats else 0
            verdict = "DANGER" if malicious > 0 else ("WARNING" if suspicious > 0 else "CLEAN")
            detections = self._extract_detections(results)

            return {
                "status": "completed",
                "stats": stats,
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": total_engines,
                "verdict": verdict,
                "detections": detections,
            }

        return {"status": status}


vt_service = VirusTotalService()
