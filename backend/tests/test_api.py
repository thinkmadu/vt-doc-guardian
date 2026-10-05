from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "api_configured" in data


def test_upload_missing_api_key_or_unsupported():
    # Envio de arquivo .exe não suportado
    files = {"file": ("malware.exe", b"A" * 1024, "application/octet-stream")}
    response = client.post("/upload", files=files)
    # Se a chave não estiver configurada no ambiente de teste, retorna 500, senão 400
    assert response.status_code in (400, 500)
