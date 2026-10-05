import hashlib
from pathlib import Path
from typing import Dict, Set, Tuple

import magic

from app.core.config import settings

# Conjunto de tipos MIME permitidos por extensão
SUPPORTED_MIME: Dict[str, Set[str]] = {
    ".pdf": {"application/pdf"},
    ".doc": {"application/msword", "application/vnd.ms-office"},
    ".docx": {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/zip",
        "application/octet-stream",
    },
    ".xls": {"application/vnd.ms-excel", "application/vnd.ms-office"},
    ".xlsx": {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/zip",
        "application/octet-stream",
    },
    ".ppt": {"application/vnd.ms-powerpoint", "application/vnd.ms-office"},
    ".pptx": {
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/zip",
        "application/octet-stream",
    },
    ".pps": {"application/vnd.ms-powerpoint", "application/vnd.ms-office"},
    ".ppsx": {
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
        "application/zip",
        "application/octet-stream",
    },
    ".odt": {
        "application/vnd.oasis.opendocument.text",
        "application/zip",
        "application/octet-stream",
    },
    ".ods": {
        "application/vnd.oasis.opendocument.spreadsheet",
        "application/zip",
        "application/octet-stream",
    },
    ".odp": {
        "application/vnd.oasis.opendocument.presentation",
        "application/zip",
        "application/octet-stream",
    },
    ".rtf": {"application/rtf", "text/rtf", "text/plain"},
}


class FileValidationError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def compute_sha256(content: bytes) -> str:
    """Calcula o hash SHA-256 dos bytes fornecidos."""
    return hashlib.sha256(content).hexdigest()


def validate_document(filename: str, content: bytes) -> Tuple[str, str]:
    """
    Valida extensão, tamanho e assinatura MIME do documento.

    Retorna:
        Tuple[str, str]: (extensão em lowercase, mime detectado)
    Raises:
        FileValidationError: Caso não atenda aos critérios de segurança.
    """
    ext = Path(filename).suffix.lower()
    if not ext:
        raise FileValidationError("Arquivo sem extensão válida informada.")

    if ext not in SUPPORTED_MIME:
        raise FileValidationError(
            f"Extensão não suportada: '{ext}'. Extensões permitidas: {', '.join(sorted(SUPPORTED_MIME.keys()))}"
        )

    file_size = len(content)
    if file_size < settings.MIN_FILE_SIZE:
        raise FileValidationError(
            f"Arquivo muito pequeno ({file_size} bytes). Tamanho mínimo: {settings.MIN_FILE_SIZE} bytes."
        )

    if file_size > settings.MAX_FILE_SIZE:
        max_mb = settings.MAX_FILE_SIZE // (1024 * 1024)
        raise FileValidationError(
            f"Arquivo excede o limite permitido de {max_mb} MB ({file_size} bytes)."
        )

    try:
        mime_detector = magic.Magic(mime=True)
        detected_mime = mime_detector.from_buffer(content)
    except Exception as e:
        raise FileValidationError(f"Falha na inspeção estrutural de bytes: {str(e)}", status_code=500)

    allowed_mimes = SUPPORTED_MIME[ext]
    if detected_mime not in allowed_mimes:
        raise FileValidationError(
            f"MIME type incorreto para a extensão '{ext}'. Detectado: '{detected_mime}'."
        )

    return ext, detected_mime
