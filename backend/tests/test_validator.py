import pytest
from app.services.validator import (
    FileValidationError,
    compute_sha256,
    validate_document,
)


def test_compute_sha256():
    data = b"VirusTotal Document Guardian Test"
    hash_result = compute_sha256(data)
    assert len(hash_result) == 64
    assert hash_result == "6048d6133995625c65650344daa7095fda02d648d58dd5ed041986d9811311c1"


def test_unsupported_extension():
    content = b"A" * 1024
    with pytest.raises(FileValidationError) as exc:
        validate_document("malicious.exe", content)
    assert "Extensão não suportada" in str(exc.value)


def test_file_too_small():
    content = b"tiny"
    with pytest.raises(FileValidationError) as exc:
        validate_document("document.pdf", content)
    assert "Arquivo muito pequeno" in str(exc.value)


def test_mime_spoofing_detection():
    # Texto puro disfarçado de PDF com mais de 512 bytes
    content = b"This is plain text content pretending to be a PDF file." * 20
    with pytest.raises(FileValidationError) as exc:
        validate_document("fake.pdf", content)
    assert "MIME type incorreto" in str(exc.value)


def test_valid_pdf_detection():
    # Cabeçalho de PDF com preenchimento para atingir > 512 bytes
    pdf_content = b"%PDF-1.4\n" + (b"%trailer<<>>\n" * 45) + b"%%EOF\n"
    assert len(pdf_content) >= 512
    ext, mime = validate_document("relatorio.pdf", pdf_content)
    assert ext == ".pdf"
    assert mime == "application/pdf"


def test_office_format_support():
    # Arquivo com assinatura ZIP de OpenDocument / OOXML com mais de 512 bytes
    zip_header_content = b"PK\x03\x04" + (b"\x00" * 600)
    ext, mime = validate_document("documento.docx", zip_header_content)
    assert ext == ".docx"
    assert mime in ("application/zip", "application/octet-stream")
