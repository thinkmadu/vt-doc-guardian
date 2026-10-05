# VT Doc Guardian

[![CI](https://github.com/thinkmadu/vt-doc-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/thinkmadu/vt-doc-guardian/actions/workflows/ci.yml)
[![Release](https://github.com/thinkmadu/vt-doc-guardian/actions/workflows/release-please.yml/badge.svg)](https://github.com/thinkmadu/vt-doc-guardian/actions/workflows/release-please.yml)

O **VT Doc Guardian** é uma plataforma de cibersegurança projetada para quarentena, análise estática e threat intelligence de documentos suspeitos. Utilizando a API do VirusTotal v3 como motor principal, o sistema atua como barreira defensiva: valida a integridade estrutural do documento, checa reputação global de hash instantaneamente e retorna um veredito detalhado sobre ameaças embutidas (malwares e greywares).

## Principais Funcionalidades

- **Estratégia Hash-First:** Antes de transferir o arquivo binário para a nuvem, o sistema calcula o hash SHA-256 e consulta a base global de inteligência de ameaças. Documentos já analisados retornam o laudo em menos de 1 segundo, economizando cota e banda de rede.
- **Proteção contra MIME Spoofing:** Em vez de confiar apenas na extensão informada (`.pdf`, `.docx`), o sistema realiza inspeção profunda de bytes (`python-magic`) para garantir conformidade entre a assinatura interna e o tipo de arquivo.
- **Suporte Amplo a Suítes de Escritório:** Suporta documentos nos formatos PDF (`.pdf`), Microsoft Office moderno e legado (`.docx`, `.doc`, `.xlsx`, `.xls`, `.pptx`, `.ppt`, `.pps`, `.ppsx`), OpenDocument (`.odt`, `.ods`, `.odp`) e Rich Text (`.rtf`).
- **Análise Assíncrona com Rate Guard:** Arquitetura de polling inteligente (intervalos de 15 segundos com teto de tentativas) para operar sem estourar limites de requisição da API pública do VirusTotal (4 requisições por minuto).
- **Console Tático de Operações:** Interface orientada a dados com tema escuro, tipografia monoespaçada, área de Drag & Drop, indicador de etapas da varredura, tabela detalhada de motores que detectaram anomalias e histórico local no navegador.

## Arquitetura

O sistema é estruturado como um monorepo dividido em duas camadas:

1. **Frontend (Next.js 15+ / React 19 / TailwindCSS v4):** Console operacional com componentes modulares (Dropzone, Stepper, ReportCard e HistorySidebar), persistência em `localStorage` e tipagem estrita em TypeScript.
2. **Backend (FastAPI / Python 3.12):** Microsserviço assíncrono com pool de conexões HTTP persistente (`httpx.AsyncClient` gerenciado por `lifespan`), configurações validadas via `pydantic-settings` e suite de testes unitários com `pytest`.

## Setup Local

### 1. Backend (FastAPI)
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env # Configure sua VT_API_KEY
fastapi dev main.py
```

Para rodar a suíte de testes e o linter:
```bash
PYTHONPATH=. pytest tests/ -v
flake8 . --exclude=.venv,legacy_cli
```

### 2. Frontend (Next.js)
Em outro terminal:
```bash
cd frontend
npm install
npm run dev
```

Para validar tipos e regras de código:
```bash
npm run lint
npm run build
```

A aplicação estará disponível em `http://localhost:3000`.

## Contribuição
O desenvolvimento segue [Conventional Commits](https://www.conventionalcommits.org/). Todas as alterações devem passar pelas esteiras de CI (Flake8, Pytest, ESLint e Next.js build) antes do merge para a branch principal.