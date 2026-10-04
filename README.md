# VT Doc Guardian

[![CI](https://github.com/thinkmadu/vt-doc-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/thinkmadu/vt-doc-guardian/actions/workflows/ci.yml)
[![Release](https://github.com/thinkmadu/vt-doc-guardian/actions/workflows/release-please.yml/badge.svg)](https://github.com/thinkmadu/vt-doc-guardian/actions/workflows/release-please.yml)

O **VT Doc Guardian** é uma plataforma de segurança projetada para análise estática e varredura de documentos suspeitos. Utilizando a API do VirusTotal como motor principal, o sistema atua como uma barreira de quarentena: ele valida a integridade estrutural de arquivos antes de processá-los e retorna um veredito detalhado sobre ameaças embutidas (malwares e greywares).

## Principais Funcionalidades

- **Proteção contra MIME Spoofing:** Ao invés de confiar apenas na extensão do arquivo (`.pdf`, `.pptx`), o sistema utiliza inspeção profunda de bytes (`python-magic`) para garantir que a assinatura interna condiz com a declaração do documento.
- **Análise Assíncrona:** Arquitetura baseada em *polling* que suporta arquivos pesados e relatórios demorados sem causar travamentos de rede ou estourar limites de timeout em hospedagens *serverless*.
- **Veredito Inteligente:** O dashboard classifica os resultados segregando *malicious* (ameaças ativas) e *suspicious* (greyware/adware), entregando ao usuário uma matriz clara do nível de risco.
- **Interface Tática:** Design system intencional focado em dados e cibersegurança, adotando tipografia monoespaçada, zero distrações e contraste severo.

## Arquitetura

O sistema é um monorepo dividido em duas camadas:

1. **Frontend (Next.js 15):** Interface *client-side* construída com React 19 e TailwindCSS. Atua como o cliente de submissão e visualização de *reports*.
2. **Backend (FastAPI):** Microsserviço Python de alta performance (via `httpx`). Centraliza a lógica de negócios, sanitização de requisições, leitura de pacotes suspeitos e comunicação com a inteligência do VirusTotal.

## Setup Local

Para rodar o ambiente de desenvolvimento:

### 1. Backend (FastAPI)
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env # Adicione sua VT_API_KEY
fastapi dev main.py
```

### 2. Frontend (Next.js)
Em outro terminal:
```bash
cd frontend
npm install
npm run dev
```

A aplicação estará disponível em `http://localhost:3000`.

## Contribuição
O desenvolvimento segue [Conventional Commits](https://www.conventionalcommits.org/). Todas as submissões devem passar pelas esteiras de CI (Flake8 e Node linting) antes do merge para a branch principal.