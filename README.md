# VT Doc Guardian

[![CI](https://github.com/thinkmadu/vt-doc-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/thinkmadu/vt-doc-guardian/actions/workflows/ci.yml)
[![Release](https://github.com/thinkmadu/vt-doc-guardian/actions/workflows/release-please.yml/badge.svg)](https://github.com/thinkmadu/vt-doc-guardian/actions/workflows/release-please.yml)

O **VT Doc Guardian** é uma plataforma open-source para análise estática e de segurança de documentos. Construída sobre a API do VirusTotal, ela permite a submissão e varredura de arquivos, com validação nativa de tipos MIME e feedback assíncrono de ameaças (malware e greyware).

## Arquitetura

O projeto foi projetado como um monorepo dividido em dois microserviços:

- **Frontend (Next.js 15):** Interface *client-side* limpa (focada em dados de segurança) com TailwindCSS. Utiliza uma estratégia de *polling* para acompanhar as análises pesadas, garantindo que o client não dependa de conexões síncronas longas em ambientes *serverless* (como Vercel).
- **Backend (FastAPI):** API Python (assíncrona via `httpx`) responsável pela integração com o VirusTotal e validação estrita de segurança (`python-magic` para verificação de MIME spoofing).

## Setup Local

### Requisitos
- Python 3.12+
- Node.js 20+
- Chave de API do VirusTotal

### 1. Configurando a API (Backend)
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
Crie seu arquivo de ambiente na pasta `/backend`:
```bash
cp .env.example .env
```
Edite o arquivo `.env` inserindo a sua `VT_API_KEY`. Para subir a API:
```bash
fastapi dev main.py
```
A API rodará por padrão na porta `8000`.

### 2. Configurando o Cliente (Frontend)
Em um novo terminal:
```bash
cd frontend
npm install
npm run dev
```
Acesse o dashboard em `http://localhost:3000`.

## Deploy (Produção)

O projeto está pronto para ir ao ar e inclui os arquivos essenciais de deploy (`Dockerfile`, `Procfile`).

### Backend (Render, DigitalOcean, Heroku)
1. Crie um Web Service apontando para o diretório `/backend`.
2. A plataforma detectará automaticamente o `Dockerfile`.
3. Configure a variável secreta `VT_API_KEY`.

### Frontend (Vercel, Netlify)
1. Crie um novo projeto importando este repositório.
2. Defina o Root Directory como `/frontend`.
3. Na seção de *Environment Variables*, crie a chave `NEXT_PUBLIC_API_URL` com o valor apontando para a URL pública gerada no deploy do Backend (sem barra no final).

## Contribuição
As alterações seguem o padrão [Conventional Commits](https://www.conventionalcommits.org/). Todas as _features_ e _fixes_ devem passar pelo *linting* (Flake8 e ESLint) nas Actions de CI.