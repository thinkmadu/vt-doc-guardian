# Spec: VT Doc Guardian (Fullstack)

## Objective
Aplicação web fullstack para quarentena, análise estática e threat intelligence de documentos suspeitos. O usuário faz o upload de documentos via console tático e recebe laudo completo com base nos motores de detecção do VirusTotal v3.

## Tech Stack
- **Frontend:** Next.js 15+ (App Router), React 19, TailwindCSS v4.
- **Backend:** FastAPI, Python 3.12, HTTPX (assíncrono), python-magic.
- **Integrações:** API do VirusTotal v3.

## Commands
- **Backend Dev:** `cd backend && fastapi dev main.py`
- **Backend Test:** `cd backend && PYTHONPATH=. pytest tests/`
- **Backend Lint:** `cd backend && flake8 . --exclude=.venv,legacy_cli`
- **Frontend Dev:** `cd frontend && npm run dev`
- **Frontend Lint:** `cd frontend && npm run lint`
- **Frontend Build:** `cd frontend && npm run build`

## Project Structure
```text
/
├── backend/
│   ├── app/
│   │   ├── api/routes.py       (endpoints /upload e /status)
│   │   ├── core/config.py      (pydantic-settings e CORS)
│   │   ├── schemas/analysis.py (modelos Pydantic)
│   │   └── services/           (validação MIME e cliente VirusTotal)
│   ├── legacy_cli/             (script CLI original v3.3 preservado)
│   ├── tests/                  (suíte de testes unitários com pytest)
│   ├── main.py                 (entrypoint FastAPI com lifespan)
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .dockerignore
├── frontend/
│   ├── src/app/                (Next.js App Router: layout, globals, page)
│   ├── src/components/         (Dropzone, ReportCard, Header, History)
│   ├── src/types/analysis.ts   (interfaces e contratos TypeScript)
│   └── package.json
├── docs/SPEC.md                (especificação viva do projeto)
└── .github/workflows/          (esteiras de CI e automações)
```

## Arquitetura de Comunicação (Hash-First & Polling Seguro)
1. **Validação Estrutural:** O backend inspeciona extensão e assinatura binária (`python-magic`), calculando o hash SHA-256 do arquivo.
2. **Estratégia Hash-First:**
   - O backend consulta `GET /files/{sha256}` no VirusTotal.
   - Caso o arquivo já tenha sido analisado na base global, o veredito completo é retornado instantaneamente (< 1s), dispensando upload de binário e economizando cota.
3. **Upload e Polling Amigável:**
   - Se o arquivo for inédito (404), o backend realiza o upload via `POST /files` e retorna `analysis_id`.
   - O frontend realiza polling a cada 15 segundos (intervalo ajustado para respeitar a cota pública de 4 req/min do VirusTotal), com limite de até 12 tentativas (3 minutos).
4. **Histórico Local:** As últimas 5 análises são armazenadas em `localStorage` para navegação rápida entre relatórios na mesma estação.

## Boundaries
- **Always:** Tratar erros da API do VirusTotal e limites de cota (HTTP 429) com mensagens amigáveis.
- **Never:** Comitar chaves de API (`VT_API_KEY`) ou expô-las nas respostas de erro.
- **Formato:** Suporte amplo a suítes de escritório: PDF, DOCX, DOC, XLSX, XLS, PPTX, PPT, PPS, PPSX, ODT, ODS, ODP, RTF.
