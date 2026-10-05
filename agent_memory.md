# Memória do Agente: VT Doc Guardian

## Estado Atual do Projeto
- **Backend (FastAPI):**
  - Estrutura modular em `backend/app/` (`core/config.py`, `schemas/analysis.py`, `services/validator.py`, `services/virustotal.py`, `api/routes.py`).
  - Lifespan gerenciando instância persistente de `httpx.AsyncClient` para reaproveitamento de conexões.
  - Fluxo Hash-First: consulta `GET /files/{sha256}` antes do upload de binário, retornando laudos existentes em milissegundos.
  - Suporte a suítes de escritório: `.pdf`, `.docx`, `.doc`, `.xlsx`, `.xls`, `.pptx`, `.ppt`, `.pps`, `.ppsx`, `.odt`, `.ods`, `.odp`, `.rtf` com validação de bytes (`python-magic`).
  - Script CLI legado preservado em `backend/legacy_cli/`.
  - Suíte de testes unitários com Pytest em `backend/tests/`.
- **Frontend (Next.js 15+ App Router):**
  - Interface tática de cibersegurança dividida em componentes: `Header`, `Dropzone` (drag & drop), `AnalysisProgress` (stepper em 4 fases), `ReportCard` (motores positivos e hash copiável) e `HistorySidebar` (persistência das últimas 5 análises no `localStorage`).
  - Polling a cada 15 segundos com teto de 12 tentativas para respeitar a cota da API pública do VirusTotal (4 req/min).
  - Tipagem estrita TypeScript e conformidade total com ESLint.
- **CI / GitHub Actions:**
  - `ci.yml` executa `flake8` e `pytest` no backend (com `libmagic1`), e `npm run lint` e `npm run build` no frontend.
  - Branch principal de trabalho: `develop`.
