# Spec: VT Doc Guardian (Fullstack)

## Objective
Transformar o script CLI `vt-doc-guardian.py` em uma aplicação web fullstack. O usuário poderá fazer o upload de documentos através de uma interface web bonita e moderna. O sistema utilizará a API do VirusTotal para analisar os arquivos e exibirá o relatório de segurança na própria interface.

## Tech Stack
- **Frontend:** Next.js (Pages Router), React, TailwindCSS. (Hospedado na Vercel).
- **Backend:** FastAPI, Python 3.12. (Hospedado na DigitalOcean ou Heroku via Student Pack).
- **Integrações:** API do VirusTotal.

## Commands
- **Backend Dev:** `cd backend && fastapi dev main.py`
- **Frontend Dev:** `cd frontend && npm run dev`
- **Frontend Build:** `cd frontend && npm run build`

## Project Structure
```text
/
├── backend/            → API FastAPI (port do vt-doc-guardian.py)
│   ├── main.py         → Endpoints principais (/upload, /status)
│   ├── requirements.txt
│   └── .env
├── frontend/           → Interface Web Next.js
│   ├── src/pages/      → Rotas da UI (Upload, Relatório)
│   ├── src/components/ → Componentes React com Tailwind
│   └── package.json
├── docs/               → Documentação e specs
└── .github/            → Templates e Actions
```

## Arquitetura de Comunicação (Polling)
Para respeitar os limites de provedores e manter a interface fluida:
1. Frontend envia arquivo para a rota `POST /backend/upload`.
2. Backend repassa para o VirusTotal e devolve imediatamente um `analysis_id`.
3. Frontend faz *polling* a cada 3 segundos na rota `GET /backend/status/{analysis_id}`.
4. Quando o backend retorna sucesso, o Frontend exibe o relatório e para o polling.

## Boundaries
- **Always:** Tratar erros da API do VirusTotal e timeouts com clareza para o usuário. Isolar o código frontend e backend para que funcionem independentes.
- **Ask first:** Adição de novos serviços externos além do VirusTotal ou banco de dados.
- **Never:** Comitar a `VT_API_KEY` ou expô-la em respostas de erro da API.

## Success Criteria
- O usuário consegue acessar a aplicação via navegador, arrastar um PDF ou DOCX, aguardar a barra de progresso (polling) e ver o resultado limpo (Malicioso/Suspeito/Seguro).
- O backend consegue rodar sem estourar limites de timeout, pois responde imediatamente delegando o polling ao frontend.

## Open Questions
- Precisamos de uma página de histórico (com banco de dados PostgreSQL/SQLite) ou a ferramenta analisará e esquecerá o arquivo após recarregar a página?
