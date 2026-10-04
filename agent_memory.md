# Memória do Agente: VT Doc Guardian

## 2026-10-04
- **Arquitetura Fullstack:** O projeto deixou de ser um script Python solto e virou um Monorepo.
- **Backend:** Usando FastAPI + HTTPX (assíncrono), lendo variáveis do `.env` e rodando na porta 8000.
- **Frontend:** Next.js 15 (Pages Router) + TailwindCSS, focado em cibersegurança (dark theme, dados objetivos) hospedável na Vercel. Faz polling no backend para evitar problemas de timeout na hospedagem serverless.
- **Integração com GitHub:**
  - Branch `develop` é a principal para trabalho.
  - Templates criados para PRs e Issues.
  - GitHub Actions criadas para CI (lint), Release Please e vinculação automática ao GitHub Projects V2 (Kanban).
- **Pendências / Futuro:** Decidir se haverá persistência de histórico (banco de dados) se a Madu quiser expandir a ferramenta. Atualmente a análise não é salva (o front esquece após o reload).
