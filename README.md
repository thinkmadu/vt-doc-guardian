# vt-doc-guardian

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![VirusTotal API v3](https://img.shields.io/badge/VirusTotal-API_v3-green)](https://developers.virustotal.com)
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Scanner profissional para documentos (PDF/PPT/ODP) com detecção de malware + greyware e sistema de quarentena.**

---

## ⚙️ Instalação (Linux & Windows)

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/vt-doc-guardian.git
cd vt-doc-guardian
```

### 2. Instale dependências

#### Linux:

```bash
sudo apt-get install libmagic1
pip install -r requirements.txt
```

#### Windows:

```powershell
# Instale primeiro o pacote binário do magic
pip install python-magic-bin
pip install -r requirements.txt
```

### 3. Configure sua chave API

Crie arquivo `.env` na pasta do projeto:

#### Linux:

```bash
echo "VT_API_KEY=sua_chave_aqui" > .env
chmod 600 .env  # Proteção crítica de credenciais
```

#### Windows (PowerShell):

```powershell
"VT_API_KEY=sua_chave_aqui" | Out-File -FilePath .env -Encoding utf8
# Permissões não são necessárias no Windows (mas mantenha o arquivo oculto)
```

> **Obtenha sua chave gratuita:** [VirusTotal Developers](https://www.virustotal.com/gui/join-us)

---

## 🚀 Como usar?

### Linux:

```bash
python3 vt-doc-guardian.py "/caminho/com/espaços"
# OU
./vt-doc-guardian.py /caminho/sem/espaços
```

### Windows (PowerShell):

```powershell
python vt-doc-guardian.py "C:\Seus Documentos"
```

---

## 📋 Fluxo Básico

1. **Execute o script** com o caminho do diretório.
2. **Responda** se quer incluir subpastas (s/n).
3. **Aguarde** a análise (mostra progresso em tempo real).
4. **Decida** o destino dos arquivos ignorados:
   - `s` → Move para pasta de quarentena
   - `n` → Mantém no local original

---

## ⚠️ Notas por plataforma

### Linux

- **Permissões críticas**: Sempre use `chmod 600 .env`
- **Caminhos com espaços**: Use aspas duplas (`"/caminho/com espaços"`)
- **Execução direta**: Torne o script executável com `chmod +x vt-doc-guardian.py`

### Windows

- **python-magic-bin**: Obrigatório (o pacote padrão não funciona)
- **Caminhos**: Use barras invertidas duplas ou aspas: `"C:\\Meus Documentos"`
- **Erros comuns**:
   - `magic.MagicException`: Falha na instalação do python-magic-bin
   - `PermissionError`: Execute o terminal como administrador

---

## 📁 Resultados

- Relatório CSV em: `relatorio_virustotal.csv`
- Quarentena criada automaticamente (ex: `quarantine_20260224_153045/`)
- Arquivos perigosos excluídos imediatamente
- Greyware detectado via campo `suspicious`

---