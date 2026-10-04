# Usar a imagem oficial leve do Python 3.12
FROM python:3.12-slim

# Instalar dependências de sistema necessárias para o python-magic
RUN apt-get update && apt-get install -y libmagic1 && rm -rf /var/lib/apt/lists/*

# Configurar o diretório de trabalho
WORKDIR /app

# Copiar apenas os requisitos primeiro para otimizar o cache do Docker
COPY requirements.txt .

# Instalar as dependências do Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar o resto do código da API
COPY . .

# Expor a porta em que a API vai rodar
EXPOSE 8000

# Comando para rodar a aplicação em produção lendo a porta que a provedora exigir
CMD sh -c "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"
