FROM python:3.12-slim

WORKDIR /app

# Build tools needed for chromadb's compiled dependencies (chroma-hnswlib, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN setpriv --version

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY ravensight/ ravensight/
COPY scripts/ scripts/
COPY config.template.toml .
COPY data/defaults/ defaults/
COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["python3", "main.py", "--config", "/app/config.toml"]
