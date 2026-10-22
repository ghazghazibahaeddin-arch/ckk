FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY scenarios/ ./scenarios/

RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["python3", "-m", "cck.cli.main", "run-server", "--host", "0.0.0.0", "--port", "8000"]
