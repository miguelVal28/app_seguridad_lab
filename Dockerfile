FROM python:3.14-slim

# uv para instalar dependencias desde uv.lock
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Instala dependencias primero para aprovechar la cache de capas
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --locked --no-install-project --no-dev

COPY . .

RUN mkdir -p uploads flask_session

EXPOSE 5000 5001

# Se usa la CLI de Flask para escuchar en 0.0.0.0 sin modificar app.py
# (que fija 127.0.0.1). database.py crea academia.db antes de arrancar.
CMD ["sh", "-c", "python database.py && flask --app app run --host 0.0.0.0 --port 5000 --debug"]
