
FROM python:3.13-slim-bullseye as builder

ENV PYTHONUNBUFFERED=1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_HOME="/opt/poetry" \
    POETRY_CACHE_DIR="/opt/.cache"
ENV PATH="$POETRY_HOME/bin:$PATH"


RUN apt-get update && apt-get install --no-install-recommends -y curl \
    && curl -sSL https://install.python-poetry.org | python3 - \
    && apt-get remove -y curl && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app


COPY pyproject.toml poetry.lock ./
RUN poetry install --no-root --sync


FROM python:3.13-slim-bullseye as runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app/.venv/lib/python3.13/site-packages" \
    PATH="/app/.venv/bin:$PATH"


RUN apt-get update && apt-get install --no-install-recommends -y \
    postgresql-client \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app


COPY --from=builder /app/.venv /app/.venv


COPY . .

RUN chmod +x scripts/*.sh


RUN useradd --create-home appuser
USER appuser

EXPOSE 8000

CMD ["./scripts/start.sh"]