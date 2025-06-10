# Stage 1: Builder - Install dependencies
FROM python:3.13-slim-bullseye as builder

ENV PYTHONUNBUFFERED=1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_HOME="/opt/poetry" \
    POETRY_CACHE_DIR="/opt/.cache"
ENV PATH="$POETRY_HOME/bin:$PATH"

# Install Poetry using its official installer
RUN apt-get update && apt-get install --no-install-recommends -y curl \
    && curl -sSL https://install.python-poetry.org | python3 - \
    && apt-get remove -y curl && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
COPY pyproject.toml poetry.lock ./
RUN poetry install --no-root --sync


# Stage 2: Runtime - Create the final, lean image
FROM python:3.13-slim-bullseye as runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app/.venv/lib/python3.13/site-packages" \
    PATH="/app/.venv/bin:$PATH"

# Install only necessary runtime system dependencies (PostgreSQL client)
RUN apt-get update && apt-get install --no-install-recommends -y \
    postgresql-client \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the virtual environment from the builder stage
COPY --from=builder /app/.venv /app/.venv

# Copy all application code and configuration in a single layer
COPY . .

# Make scripts executable
RUN chmod +x scripts/*.sh

# Set a default user to run as (good security practice)
RUN useradd --create-home appuser
USER appuser

EXPOSE 8000

# The CMD is defined in docker-compose.yml, but this is a good default
CMD ["./scripts/start.sh"]