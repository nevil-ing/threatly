# Dockerfile


# Using slim-bullseye for a smaller image size
FROM python:3.13-slim-bullseye as builder

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    # Poetry settings:
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    # Set path where Poetry installs packages inside the container
    POETRY_HOME="/opt/poetry" \
    # Set path for Poetry's cache
    POETRY_CACHE_DIR="/opt/.cache"

# Add Poetry to PATH
ENV PATH="$POETRY_HOME/bin:$PATH"

# Install Poetry
# Why install Poetry? We need it inside the container to install dependencies defined in pyproject.toml
RUN apt-get update && apt-get install --no-install-recommends -y curl \
    && curl -sSL https://install.python-poetry.org | python3 - \
    && apt-get remove -y curl && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

COPY pyproject.toml poetry.lock ./


RUN poetry install --no-root --sync

FROM python:3.13-slim-bullseye as runtime

# Set environment variables (can be overridden by docker-compose)
ENV PYTHONUNBUFFERED=1 \
    # Set the path where packages were installed by Poetry in the builder stage
    PYTHONPATH="/app/.venv/lib/python3.13/site-packages" \
    # Add Poetry's venv bin to PATH if needed, though we use absolute path in CMD
    PATH="/app/.venv/bin:$PATH" \
    # Set default host and port (can be overridden)
    APP_HOST="0.0.0.0" \
    APP_PORT="8000"

# Set the working directory
WORKDIR /app

COPY --from=builder /app/.venv /app/.venv

COPY src/ ./src/

EXPOSE ${APP_PORT}

CMD uvicorn src.main:app --host ${APP_HOST} --port ${APP_PORT}