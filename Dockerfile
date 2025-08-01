FROM python:3.13-slim-bullseye as builder

# Environment variables for Poetry and ARM optimization
ENV PYTHONUNBUFFERED=1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_HOME="/opt/poetry" \
    POETRY_CACHE_DIR="/opt/.cache" \
    # ARM/Memory optimization variables
    TOKENIZERS_PARALLELISM=false \
    OMP_NUM_THREADS=2 \
    MKL_NUM_THREADS=2 \
    NUMEXPR_NUM_THREADS=2

ENV PATH="$POETRY_HOME/bin:$PATH"

# Install system dependencies including build tools for ARM
RUN apt-get update && apt-get install --no-install-recommends -y \
    curl \
    gcc \
    g++ \
    build-essential \
    && curl -sSL https://install.python-poetry.org | python3 - \
    && apt-get remove -y curl && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Poetry configuration
COPY pyproject.toml poetry.lock ./

# Generate lock file and install dependencies
RUN poetry lock
RUN poetry install --no-root --sync --no-dev

FROM python:3.13-slim-bullseye as runtime

# Runtime environment variables optimized for 8GB ARM VPS
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app/.venv/lib/python3.13/site-packages" \
    PATH="/app/.venv/bin:$PATH" \
    # Memory optimization for PyTorch on ARM
    PYTORCH_CUDA_ALLOC_CONF=max_split_size_mb:128 \
    TORCH_HOME=/app/.cache/torch \
    TOKENIZERS_PARALLELISM=false \
    OMP_NUM_THREADS=2 \
    MKL_NUM_THREADS=2 \
    NUMEXPR_NUM_THREADS=2 \
    # Hugging Face cache location
    HF_HOME=/app/.cache/huggingface \
    TRANSFORMERS_CACHE=/app/.cache/huggingface

# Install runtime dependencies
RUN apt-get update && apt-get install --no-install-recommends -y \
    postgresql-client \
    curl \
    # Additional dependencies for ML models on ARM
    libgomp1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy application code
COPY . .

# Create necessary directories and set permissions
RUN mkdir -p /app/.cache/huggingface /app/.cache/torch \
    && chmod +x scripts/*.sh

# Create non-root user
RUN useradd --create-home appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Health check optimized for compliance system
HEALTHCHECK --interval=30s --timeout=15s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["./scripts/start.sh"]