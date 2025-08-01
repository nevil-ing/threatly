#!/bin/bash
set -e

# Set memory-efficient environment variables for ARM VPS
export TOKENIZERS_PARALLELISM=false
export OMP_NUM_THREADS=2
export MKL_NUM_THREADS=2
export NUMEXPR_NUM_THREADS=2
export PYTORCH_CUDA_ALLOC_CONF=max_split_size_mb:128

# Create cache directories if they don't exist
mkdir -p /app/.cache/huggingface
mkdir -p /app/.cache/torch

echo "🚀 Starting Sentinel XDR Application..."
echo "🔧 Environment: ARM VPS with memory optimizations"
echo "📦 Python version: $(python --version)"
echo "🧠 Memory optimization: Enabled for 8GB ARM VPS"

# Check if we're running in different modes
case "${1:-uvicorn}" in
    "uvicorn"|"web")
        echo "🌐 Starting web server..."
        exec uvicorn src.main:app --host 0.0.0.0 --port 8000 --workers 1
        ;;
    "worker"|"arq")
        echo "⚡ Starting ARQ worker with compliance support..."
        echo "🤖 Compliance analysis: Lightweight models + rule-based fallback"
        exec arq src.worker.WorkerSettings
        ;;
    "migrate")
        echo "🗃️  Running database migrations..."
        exec alembic upgrade head
        ;;
    "compliance-test")
        echo "🔍 Starting compliance API for testing..."
        exec python -m src.compliance_api
        ;;
    *)
        echo "🌐 Default: Starting web server..."
        exec uvicorn src.main:app --host 0.0.0.0 --port 8000 --workers 1
        ;;
esac