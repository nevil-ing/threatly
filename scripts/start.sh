#!/bin/bash
#
# Starts the Uvicorn web server.
# This script is the entrypoint for the 'backend' container.
# It assumes the database is already migrated.
#
set -e

echo "🚀 Starting FastAPI application..."


# for production,remove the '--reload' flag.
exec uvicorn src.main:app --host "0.0.0.0" --port 8000 --reload