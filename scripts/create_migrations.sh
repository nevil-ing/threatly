#!/bin/bash

# Script to create new migrations
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <migration_message>"
    echo "Example: $0 'Add alerts table'"
    exit 1
fi

echo "Creating new migration: $1"
docker-compose exec backend alembic revision --autogenerate -m "$1"
