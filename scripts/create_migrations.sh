#!/bin/bash
# scripts/create_migrations.sh

if [ -z "$1" ]; then
  echo "Usage: $0 \"<migration_message>\""
  exit 1
fi

MIGRATION_MESSAGE="$1"

echo "Ensuring database container is up..."
docker-compose up -d db

echo "Waiting for DB to be ready..."
sleep 5 

echo "Creating new migration: '$MIGRATION_MESSAGE' using the migrate service..."

# The --autogenerate flag is essential
docker-compose run --rm migrate alembic revision --autogenerate -m "$MIGRATION_MESSAGE"

echo ""
echo "Migration file created. Please review it in alembic/versions/."
echo "Then, apply the migration using: docker-compose run --rm migrate"