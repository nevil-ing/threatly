#!/bin/bash

set -e

echo "Starting TEAPEC Backend..."

# Wait for database to be ready
echo "Waiting for database to be ready..."
while ! pg_isready -h db -p 5432 -U ${POSTGRES_USER}; do
  echo "Database is not ready yet. Waiting..."
  sleep 2
done

echo "Database is ready!"

# Run database migrations
echo "Running database migrations..."
alembic upgrade head

if [ $? -eq 0 ]; then
    echo "Migrations completed successfully!"
else
    echo "Migration failed!"
    exit 1
fi

# Start the application
echo "Starting FastAPI application..."
exec uvicorn src.main:app --host ${APP_HOST} --port ${APP_PORT} --reload
