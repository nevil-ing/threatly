
FROM python:3.11-slim


# Prevents Python from buffering stdout/stderr (good for logs)
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app


COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# --- Copy Alembic files ---
COPY alembic.ini .
COPY alembic /app/alembic

COPY ./app /app/app
 
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]