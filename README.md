# teapec-backend

A FastAPI backend for the Sentinel XDR project, featuring log processing, anomaly detection, and incident response.

### Prerequisites
- Docker & Docker Compose
- Poetry (for local development)

### Running with Docker (Recommended)

1.  **Environment Setup**
    Copy the example environment file and fill in your secrets:
    ```bash
    cp .env.example .env
    ```

2.  **Build the Docker Images**
    ```bash
    docker-compose build
    ```

3.  **Run Database Migrations**
    This applies any pending database schema changes.
    ```bash
    docker-compose run --rm migrate
    ```

4.  **Start the Application**
    ```bash
    docker-compose up backend
    ```

The API will be available at `http://localhost:8000`.

### API Documentation
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Development Workflow

#### Creating a New Database Migration
When you change a SQLAlchemy model in `src/models/`, you must create a new migration.

1.  Make sure the database container is running:
    ```bash
    docker-compose up -d db
    ```

2.  Run the migration creation script from your host machine:
    ```bash
    ./create-migration.sh "Your descriptive migration message"
    ```
    *Note: You might need to make it executable first: `chmod +x create-migration.sh`*

3.  Apply the new migration:
    ```bash
    docker-compose run --rm migrate
    ```

### Project Structure

teapec-backend/
├── alembic/ # Database migrations
├── scripts/ # Startup and utility scripts
├── src/ # Main application source code
│ ├── api/ # API endpoints (routers)
│ ├── core/ # Core config, DB, security
│ ├── models/ # SQLAlchemy models
│ ├── schemas/ # Pydantic schemas
│ └── services/ # Business logic
├── .env.example # Environment variables template
├── docker-compose.yml # Docker Compose configuration
├── Dockerfile # Instructions for building the Docker image
└── pyproject.toml # Python dependencies (Poetry)