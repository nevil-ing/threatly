# teapec-backend

## Project Setup and Run Guide

### Prerequisites
- Python 3.8+
- Docker (optional, for containerized deployment)
- PostgreSQL (or other supported database)
- Redis (for caching/queuing if used)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/teapec-backend.git
   cd teapec-backend
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Configuration
1. Copy `.env.example` to `.env` and update with your configuration:
   ```bash
   cp .env.example .env
   ```
   Edit the `.env` file to set:
   - Database connection (DATABASE_URL)
   - Secret keys
   - Any service-specific configurations

### Database Setup
1. Initialize the database:
   ```bash
   alembic upgrade head
   ```

### Running the Application
#### Development Mode
```bash
uvicorn app.main:app --reload
```

#### Production Mode (using Docker)
```bash
docker-compose up --build
```

### Services
The application includes several services:
- Log processing (Apache, Nginx, Syslog, Windows Event Log)
- Alerting system
- User management
- AI/ML processing

### Testing
Run tests with:
```bash
pytest tests/
```

### API Documentation
After starting the application, access the API docs at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Migrations
To create new database migrations:
```bash
alembic revision --autogenerate -m "Your migration message"
alembic upgrade head
```

### Project Structure
```
teapec-backend/
├── app/                  # Main application code
│   ├── api/              # API endpoints
│   ├── core/             # Core configurations
│   ├── models/           # Database models
│   ├── schemas/          # Pydantic schemas
│   ├── services/         # Business logic
│   └── utils/            # Utility functions
├── alembic/              # Database migrations
├── tests/                # Test cases
├── .env.example          # Environment variables template
├── docker-compose.yml    # Docker compose configuration
└── requirements.txt      # Python dependencies
