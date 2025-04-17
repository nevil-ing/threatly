from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context
import os
import sys
project_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_dir)

try:
    from src.models import Base
    target_metadata = Base.metadata
    print("Successfully imported Base metadata from src.models")
except ImportError as e:
    print(f"Error: Could not import Base from src.models: {e}")
    print("Please check the path in alembic/env.py and ensure your models file exists.")
    target_metadata = None # Set to None if import fails, autogenerate will likely fail later

from dotenv import load_dotenv
# Construct the path to the .env file in the project root
dotenv_path = os.path.join(project_dir, '.env')
print(f"Attempting to load .env file from: {dotenv_path}")
# Load the .env file. If it's not found, environment variables might still be
# set externally (e.g., by docker-compose env_file).
load_dotenv(dotenv_path=dotenv_path)

# Get the database URL from the environment variable
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    print("Error: DATABASE_URL environment variable not found.")
    print("Ensure it is set in your .env file or environment.")
   
else:
    print(f"DATABASE_URL found: {DATABASE_URL[:15]}...") # Print partial URL for verification

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

if DATABASE_URL:
    config.set_main_option('sqlalchemy.url', DATABASE_URL)
    print("Alembic config 'sqlalchemy.url' set from environment variable.")
else:
    print("Warning: DATABASE_URL not found, Alembic might use default from .ini if set.")
# -

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = None

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
