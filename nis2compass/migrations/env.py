import os
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

config = context.config

# Allow env vars to override the DB URL components.
section = config.config_ini_section
config.set_section_option(section, "DB_USER",     os.getenv("NIS2_DB_USER",     "nis2compass"))
config.set_section_option(section, "DB_PASSWORD", os.getenv("NIS2_DB_PASSWORD", "nis2compass"))
config.set_section_option(section, "DB_HOST",     os.getenv("NIS2_DB_HOST",     "localhost"))
config.set_section_option(section, "DB_PORT",     os.getenv("NIS2_DB_PORT",     "5432"))
config.set_section_option(section, "DB_NAME",     os.getenv("NIS2_DB_NAME",     "nis2compass"))

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None

def run_migrations_offline() -> None:
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
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
