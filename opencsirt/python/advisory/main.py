"""ASGI entry point.

Run via:
    uvicorn advisory.main:app --host 0.0.0.0 --port 8089
or via the console script:
    opencsirt-advisory
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from advisory import __version__
from advisory.api import router
from advisory.config import get_settings
from advisory.enrich import Aggregator


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format='{"ts":"%(asctime)s","lvl":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
    )


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    _configure_logging(settings.log_level)
    aggregator = Aggregator(settings)
    app.state.aggregator = aggregator
    log = logging.getLogger("advisory")
    log.info(
        "advisory subsystem starting (version=%s, port=%d, enrichers=%s)",
        __version__,
        settings.port,
        aggregator.active_sources,
    )
    try:
        yield
    finally:
        await aggregator.aclose()
        log.info("advisory subsystem stopped")


def create_app() -> FastAPI:
    """Build the ASGI app. Used by tests and by uvicorn workers."""
    app = FastAPI(
        title="OpenCSIRT Advisory",
        version=__version__,
        description=(
            "Python advisory subsystem — CSAF 2.0 generation, IOC enrichment, "
            "abuse-mailbox triage. Communicates with the Go core over loopback."
        ),
        lifespan=_lifespan,
    )
    app.include_router(router)
    return app


app = create_app()


def run() -> None:
    """Console-script entry point used by `opencsirt-advisory`."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "advisory.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )
