"""JevShield FastAPI application entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router
from app.core.config import get_settings
from app.security.firewall import Firewall
from app.security.tool_guard import ToolGuard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    firewall = Firewall(settings=settings)
    tool_guard = ToolGuard(firewall=firewall, settings=settings)
    app.state.firewall = firewall
    app.state.tool_guard = tool_guard
    app.state.settings = settings
    yield
    await firewall.aclose()


app = FastAPI(
    title="JevShield",
    description="Local prompt-injection firewall powered by Ollama Nimble System One",
    version="0.1.0",
    lifespan=lifespan,
)
app.include_router(router)
