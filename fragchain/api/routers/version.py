from __future__ import annotations

from fastapi import APIRouter

from fragchain import __version__
from fragchain.config import get_settings

router = APIRouter()


@router.get("/version")
async def version() -> dict[str, str]:
    settings = get_settings()
    return {
        "name": "fragchain-core",
        "version": __version__,
        "env": settings.APP_ENV,
    }
