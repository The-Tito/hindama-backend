"""`GET /health` (operationId `getHealth`)."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncEngine

from hindama.api.dependencies import get_engine
from hindama.core.errors import ServiceUnavailableError
from hindama.schemas.common import Health
from hindama.services import health as health_service

router = APIRouter(tags=["System"])


async def check_database(engine: Annotated[AsyncEngine, Depends(get_engine)]) -> bool:
    return await health_service.is_database_up(engine)


@router.get("/health", operation_id="getHealth", summary="Estado del servicio")
async def get_health(database_up: Annotated[bool, Depends(check_database)]) -> Health:
    if not database_up:
        raise ServiceUnavailableError()
    return Health(status="ok")
