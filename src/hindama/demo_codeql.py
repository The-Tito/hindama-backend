"""Archivo de demostración para la práctica de CodeQL (versión corregida)."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

CONSULTA = text("SELECT * FROM usuarios WHERE nombre = :nombre")


async def buscar_usuario(session: AsyncSession, nombre: str):
    return await session.execute(CONSULTA, {"nombre": nombre})
