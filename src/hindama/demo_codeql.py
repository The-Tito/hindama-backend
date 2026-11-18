"""Archivo de demostración para la práctica de CodeQL. NO usar en producción."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def variante_fstring(session: AsyncSession, nombre: str):
    return await session.execute(text(f"SELECT * FROM usuarios WHERE nombre = '{nombre}'"))


async def variante_concatenacion(session: AsyncSession, nombre: str):
    return await session.execute(text("SELECT * FROM usuarios WHERE nombre = '" + nombre + "'"))


async def variante_porcentaje(session: AsyncSession, nombre: str):
    return await session.execute(text("SELECT * FROM usuarios WHERE nombre = '%s'" % nombre))


async def variante_format(session: AsyncSession, nombre: str):
    return await session.execute(text("SELECT * FROM usuarios WHERE nombre = '{}'".format(nombre)))
