# hindama-backend

API de la plataforma y motor de pruebas de **Hindama**: FastAPI, PostgreSQL, Redis y un motor de pruebas asíncrono.

La documentación del proyecto (requerimientos, arquitectura, modelo de datos, contrato de la API) vive en el repositorio [`hindama-docs`](../hindama-docs), que se clona junto a este en la misma carpeta madre. El contrato [`03-api/openapi.yaml`](../hindama-docs/03-api/openapi.yaml) es la fuente de verdad de la API ([ADR-016](../hindama-docs/01-arquitectura/decisiones/ADR-016-contrato-primero-con-verificacion-automatica.md)).

## Requisitos

- [uv](https://docs.astral.sh/uv/) (instala Python 3.12 si hace falta).
- Docker con Docker Compose.

## Estructura

Organización por capas. Una petición recorre `api` → `services` → `repositories` → `models`. Todos los identificadores del código están en inglés ([ADR-017](../hindama-docs/01-arquitectura/decisiones/ADR-017-identificadores-en-ingles.md)); la traducción de cada término del dominio está en el [glosario de identificadores](../hindama-docs/03-api/glosario-identificadores.md).

```
src/hindama/
├── config.py        Configuración desde variables de entorno
├── main.py          Crea la aplicación FastAPI
├── api/             Routers HTTP, uno por recurso del contrato
├── schemas/         Pydantic de entrada y salida (reflejan el contrato)
├── services/        Casos de uso y reglas de negocio; no conocen HTTP
├── repositories/    Consultas a la base de datos
├── models/          Modelos de SQLAlchemy (todo el esquema)
├── db/              Engine, sesiones y variables de Row-Level Security
└── core/            Transversal: errores, registros, id de petición, tokens
migrations/          Alembic (versiones en migrations/versions/)
tests/
├── unit/            Sin base de datos
├── integration/     Contra PostgreSQL real (RLS no se puede probar en SQLite)
└── contract/        La API cumple 03-api/openapi.yaml
```

## Comandos

```bash
uv sync                          # instala dependencias en .venv
uv run ruff check .              # lint (incluye reglas de seguridad de Bandit)
uv run ruff format .             # formato
uv run mypy                      # tipos
uv run pytest                    # pruebas
uv run pip-audit                 # vulnerabilidades en dependencias
```

### Entorno local con Docker Compose

```bash
cp .env.example .env               # y cambia cada contraseña
docker compose up --build          # PostgreSQL 16 + API en http://localhost:8000
curl localhost:8000/health         # {"status":"ok"}
```

- PostgreSQL crea al iniciar por primera vez los cuatro roles (`hindama_migrations`, `hindama_api`, `hindama_scanner`, `hindama_backup`) y las bases `hindama` y `hindama_test` ([docker/postgres/init/01-roles.sh](docker/postgres/init/01-roles.sh)). Si cambias contraseñas en `.env` después, borra el volumen: `docker compose down -v`.
- La API recarga sola al editar `src/`. Corre con el mismo endurecimiento que en producción: usuario sin privilegios, sistema de archivos de solo lectura y 512 MB de memoria.
- Los puertos solo escuchan en `127.0.0.1`.

### Migraciones

Alembic se conecta como `hindama_migrations`, el dueño del esquema; nunca con un rol de la aplicación. `docker compose up` las aplica solo (servicio `migrations`) antes de arrancar la API. Desde tu máquina:

```bash
set -a; . ./.env; set +a
export HINDAMA_MIGRATIONS_DATABASE_URL="postgresql+asyncpg://hindama_migrations:${HINDAMA_MIGRATIONS_DB_PASSWORD}@localhost:5432/hindama"
uv run alembic upgrade head                              # aplicar
uv run alembic revision --autogenerate -m "descripción"  # nueva migración (revísala a mano)
uv run alembic check                                     # ¿los modelos coinciden con la base?
```

`autogenerate` no detecta políticas RLS, permisos ni triggers: esas migraciones se escriben a mano.

### Pruebas de integración

Corren contra PostgreSQL real; sin estas variables se omiten. Las de reglas del esquema se conectan como dueño, porque prueban restricciones, no permisos:

```bash
set -a; . ./.env; set +a
export HINDAMA_MIGRATIONS_DATABASE_URL="postgresql+asyncpg://hindama_migrations:${HINDAMA_MIGRATIONS_DB_PASSWORD}@localhost:5432/hindama_test"
uv run alembic upgrade head          # la base de pruebas también necesita el esquema
export HINDAMA_TEST_DATABASE_URL="postgresql+asyncpg://hindama_api:${HINDAMA_API_DB_PASSWORD}@localhost:5432/hindama_test"
export HINDAMA_TEST_OWNER_DATABASE_URL="postgresql+asyncpg://hindama_migrations:${HINDAMA_MIGRATIONS_DB_PASSWORD}@localhost:5432/hindama_test"
uv run pytest
```

### Configuración

Se lee de variables de entorno con el prefijo `HINDAMA_` (ver `src/hindama/config.py`). Se arranca con `--no-access-log` porque el registro de uvicorn incluye la query string; la API escribe su propio registro de cada petición.
