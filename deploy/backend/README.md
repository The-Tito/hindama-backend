# Backend en producción

Archivos que la EC2 del backend usa en `/opt/hindama` (arquitectura §2.3 y §3.1; ADR-002, ADR-003, ADR-011). El paso a paso para crear la infraestructura está en [`../PROCEDIMIENTO.md`](../PROCEDIMIENTO.md).

| Archivo | Qué hace |
| --- | --- |
| `bootstrap.sh` | *User data* de la EC2 (Amazon Linux 2023, arm64). Instala Docker, el plugin de Compose (verifica su checksum), 2 GB de swap, los certificados de RDS y los archivos de esta carpeta **de un commit fijo**. Después arranca el servicio. Se puede volver a correr. |
| `hindama-backend.service` | Unidad de systemd. En cada arranque corre `load-env.sh` y luego `docker compose up -d` (RNF-20). |
| `load-env.sh` | Lee `/hindama/backend/*` de SSM con el rol de la instancia y escribe `/run/hindama/backend.env` (tmpfs, permisos 0600). Los secretos nunca tocan el disco. Solo imprime los nombres. |
| `compose.yaml` | Caddy, Redis, migraciones, API y motor, con límites de memoria, logs `awslogs`, solo lectura y `restart: unless-stopped`. No incluye PostgreSQL, porque la base es RDS. |
| `Caddyfile` | TLS con la CA propia de Caddy (`tls internal`) para `backend.internal:8443`, publicado solo en la IP privada. |
| `iam/` | Política de confianza y políticas del rol `hindama-backend-ec2`, con `CUENTA` como marcador (el número de cuenta no se versiona). |
| `rds-roles.sql`, `init-rds.sh` | Crean los roles y la base en RDS una sola vez, con el usuario maestro (que en RDS no es superusuario). |

## Parámetros de SSM

`load-env.sh` convierte cada nombre en una variable: `/hindama/backend/api-db-password` → `HINDAMA_API_DB_PASSWORD`. Los valores no pueden llevar comilla simple ni salto de línea.

| Parámetro | Tipo | Contenido |
| --- | --- | --- |
| `/hindama/backend/image-tag` | String | Etiqueta de la imagen que corre, por ejemplo `sha-1a2b3c4` |
| `/hindama/backend/db-host` | String | Endpoint de RDS |
| `/hindama/backend/migrations-db-password` | SecureString | Contraseña de `hindama_migrations` |
| `/hindama/backend/api-db-password` | SecureString | Contraseña de `hindama_api` |
| `/hindama/backend/scanner-db-password` | SecureString | Contraseña de `hindama_scanner` |
| `/hindama/backend/redis-password` | SecureString | Contraseña de Redis |
| `/hindama/backend/credential-keys` | SecureString | `{"1":"<32 bytes en base64>"}` (ADR-007) |
| `/hindama/backend/credential-key-version` | String | `1` |
| `/hindama/backend/cognito-region` | String | `us-east-1` |
| `/hindama/backend/cognito-user-pool-id` | String | ID del User Pool |
| `/hindama/backend/cognito-client-id` | String | ID del cliente de la aplicación |
| `/hindama/backend/own-ip-addresses` | String | IP elásticas de la plataforma en JSON, por ejemplo `["203.0.113.10"]` (ADR-008) |
| `/hindama/backend-init/db-master-password` | SecureString | Contraseña maestra de RDS. Solo se usa para `init-rds.sh`; después se borra. |

Las contraseñas se generan con `secrets.token_urlsafe(32)`. Sus caracteres no necesitan escaparse dentro de la URL de la base. Se generan y se guardan sin mostrarse en pantalla.

## Conexión con RDS

La API, el motor y las migraciones verifican el certificado del servidor: `PGSSLMODE=verify-full` con el paquete de CA de RDS de la región (`/opt/hindama/rds-ca.pem`). Así se cumple `rds.force_ssl = 1` sin cambiar el código.

## Cómo se probó

- `rds-roles.sql` se corrió en un PostgreSQL 16 desechable, con un usuario maestro sin superusuario (`CREATEROLE CREATEDB`, como en RDS). Después corrieron todas las migraciones como `hindama_migrations`. Al terminar, el maestro ya no puede actuar como ese rol.
- Prueba de humo del `compose.yaml` en local: imagen construida aquí, ese PostgreSQL y logs locales en lugar de `awslogs`. Resultado:
  - `GET /health` responde 200 por HTTP/2 en `backend.internal:8443`, confiando solo en la raíz de Caddy;
  - sin esa raíz, o entrando por IP sin el nombre, la conexión TLS se rechaza;
  - `/docs` responde 401 en producción.
- `load-env.sh` se probó con `aws` y `curl` falsos: escribe el archivo con permisos 0600 y rechaza un valor con comilla sin dejar un archivo a medias.
