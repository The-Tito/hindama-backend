# Colección de Postman

Sirve para probar a mano la API de la plataforma en local, contra el laboratorio expuesto por un túnel.

| Archivo | Qué es |
| --- | --- |
| `hindama.postman_collection.json` | Colección generada desde el contrato. No se edita a mano. |
| `local.postman_environment.json` | Entorno «Hindama local», sin secretos. |
| `build.py` | Generador. Se vuelve a correr cada vez que cambia el contrato. |

La colección tiene dos partes:

- **«Flujo con el laboratorio»:** el proyecto de las pruebas de integración (`tests/lab/scanning.py`), paso por paso y en orden. Cada paso guarda los ids que necesitan los siguientes.
- **Una carpeta por etiqueta del contrato**, con todas las operaciones. Cada una trae:
  - parámetros de ruta, de consulta y de cabecera (los opcionales vienen desactivados);
  - el cuerpo de cada ejemplo del contrato;
  - los ejemplos de respuesta, en la pestaña *Examples*;
  - en la descripción, la lista de códigos de respuesta.

## 1. Regenerar

```bash
uv run python -m postman.build                       # lee ../hindama-docs/03-api/openapi.yaml
uv run python -m postman.build --contract /otra/ruta/openapi.yaml
```

Después, en Postman, vuelve a importar el archivo y elige reemplazar la colección.

## 2. Requisitos, una sola vez

1. **Docker Desktop**, y el `.env` del backend con una llave real en `HINDAMA_CREDENTIAL_KEYS`: 32 bytes en base64.
2. **`cloudflared`**, para el túnel: `brew install cloudflared`. No necesita cuenta.
3. **Un usuario en el pool `hindama-dev`.** Toma el id del pool de `HINDAMA_COGNITO_USER_POOL_ID` en `.env`:

   ```bash
   POOL=<id del pool>
   aws cognito-idp admin-create-user --user-pool-id "$POOL" --username <correo> \
     --user-attributes Name=email,Value=<correo> Name=email_verified,Value=true Name=name,Value="<nombre>" \
     --message-action SUPPRESS
   aws cognito-idp admin-set-user-password --user-pool-id "$POOL" --username <correo> \
     --password '<contraseña>' --permanent
   ```

   - Sin `--permanent`, Cognito pide cambiar la contraseña (`NEW_PASSWORD_REQUIRED`) y la colección no obtiene token.
   - Para probar las operaciones de administrador, agrega el usuario al grupo `administradores` con `admin-add-user-to-group`.
4. **El secreto del cliente.** Cópialo al portapapeles sin que salga en pantalla:

   ```bash
   aws ssm get-parameter --name /hindama/dev/frontend/cognito-client-secret \
     --with-decryption --query Parameter.Value --output text | pbcopy
   ```

5. **Postman:**
   - Importa los dos archivos JSON y selecciona el entorno «Hindama local».
   - Llena `cognitoClientId` con el valor de `HINDAMA_COGNITO_CLIENT_ID`, además de `username`, `password` y `cognitoClientSecret`.
   - Escribe los secretos solo en el **valor actual** (*current value*), que no se sincroniza. Nunca los guardes en la colección ni en git.

## 3. Cada sesión

Abre tres terminales en `hindama-backend/`:

```bash
# 1. Plataforma: base de datos, Redis, migraciones, API y motor
docker compose up -d --wait

# 2. Laboratorio, en modo vulnerable
uv run python -m tests.lab.serve --mode vulnerable

# 3. Túnel público hacia el laboratorio
cloudflared tunnel --url http://localhost:8100
```

Copia la URL `https://….trycloudflare.com` que imprime `cloudflared` a la variable `labUrl` del entorno, sin `/` al final.

**¿Por qué un túnel?** La guardia SSRF (RF-11, RF-50) bloquea loopback y las redes privadas, así que el motor no puede apuntar a `localhost`. Esa excepción existe solo en las pruebas automáticas. Con el túnel, el laboratorio tiene una URL pública con TLS y pasa la guardia igual que una API real.

## 4. El flujo

Ejecuta la carpeta en orden. Puedes hacerlo petición por petición, o todo junto con *Run folder* hasta el paso 12.

| Pasos | Qué hacen |
| --- | --- |
| 00–02 | Salud de la API, tu cuenta y aceptar los términos. |
| 03 | Crear el proyecto con `base_url = {{labUrl}}`. |
| 04–05 | Verificar la propiedad por archivo (ver abajo). |
| 06–08 | Importar el contrato del laboratorio por URL y aplicar las políticas del catálogo. |
| 09–11 | Crear las identidades ana, beto y raiz, y los recursos de cada una. |
| 12–19 | Lanzar la ejecución, ver su progreso (SSE), la matriz y los hallazgos. |

**Verificación por archivo (paso 04).** La consola de Postman muestra el comando que escribe el código:

```bash
echo 'hindama-verificacion=…' > tests/lab/.verificacion.txt
```

El laboratorio lee ese archivo en cada petición, así que no hace falta reiniciarlo. El archivo lo ignora git.

**Corregir y volver a probar.** Detén el laboratorio y levántalo con `--mode secure`. El túnel conserva su URL. Repite el paso 12: los hallazgos pasan a resueltos y el paso 19 muestra el proyecto concluido.

## 5. Notas

- El token de Cognito dura 15 minutos. Un script de la colección lo renueva solo, antes de cada petición.
- Las credenciales de las identidades del laboratorio son ficticias: son las de `tests/lab/app.py`.
- El laboratorio expuesto es vulnerable a propósito. Cierra el túnel al terminar.
- `discoverResources` aún no está implementada.
- Al terminar: `docker compose stop`.
