# Procedimiento de despliegue en AWS

Infraestructura de Hindama creada paso a paso, sin Terraform ([ADR-011](../../hindama-docs/01-arquitectura/decisiones/ADR-011-despliegue-con-compose-y-procedimiento.md)). Cada paso indica el valor exacto de cada campo, de modo que cualquier integrante pueda reconstruir la plataforma en la cuenta principal o en la de respaldo.

| Sección | Contenido | Estado |
| --- | --- | --- |
| 1 | Antes de empezar: cuenta, región y credenciales | Listo |
| 2 | Amazon Cognito: User Pool, grupo y cliente | Listo |
| 3 | Red: VPC, subredes y security groups | Pendiente (semana 3) |
| 4 | PostgreSQL en RDS | Pendiente (semana 3) |
| 5 | Parámetros de SSM | Pendiente (semana 3) |
| 6 | EC2 del backend y del frontend | Pendiente (semana 3) |
| 7 | Presupuesto y alertas | Pendiente (semana 3) |
| 8 | Lista de verificación final | En construcción |

## 1. Antes de empezar

- **Región:** `us-east-1` para todo ([ADR-010](../../hindama-docs/01-arquitectura/decisiones/ADR-010-una-sola-cuenta-aws.md)).
- **Nunca uses la cuenta raíz.** Trabaja con un usuario de IAM (o de IAM Identity Center) con MFA activado. El script de la sección 2 se niega a correr con la raíz.
- **AWS CLI v2** configurada con un perfil propio:

  ```bash
  aws configure --profile hindama          # o: aws configure sso --profile hindama
  export AWS_PROFILE=hindama
  aws sts get-caller-identity              # debe mostrar tu usuario, no :root
  ```

- **Permisos mínimos para la sección 2.** Si el usuario no es administrador de la cuenta, asígnale esta política (cambia `<CUENTA>`):

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "cognito-idp:CreateUserPool",
          "cognito-idp:CreateGroup",
          "cognito-idp:CreateUserPoolClient",
          "cognito-idp:ListUserPools",
          "cognito-idp:DescribeUserPool",
          "cognito-idp:AdminSetUserPassword",
          "cognito-idp:TagResource",
          "sts:GetCallerIdentity"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": ["ssm:PutParameter", "ssm:GetParameter", "ssm:AddTagsToResource"],
        "Resource": "arn:aws:ssm:us-east-1:<CUENTA>:parameter/hindama/*"
      }
    ]
  }
  ```

  `ssm:GetParameter`, `DescribeUserPool` y `AdminSetUserPassword` solo hacen falta para los scripts de desarrollo (`get-dev-token.sh`, `set-dev-password.sh`). Los SecureString usan la llave administrada `aws/ssm`, que el usuario ya puede usar sin permisos extra de KMS.

## 2. Amazon Cognito

Un User Pool por entorno: `hindama-dev` para desarrollo y `hindama-prod` para la entrega. Nunca se comparten usuarios entre los dos.

### 2.1 Qué se crea

| Recurso | Valor | Por qué |
| --- | --- | --- |
| User Pool | `hindama-<entorno>`, plan **Essentials** | Historial de contraseñas y política de inicio de sesión; gratis hasta 10 000 usuarios activos al mes. |
| Protección contra borrado | Activa | Borrar el pool borra todas las cuentas. |
| Inicio de sesión | Con **correo**, sin distinguir mayúsculas | RF-01, RF-04. |
| Atributos obligatorios | `email`, `name` (1 a 100 caracteres) | RF-01. La API lee nombre y correo con `GetUser`; no se guardan en la base (ADR-015). |
| Autorregistro | Permitido | Cualquiera crea su cuenta de analista (RF-01). |
| Verificación | Código de 6 dígitos al correo antes del primer inicio de sesión | RF-02. Cambiar el correo exige verificar el nuevo. |
| Contraseñas | Mínimo 12, con mayúsculas, minúsculas, números y símbolos; no repetir las últimas 5; contraseña temporal válida 1 día | RF-03. |
| Recuperación | Solo por correo verificado | RF-05. |
| MFA | Desactivado por ahora | Se activa con F-15 (RF-85 a RF-87). |
| Correo | El de Cognito (`COGNITO_DEFAULT`) | Límite de 50 correos al día: suficiente para desarrollo y la demostración. Si no alcanza, configurar SES. |
| Grupo `administradores` | Precedencia 0 | Rol de administrador (RN-04, RF-09). Solo se asigna desde la consola (sección 2.5). |
| Cliente `hindama-web` | **Confidencial** (con secreto) | Next.js llama a Cognito desde su servidor (ADR-005). |
| Flujos del cliente | `ALLOW_USER_PASSWORD_AUTH`, `ALLOW_REFRESH_TOKEN_AUTH` | Formulario propio; sin interfaz alojada ni OAuth. |
| Errores de existencia de usuario | Ocultos (`PreventUserExistenceErrors = ENABLED`) | Mensaje genérico que no revela si el correo existe (RF-06). |
| Vigencia de tokens | Access e id: **15 minutos**; refresh: **7 días** | Acota una sesión robada (ADR-005). |
| Revocación de tokens | Activa | El cierre de sesión revoca el refresh token (RF-04). |
| Atributos del cliente | Lee `email`, `email_verified`, `name`; escribe `email`, `name` | El registro debe poder escribir los atributos obligatorios. |
| Secreto del cliente | SSM `/hindama/<entorno>/frontend/cognito-client-secret` (SecureString) | Lo lee solo el servidor de Next.js. El backend no lo necesita. |

El bloqueo temporal tras intentos fallidos (RF-06) es parte de Cognito en todos los planes y no se configura.

La configuración exacta está en [`cognito/user-pool.json`](cognito/user-pool.json) y [`cognito/app-client.json`](cognito/app-client.json). Si cambias algo, cámbialo ahí y en esta tabla en el mismo commit.

### 2.2 Crear el User Pool

```bash
export AWS_PROFILE=hindama
deploy/cognito/create-user-pool.sh dev
```

El script:

1. Muestra la cuenta, la identidad y la región, y pide escribir el nombre del pool para confirmar.
2. Se detiene si ya existe un pool con ese nombre, para no crear duplicados.
3. Crea el pool, el grupo `administradores` y el cliente `hindama-web`.
4. Guarda el secreto del cliente directo en SSM, sin imprimirlo ni pasarlo como argumento.
5. Imprime las tres variables para el `.env` del backend. Ninguna es secreta.

### 2.3 Configurar el backend

En el `.env` local (y, en la sección 5, en los parámetros de SSM del backend), reemplaza los valores provisionales por los que imprimió el script:

```bash
HINDAMA_COGNITO_REGION=us-east-1
HINDAMA_COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX
HINDAMA_COGNITO_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
```

Pásale al equipo de frontend el `HINDAMA_COGNITO_CLIENT_ID` y la ruta del secreto en SSM; el secreto no se envía por chat ni por correo.

### 2.4 Probar de punta a punta

1. Crea una cuenta de prueba en la consola: **Cognito → User pools → hindama-dev → Users → Create user**, con «Don't send an invitation», correo real, «Mark email address as verified» y una contraseña temporal cualquiera. Agrega el atributo `name`. Sin `name`, `GET /me` responde 503. Después fija una contraseña permanente que cumpla la política y sea **distinta de la temporal** (Cognito recuerda las últimas 5):

   ```bash
   set -a; . ./.env; set +a
   deploy/cognito/set-dev-password.sh ana@ejemplo.com
   ```

   (Cuando el frontend tenga registro, este paso se sustituye por crear la cuenta desde la interfaz.)

2. Levanta la API y pide un token como lo haría Next.js:

   En zsh no escribas comentarios (`# …`) al final de estas líneas: la terminal interactiva los ejecuta como comandos.

   ```bash
   docker compose up -d --build
   TOKEN="$(deploy/cognito/get-dev-token.sh ana@ejemplo.com)"
   curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/me
   ```

   Debe responder 200 con el nombre y el correo de la cuenta, `role: analyst` y `acceptance_required: true`.

3. Comprueba los rechazos:
   - Sin la cabecera `Authorization`: 401 `auth.required`.
   - Con el token alterado (cambia un carácter de la firma): 401 `auth.invalid_token`.
   - Revoca la sesión con `aws cognito-idp global-sign-out --access-token "$TOKEN"` y repite `GET /me`: 401 `auth.invalid_token` (el token sigue firmado, pero `GetUser` lo rechaza).

`get-dev-token.sh` solo funciona con el pool de desarrollo. En producción, los tokens existen solo dentro de la cookie cifrada.

### 2.5 Asignar un administrador (RF-09)

Solo el equipo, y solo desde la consola: **Cognito → User pools → hindama-<entorno> → Groups → administradores → Add user to group**. No existe ningún endpoint ni script para hacerlo. El cambio se refleja en el siguiente token que emita Cognito (a más tardar en 15 minutos, o al volver a iniciar sesión).

### 2.6 Verificar en la consola

Después de crear el pool, revisa en **Cognito → User pools → hindama-<entorno>**:

- [ ] **Sign-in:** correo como identificador; política de contraseñas de 12 caracteres con los cuatro tipos; MFA desactivado.
- [ ] **Sign-up:** autorregistro activo; atributos obligatorios `email` y `name`; verificación por correo.
- [ ] **Settings → Deletion protection:** activa.
- [ ] **Groups:** existe `administradores` y está vacío.
- [ ] **App clients → hindama-web:** tiene secreto; flujos `ALLOW_USER_PASSWORD_AUTH` y `ALLOW_REFRESH_TOKEN_AUTH`; sin interfaz alojada; tokens de 15 minutos y 7 días; revocación activa; «Prevent user existence errors» activo.
- [ ] **Systems Manager → Parameter Store:** existe `/hindama/<entorno>/frontend/cognito-client-secret` como SecureString.

### 2.7 Borrar o recrear un pool

Borrar un pool elimina todas sus cuentas y no se puede deshacer. Primero desactiva la protección (**Settings → Deletion protection → Deactivate**), después bórralo y borra el parámetro de SSM. Si se recrea, cambian el User Pool ID, el Client ID y el secreto: actualiza el `.env` y avisa al frontend. Los usuarios de la base que apuntaban al pool anterior quedan huérfanos; en desarrollo se limpian con `docker compose down -v`.

## 8. Lista de verificación final

- [ ] Ningún recurso se creó con la cuenta raíz.
- [ ] Cognito: los puntos de la sección 2.6.
- [ ] Ningún secreto aparece en el repositorio, en un `.env` versionado ni en la salida de la CI.
