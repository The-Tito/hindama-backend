# Procedimiento de despliegue en AWS

Infraestructura de Hindama creada paso a paso, sin Terraform ([ADR-011](../../hindama-docs/01-arquitectura/decisiones/ADR-011-despliegue-con-compose-y-procedimiento.md)). Cada paso indica el valor exacto de cada campo, de modo que cualquier integrante pueda reconstruir la plataforma en la cuenta principal o en la de respaldo.

| Sección | Contenido | Estado |
| --- | --- | --- |
| 1 | Antes de empezar: cuenta, región y credenciales | Listo |
| 2 | Amazon Cognito: User Pool, grupo y cliente | Listo |
| 3 | Red: VPC, subredes y security groups | Listo (2026-11-22) |
| 4 | PostgreSQL en RDS | Listo (2026-11-22) |
| 5 | Parámetros de SSM | Listo; falta el pool de Cognito de producción |
| 6 | EC2 del backend y del frontend | Backend listo (2026-11-22); frontend pendiente |
| 7 | Presupuesto y alertas | Listo (2026-11-22) |
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

## 3. Red: VPC, subredes y security groups

Arquitectura §3.2. Ninguno de estos recursos cuesta: el costo empieza con RDS, la EC2 y la IP elástica.

> **Corre los bloques de las secciones 3 a 6 con `bash`, no en zsh.** En zsh, `$VAR:algo` aplica un modificador (`:l`, `:r`, `:p`…) y altera los ARN en silencio. Así quedó mal la política de logs el 2026-11-22, y solo lo detectó el simulador de IAM. Si usas zsh, escribe siempre `${VAR}`. Tampoco guardes un comando en una variable para llamarlo después; usa una función.

### 3.1 Qué se crea

| Recurso | Valor | Por qué |
| --- | --- | --- |
| VPC `hindama-vpc` | `10.10.0.0/16`, DNS y nombres DNS activos | Session Manager y el endpoint de RDS resuelven por el DNS de la VPC. |
| Internet Gateway `hindama-igw` | Asociado a la VPC | Salida de las EC2 sin NAT Gateway (ADR-004). |
| Subred `hindama-publica-a` | `10.10.1.0/24`, `us-east-1a`, **sin** IP pública automática | Las EC2. La IP pública es solo la elástica, puesta a propósito. |
| Subredes `hindama-privada-a` y `hindama-privada-b` | `10.10.10.0/24` (`us-east-1a`) y `10.10.11.0/24` (`us-east-1b`) | RDS exige un grupo de subredes con dos zonas. |
| Tabla `hindama-rt-publica` | `0.0.0.0/0` → Internet Gateway; asociada a la subred pública | |
| Tabla `hindama-rt-privada` | La principal de la VPC: solo `10.10.0.0/16` local | Las subredes privadas no tienen ruta a internet. |
| `hindama-sg-fe` | Entrada 443 y 80 desde `0.0.0.0/0` | El 80 solo redirige y sirve el reto de Let's Encrypt. |
| `hindama-sg-be` | Entrada **solo 8443 desde `hindama-sg-fe`** | Por referencia entre grupos, no por rango de IP. |
| `hindama-sg-db` | Entrada **solo 5432 desde `hindama-sg-be`**; **sin reglas de salida** | La base nunca inicia conexiones. |

Zonas: `us-east-1a` y `us-east-1b` ofrecen t4g.small y db.t4g.micro con PostgreSQL 16 (se consultó con `describe-instance-type-offerings` y `describe-orderable-db-instance-options`).

### 3.2 Comandos

```bash
export AWS_PROFILE=hindama AWS_REGION=us-east-1
tags() { echo "ResourceType=$1,Tags=[{Key=Name,Value=$2},{Key=Project,Value=hindama}]"; }

VPC=$(aws ec2 create-vpc --cidr-block 10.10.0.0/16 --tag-specifications "$(tags vpc hindama-vpc)" --query Vpc.VpcId --output text)
aws ec2 wait vpc-available --vpc-ids "${VPC}"
aws ec2 modify-vpc-attribute --vpc-id "${VPC}" --enable-dns-support '{"Value":true}'
aws ec2 modify-vpc-attribute --vpc-id "${VPC}" --enable-dns-hostnames '{"Value":true}'
IGW=$(aws ec2 create-internet-gateway --tag-specifications "$(tags internet-gateway hindama-igw)" --query InternetGateway.InternetGatewayId --output text)
aws ec2 attach-internet-gateway --internet-gateway-id "${IGW}" --vpc-id "${VPC}"

PUB=$(aws ec2 create-subnet --vpc-id "${VPC}" --cidr-block 10.10.1.0/24 --availability-zone us-east-1a --tag-specifications "$(tags subnet hindama-publica-a)" --query Subnet.SubnetId --output text)
PRIVA=$(aws ec2 create-subnet --vpc-id "${VPC}" --cidr-block 10.10.10.0/24 --availability-zone us-east-1a --tag-specifications "$(tags subnet hindama-privada-a)" --query Subnet.SubnetId --output text)
PRIVB=$(aws ec2 create-subnet --vpc-id "${VPC}" --cidr-block 10.10.11.0/24 --availability-zone us-east-1b --tag-specifications "$(tags subnet hindama-privada-b)" --query Subnet.SubnetId --output text)

RTPUB=$(aws ec2 create-route-table --vpc-id "${VPC}" --tag-specifications "$(tags route-table hindama-rt-publica)" --query RouteTable.RouteTableId --output text)
aws ec2 create-route --route-table-id "${RTPUB}" --destination-cidr-block 0.0.0.0/0 --gateway-id "${IGW}"
aws ec2 associate-route-table --route-table-id "${RTPUB}" --subnet-id "${PUB}"

SGFE=$(aws ec2 create-security-group --vpc-id "${VPC}" --group-name hindama-sg-fe --description "Frontend: 80 y 443 desde Internet" --query GroupId --output text)
SGBE=$(aws ec2 create-security-group --vpc-id "${VPC}" --group-name hindama-sg-be --description "Backend: 8443 solo desde SG-FE" --query GroupId --output text)
SGDB=$(aws ec2 create-security-group --vpc-id "${VPC}" --group-name hindama-sg-db --description "RDS: 5432 solo desde SG-BE" --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id "${SGFE}" --ip-permissions \
  'IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0}]' 'IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=0.0.0.0/0}]'
aws ec2 authorize-security-group-ingress --group-id "${SGBE}" --ip-permissions \
  "IpProtocol=tcp,FromPort=8443,ToPort=8443,UserIdGroupPairs=[{GroupId=${SGFE}}]"
aws ec2 authorize-security-group-ingress --group-id "${SGDB}" --ip-permissions \
  "IpProtocol=tcp,FromPort=5432,ToPort=5432,UserIdGroupPairs=[{GroupId=${SGBE}}]"
aws ec2 revoke-security-group-egress --group-id "${SGDB}" --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'
```

Guarda los IDs que imprimen estos comandos en un archivo local, fuera del repositorio: las secciones siguientes los usan.

## 4. PostgreSQL en RDS

### 4.1 Tamaño: db.t4g.micro con 20 GB

Se midió antes de crearla (2026-11-22):

- **Datos.** En la base local de desarrollo, una ejecución típica deja unos 34 resultados (148 bytes cada uno) y 11 ocurrencias con evidencia (≈ 1 KB). Con índices, son unos 50 KB por ejecución. El tope de una ejecución es de 5 000 resultados (`max_requests`), y la evidencia se corta en 10 KB por cuerpo (RF-67).
  - 300 ejecuciones típicas ocupan ≈ 15 MB; con 50 contratos de 5 MB como máximo, menos de 300 MB.
  - Ni 300 ejecuciones en el peor caso llegan a 20 GB.
- **Memoria.** RDS reserva ¼ de la memoria para `shared_buffers` (≈ 256 MB con 1 GiB): la base completa cabe en caché.
- **Conexiones.** El máximo por defecto es `memoria / 9 531 392` (≈ 80). Hindama usa como mucho unas 50: la API, 2 workers × 15, y el motor, 20.
- **Carga.** 10 ejecuciones a 5 peticiones por segundo son ≈ 50 escrituras por segundo.
- **Mínimos.** db.t4g.micro es la clase más pequeña para PostgreSQL 16, y 20 GB el almacenamiento mínimo. Precios de lista de us-east-1:

  | Clase | USD por hora |
  | --- | --- |
  | db.t4g.micro | 0.016 |
  | db.t3.micro | 0.018 |
  | db.t4g.small | 0.032 |

  El almacenamiento gp3 cuesta 0.115 USD por GB al mes. **Total ≈ 14 USD al mes.**

Durante la prueba de carga se revisa `CPUCreditBalance`: una clase T que pasa mucho tiempo arriba de su línea base cobra créditos extra.

### 4.2 Qué se crea

| Campo | Valor | Por qué |
| --- | --- | --- |
| Identificador | `hindama-db` | |
| Motor | PostgreSQL **16.15** | Modelo de datos. Actualizaciones menores automáticas. |
| Clase y disco | db.t4g.micro, gp3 20 GB, **cifrado** | Sección 4.1. |
| Red | Grupo de subredes `hindama-db-subnets` (las dos privadas), `hindama-sg-db`, **sin acceso público**, `us-east-1a` (la zona de las EC2), Single-AZ | Arquitectura §3.2. |
| TLS | `rds.force_ssl = 1`; CA `rds-ca-rsa2048-g1` | En PostgreSQL 16 ya es el valor por defecto: no hace falta un grupo de parámetros propio. |
| Usuario maestro | `hindama_admin` | Su contraseña se genera y se guarda en SSM sin mostrarse (sección 5). Se borra después de la sección 6.4. |
| Respaldos | **1 día**, ventana 08:00–08:30 UTC; mantenimiento los domingos a las 08:30 UTC | Ver la desviación de abajo. |
| Protección contra borrado | Activa | |
| Performance Insights y monitoreo mejorado | Desactivados | Gastan créditos y no hacen falta a esta escala. |

> **Desviación: respaldos de 1 día en lugar de 7.** El plan gratuito de AWS rechaza más de 1 día (`FreeTierRestrictionError`). Tampoco se configuró el crecimiento automático del disco, porque el plan limita el almacenamiento. Mientras la cuenta siga en ese plan, se toma una **instantánea manual** antes de cada cambio grande y antes de la demo:
>
> ```bash
> aws rds create-db-snapshot --db-instance-identifier hindama-db --db-snapshot-identifier "hindama-db-$(date +%Y%m%d-%H%M)"
> ```

### 4.3 Comandos

La contraseña maestra viaja a la CLI en un archivo temporal con permisos 0600, nunca como argumento:

```bash
aws rds create-db-subnet-group --db-subnet-group-name hindama-db-subnets \
  --db-subnet-group-description "Subredes privadas de Hindama (sin ruta a Internet)" \
  --subnet-ids "${PRIVA}" "${PRIVB}"

python3 - "${SGDB}" <<'PY'
import json, os, subprocess, sys, tempfile
master = subprocess.run(["aws", "ssm", "get-parameter", "--name", "/hindama/backend-init/db-master-password",
    "--with-decryption", "--query", "Parameter.Value", "--output", "text"],
    capture_output=True, text=True, check=True).stdout.strip()
body = {"DBInstanceIdentifier": "hindama-db", "Engine": "postgres", "EngineVersion": "16.15",
  "DBInstanceClass": "db.t4g.micro", "StorageType": "gp3", "AllocatedStorage": 20, "StorageEncrypted": True,
  "MasterUsername": "hindama_admin", "MasterUserPassword": master,
  "DBSubnetGroupName": "hindama-db-subnets", "VpcSecurityGroupIds": [sys.argv[1]], "PubliclyAccessible": False,
  "AvailabilityZone": "us-east-1a", "MultiAZ": False, "BackupRetentionPeriod": 1,
  "PreferredBackupWindow": "08:00-08:30", "PreferredMaintenanceWindow": "sun:08:30-sun:09:30",
  "DeletionProtection": True, "CopyTagsToSnapshot": True, "AutoMinorVersionUpgrade": True,
  "EnablePerformanceInsights": False, "MonitoringInterval": 0, "CACertificateIdentifier": "rds-ca-rsa2048-g1",
  "Tags": [{"Key": "Project", "Value": "hindama"}]}
os.umask(0o077)
fd, path = tempfile.mkstemp(suffix=".json")
try:
    with os.fdopen(fd, "w") as f:
        json.dump(body, f)
    subprocess.run(["aws", "rds", "create-db-instance", "--cli-input-json", f"file://{path}",
                    "--query", "DBInstance.DBInstanceStatus", "--output", "text"], check=True)
finally:
    os.remove(path)
PY

aws rds wait db-instance-available --db-instance-identifier hindama-db
aws ssm put-parameter --name /hindama/backend/db-host --type String \
  --value "$(aws rds describe-db-instances --db-instance-identifier hindama-db --query 'DBInstances[0].Endpoint.Address' --output text)"
```

Tarda de 5 a 10 minutos. Los roles y la base se crean desde la EC2, en la sección 6.4: RDS no tiene ruta a internet y solo SG-BE llega a ella.

## 5. Parámetros de SSM

La lista completa, con su tipo y su contenido, está en [`backend/README.md`](backend/README.md#parámetros-de-ssm). `load-env.sh` los lee en cada arranque con el rol de la instancia.

### 5.1 Generarlos

Las contraseñas (`secrets.token_urlsafe(32)`) y la llave de credenciales (`os.urandom(32)` en base64, ADR-007) se generan en la máquina de un integrante. Llegan a SSM por un archivo temporal 0600, nunca en pantalla, como argumento ni en el historial:

```bash
python3 <<'PY'
import base64, json, os, secrets, subprocess, tempfile
def put(name, value, secure):
    os.umask(0o077)
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"Name": name, "Value": value, "Type": "SecureString" if secure else "String",
                       "Tags": [{"Key": "Project", "Value": "hindama"}]}, f)
        ok = subprocess.run(["aws", "ssm", "put-parameter", "--cli-input-json", f"file://{path}"],
                            capture_output=True).returncode == 0
    finally:
        os.remove(path)
    print("ok    " if ok else "FALLÓ ", name)
pw = lambda: secrets.token_urlsafe(32)
put("/hindama/backend-init/db-master-password", pw(), True)
for user in ("migrations", "api", "scanner"):
    put(f"/hindama/backend/{user}-db-password", pw(), True)
put("/hindama/backend/redis-password", pw(), True)
put("/hindama/backend/credential-keys",
    json.dumps({"1": base64.b64encode(os.urandom(32)).decode()}, separators=(",", ":")), True)
put("/hindama/backend/credential-key-version", "1", False)
put("/hindama/backend/cognito-region", "us-east-1", False)
put("/hindama/backend/cognito-user-pool-id", "us-east-1_XXXXXXXXX", False)   # sección 2.3
put("/hindama/backend/cognito-client-id", "xxxxxxxxxxxxxxxxxxxxxxxxxx", False)
PY
```

`db-host` se guarda en la sección 4.3. `image-tag` y `own-ip-addresses`, en la sección 6.

- **Copia fuera de línea de la llave de credenciales.** Sin ella, una base restaurada sin acceso a SSM tiene las credenciales ilegibles (ADR-007). Cópiala una vez a un gestor de contraseñas, desde tu propia terminal. No la pegues en un chat:

  ```bash
  aws ssm get-parameter --name /hindama/backend/credential-keys --with-decryption --query Parameter.Value --output text
  ```

- **Pendiente: Cognito de producción.** El despliegue del 2026-11-22 apunta al pool `hindama-dev`, el único que existe. La sección 2 pide un pool por entorno. Antes de abrir la plataforma a usuarios de prueba, crea `hindama-prod` (sección 2.2) y cambia los dos parámetros `cognito-*`.

## 6. EC2 del backend

### 6.1 Rol de IAM y logs

El rol `hindama-backend-ec2` usa **una política propia mínima**, [`backend/iam/ec2-backend.json`](backend/iam/ec2-backend.json):

- **Session Manager y Run Command:** `ssmmessages:*Channel`, `ec2messages:*` y `ssm:UpdateInstanceInformation`, entre otros.
- **Lectura** de `/hindama/backend` y `/hindama/backend/*`.
- **Escritura** en el grupo de logs `/hindama/backend`.

**No se usa `AmazonSSMManagedInstanceCore`.** Esa política administrada concede `ssm:GetParameter` y `ssm:GetParameters` sobre `*`, así que la EC2 del backend podría leer los secretos del frontend, como el secreto del cliente de Cognito. La arquitectura §3.1 pide que cada EC2 lea solo su ruta.

```bash
CUENTA=$(aws sts get-caller-identity --query Account --output text)
for f in ec2-backend ec2-backend-init-temporal; do
  sed "s/CUENTA/${CUENTA}/g" "deploy/backend/iam/${f}.json" > "/tmp/${f}.json"
done
aws iam create-role --role-name hindama-backend-ec2 --assume-role-policy-document file://deploy/backend/iam/ec2-trust.json
aws iam put-role-policy --role-name hindama-backend-ec2 --policy-name hindama-backend --policy-document file:///tmp/ec2-backend.json
# Temporal: solo mientras corre init-rds.sh (sección 6.4).
aws iam put-role-policy --role-name hindama-backend-ec2 --policy-name hindama-backend-init-temporal --policy-document file:///tmp/ec2-backend-init-temporal.json
aws iam create-instance-profile --instance-profile-name hindama-backend-ec2
aws iam add-role-to-instance-profile --instance-profile-name hindama-backend-ec2 --role-name hindama-backend-ec2
aws logs create-log-group --log-group-name /hindama/backend
aws logs put-retention-policy --log-group-name /hindama/backend --retention-in-days 14
```

**Verifica los permisos con el simulador de IAM.** Debe responder `allowed` a leer `/hindama/backend/*` y escribir en `/hindama/backend`, e `implicitDeny` a leer `/hindama/frontend/*` o `/hindama/dev/frontend/*`, escribir en SSM o escribir en otro grupo de logs:

```bash
sim() { aws iam simulate-principal-policy --policy-source-arn "arn:aws:iam::${CUENTA}:role/hindama-backend-ec2" \
  --action-names "$1" --resource-arns "$2" --query 'EvaluationResults[0].EvalDecision' --output text; }
sim ssm:GetParameter "arn:aws:ssm:us-east-1:${CUENTA}:parameter/hindama/backend/api-db-password"
sim ssm:GetParameter "arn:aws:ssm:us-east-1:${CUENTA}:parameter/hindama/dev/frontend/cognito-client-secret"
sim logs:PutLogEvents "arn:aws:logs:us-east-1:${CUENTA}:log-group:/hindama/backend:log-stream:api"
```

### 6.2 IP elástica, imagen y lanzamiento

| Campo | Valor | Por qué |
| --- | --- | --- |
| Instancia | `hindama-backend`, **t4g.small**, Amazon Linux 2023 arm64 (AMI más reciente del parámetro público de SSM) | Arquitectura §3.1. |
| Red | `hindama-publica-a`, `hindama-sg-be` | |
| Acceso | **Sin par de llaves**: solo Session Manager | Ningún puerto de administración abierto. |
| Metadatos | **IMDSv2 obligatorio, `hop limit = 1`** | Los contenedores no llegan a `169.254.169.254` (verificado en la sección 6.5). |
| Disco | gp3 30 GB, **cifrado** | |
| CPU | Créditos **estándar** | Sin cobros extra por ráfagas; si la prueba de carga los agota, se reevalúa. |
| Protección contra terminación | Activa | |
| *User data* | [`backend/bootstrap.sh`](backend/bootstrap.sh) con `HINDAMA_REF` = SHA completo del commit de `develop` | Instala exactamente esos archivos. |
| IP elástica | `hindama-backend-eip` | Es la IP de salida del motor. Va en `own-ip-addresses` antes de arrancar, para que nadie apunte la plataforma contra sí misma (ADR-008). |

La IP elástica cuesta lo mismo que cualquier IPv4 pública (0.005 USD por hora desde 2024). Una IP automática cambiaría en cada arranque y dejaría vieja la protección de ADR-008.

```bash
read -r ALLOC EIP < <(aws ec2 allocate-address --domain vpc --query '[AllocationId,PublicIp]' --output text)
aws ssm put-parameter --name /hindama/backend/own-ip-addresses --type String --value "[\"${EIP}\"]"

# Etiqueta de la imagen: la que publicó el workflow «Imágenes» para el commit de develop.
REF=$(git rev-parse origin/develop)
aws ssm put-parameter --name /hindama/backend/image-tag --type String --value "sha-${REF:0:7}"
sed "s/REPLACE_WITH_COMMIT_SHA/${REF}/" deploy/backend/bootstrap.sh > /tmp/user-data.sh

AMI=$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64 --query Parameter.Value --output text)
INSTANCE=$(aws ec2 run-instances --image-id "${AMI}" --instance-type t4g.small \
  --network-interfaces "DeviceIndex=0,SubnetId=${PUB},Groups=${SGBE},AssociatePublicIpAddress=true" \
  --iam-instance-profile Name=hindama-backend-ec2 \
  --metadata-options HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled \
  --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=30,VolumeType=gp3,Encrypted=true,DeleteOnTermination=true}' \
  --credit-specification CpuCredits=standard --disable-api-termination \
  --user-data file:///tmp/user-data.sh \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=hindama-backend},{Key=Project,Value=hindama}]' \
  --query 'Instances[0].InstanceId' --output text)
```

La IP pública temporal (`AssociatePublicIpAddress=true`) le da internet al *user data*. La IP elástica la reemplaza al final, en la sección 6.5.

### 6.3 Esperar el arranque

En unos 3 minutos el agente de SSM aparece `Online`:

```bash
aws ssm describe-instance-information --filters "Key=InstanceIds,Values=${INSTANCE}" --query 'InstanceInformationList[0].PingStatus'
```

En el primer arranque, `hindama-backend.service` **falla a propósito**: las migraciones no pueden entrar porque los roles de la base aún no existen. El log de `hindama-migrations-1` dice `password authentication failed for user "hindama_migrations"`. Ese error confirma que la conexión TLS con `verify-full` hacia RDS ya funciona.

### 6.4 Inicializar la base y cerrar la puerta temporal

Desde Session Manager (`aws ssm start-session --target "${INSTANCE}"`) o con Run Command:

```bash
sudo /opt/hindama/init-rds.sh
```

Imprime `roles y base de datos creados en hindama-db`. Enseguida, desde tu máquina:

```bash
aws iam delete-role-policy --role-name hindama-backend-ec2 --policy-name hindama-backend-init-temporal
aws ssm delete-parameter --name /hindama/backend-init/db-master-password
```

Si algún día se necesita el usuario maestro, se restablece con `aws rds modify-db-instance --master-user-password`, que también va por archivo temporal.

### 6.5 Arrancar y verificar

En la EC2:

```bash
sudo systemctl restart hindama-backend
docker ps -a --format '{{.Names}}: {{.Status}}'
IP=$(hostname -I | awk '{print $1}')
docker cp hindama-caddy-1:/data/caddy/pki/authorities/local/root.crt /tmp/caddy-root.crt
curl --cacert /tmp/caddy-root.crt --resolve "backend.internal:8443:${IP}" https://backend.internal:8443/health
```

Después asocia la IP elástica:

```bash
aws ec2 associate-address --instance-id "${INSTANCE}" --allocation-id "${ALLOC}"
```

Resultado del 2026-11-22:

| Prueba | Resultado |
| --- | --- |
| `GET /health` por `backend.internal:8443` | 200 |
| `GET /me` sin token | 401 `auth.required` |
| Puerto 8443 | escucha **solo** en la IP privada |
| Un contenedor pide un token de IMDS | se agota el tiempo (bloqueado por el `hop limit`) |
| IP de salida del motor (`checkip.amazonaws.com` desde el contenedor) | la IP elástica |
| Memoria en reposo | API 197 MB de 512; motor 68 de 768; Redis 6 de 128; Caddy 52 de 64. Por eso Caddy pasó a 128 MB |

### 6.6 Probar desde tu máquina por Session Manager

Hace falta el plugin (`brew install --cask session-manager-plugin`). El túnel lleva el 8443 de la EC2 al de tu máquina sin abrir nada a internet:

```bash
aws ssm start-session --target "${INSTANCE}" --document-name AWS-StartPortForwardingSessionToRemoteHost \
  --parameters '{"host":["<IP privada>"],"portNumber":["8443"],"localPortNumber":["8443"]}'
```

En otra terminal, con la raíz de Caddy copiada de la EC2 (es un certificado público) y una cuenta del pool configurado:

```bash
set -a; . ./.env; set +a
TOKEN="$(deploy/cognito/get-dev-token.sh ana@ejemplo.com)"
curl --cacert caddy-root.crt --resolve backend.internal:8443:127.0.0.1 \
  -H "Authorization: Bearer ${TOKEN}" https://backend.internal:8443/me
```

El 2026-11-22 respondió 200 con `role: analyst` y `acceptance_required: true`. Esa petición recorrió Session Manager, Caddy, la API, Cognito y RDS.

### 6.7 Actualizar el backend

- **Solo una imagen nueva:** cambia `/hindama/backend/image-tag` a la etiqueta `sha-…` que publicó el workflow y reinicia el servicio con `sudo systemctl restart hindama-backend`. Las migraciones corren solas antes de la API.
- **Cambios en `deploy/backend/`:** vuelve a correr el *bootstrap* con el commit nuevo. Es idempotente:

  ```bash
  REF=<sha completo de develop>
  curl -fsSL "https://raw.githubusercontent.com/The-Tito/hindama-backend/${REF}/deploy/backend/bootstrap.sh" | sudo HINDAMA_REF="${REF}" bash
  ```

### 6.8 EC2 del frontend

Pendiente: se crea cuando el frontend tenga conectadas sus vistas. Necesita:

- el rol con `ssm:GetParameter` solo sobre `/hindama/frontend/*`;
- `HINDAMA_API_URL=https://backend.internal:8443`, una entrada `backend.internal` en `/etc/hosts` hacia la IP privada del backend y `NODE_EXTRA_CA_CERTS` con la raíz de Caddy;
- su IP elástica agregada a `own-ip-addresses`.

## 7. Presupuesto y alertas

| Campo | Valor |
| --- | --- |
| Nombre | `hindama-mensual` (AWS Budgets, tipo costo, mensual) |
| Límite | **50 USD** |
| Créditos | **No** cuentan como pago (`IncludeCredit: false`). Si contaran, el gasto siempre marcaría 0 y nunca avisaría |
| Avisos por correo | Gasto real al 50, 80 y 100 %; pronóstico al 100 % |
| Destinatarios | Los dos integrantes |

```bash
aws budgets create-budget --account-id "${CUENTA}" --budget file://budget.json --notifications-with-subscribers file://notifications.json
```

`budget.json` lleva `BudgetLimit` de 50 USD y `CostTypes.IncludeCredit: false`. `notifications.json` lleva los cuatro umbrales con los correos del equipo. Los correos no se versionan.

Costo esperado del backend: ≈ 32 USD al mes.

| Concepto | USD al mes |
| --- | --- |
| RDS | ≈ 14 |
| EC2 t4g.small | ≈ 12.3 |
| Disco de la EC2 | ≈ 2.4 |
| IP elástica | ≈ 3.65 |

Con el frontend, ≈ 44 USD al mes.

## 8. Lista de verificación final

- [ ] Ningún recurso se creó con la cuenta raíz.
- [ ] Cognito: los puntos de la sección 2.6.
- [ ] Ningún secreto aparece en el repositorio, en un `.env` versionado ni en la salida de la CI.
- [ ] La llave maestra de credenciales (ADR-007) está en SSM como SecureString (`/hindama/backend/credential-keys`, JSON `{"1":"<32 bytes en base64>"}`), generada en la máquina de un integrante con `os.urandom(32)`, nunca en un chat ni en un correo. Hay una copia fuera de línea junto a la llave privada de los respaldos: sin ella, una base restaurada en la cuenta de respaldo tiene las credenciales ilegibles.
- [ ] La red cumple la sección 3.1. En particular, `hindama-sg-db` no tiene reglas de salida y ninguna subred asigna IP pública automática.
- [ ] RDS: sin acceso público, cifrada, con protección contra borrado. Hay una instantánea manual reciente mientras los respaldos sean de 1 día.
- [ ] `/hindama/backend-init/db-master-password` **no existe** y el rol `hindama-backend-ec2` solo tiene la política `hindama-backend`.
- [ ] El simulador de IAM niega al rol del backend leer `/hindama/frontend/*`.
- [ ] La EC2 no tiene par de llaves, tiene IMDSv2 obligatorio con `hop limit = 1`, y `hindama-sg-be` solo admite el 8443 desde `hindama-sg-fe`.
- [ ] `own-ip-addresses` contiene todas las IP elásticas de la plataforma.
- [ ] Existe `hindama-mensual` en AWS Budgets, con los créditos excluidos.
