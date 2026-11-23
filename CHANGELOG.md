# Cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/). Versiones con [SemVer](https://semver.org/lang/es/). La versión del backend es independiente de la del contrato de la API (`hindama-docs/03-api/openapi.yaml`).

## [Sin publicar]

Implementa el **contrato 0.11.0**: 42 de 42 operaciones.

### Agregado

- Baja de cuenta: `DELETE /me` con confirmación del correo (CU-25, RF-88). Borra el usuario y en cascada sus proyectos, suma `deleted_accounts` y registra `account_deleted` en una transacción; después borra la cuenta en Cognito con `DeleteUser` y el token del propio usuario, sin permisos IAM nuevos. Si Cognito falla, `account.deletion_incomplete` (503) y la baja se repite (CU-25 E3).
- Exportar hallazgos a Excel: `GET /projects/{project_id}/findings/export` con los filtros de la lista (CU-19, RF-77). Sin evidencia ni credenciales (RN-11), toda celda de texto queda como texto y nunca como fórmula (CWE-1236), hasta 5 000 hallazgos (`finding.export_too_large`).
- Dependencia `openpyxl` para escribir el `.xlsx`.

### Cambiado

- Contrato 0.11.0: `finding_type` garantiza el mismo `title` y es la llave para agrupar hallazgos repetidos (B21). Sin cambio de código: los títulos ya eran constantes de cada comprobación.

## [0.2.0] — 2026-11-23

Los **siete módulos de prueba** (F-09) y las estadísticas del administrador. Implementa el **contrato 0.10.0 completo**: 40 de 40 operaciones, cubiertas por 1 044 pruebas y verificadas con Schemathesis como analista y como administrador. El catálogo del laboratorio (1.5) fija lo que cada módulo debe encontrar y lo que no.

### Agregado

- Módulo de propiedades (API3, RF-58): campos que la respuesta trae sin declararlos y asignación masiva al crear. Solo escribe donde el contrato ofrece el DELETE de lo creado; anota el recurso antes de crearlo y lo borra en la misma celda, también al cancelar (RN-06). Catálogo del laboratorio 1.5.
- Limpieza de recursos creados (RN-06, CU-23 E1): lo que siga pendiente al terminar, o en una ejecución que la reconciliación da por perdida, queda `failed` con su motivo, a la vista en `created_resources`.
- Contrato 0.10.0: `created_resources.failed_items` dice la ruta, la operación y el motivo de cada recurso que el analista debe borrar a mano (CU-23 E1).
- Módulo de inyección SQL (CWE-89, RF-60): pruebas de error y booleana en los parámetros de ruta y de consulta de las operaciones GET, sin escribir ni esperar (RN-06). Catálogo del laboratorio 1.4.
- Módulo de consumo de recursos (API4, RF-59): ráfaga de hasta 40 peticiones y cuerpos crecientes de hasta 8 MB, sin crear nada en la API del analista (RN-06). Catálogo del laboratorio 1.3.
- Estadísticas del administrador: `GET /admin/stats` (contrato 0.9.0), con actividad por día o semana y hallazgos por módulo, categoría OWASP y severidad, solo de métricas anónimas (CU-20, RF-78, RF-79, RF-89).
- Métricas diarias de ejecuciones: `runs_started` al lanzar o repetir, `runs_cancelled` y `runs_failed` al terminar así (RF-78). Migración `7c4e1a2b9d30`.

### Cambiado

- La verificación al iniciar una ejecución se repite hasta 3 veces, con 2 s de pausa, antes de quitarle la verificación al proyecto: un fallo pasajero del DNS ya no la hace perder (RF-20).
- Contrato 0.8.0: un módulo que el motor no tiene informa `not_implemented` en `modules[].missing` y lanzarlo responde `run.module_unavailable`, en lugar de planear 0 celdas en silencio (RF-45). Desde esta versión no hay ninguno; la regla queda para módulos futuros.

### Fuera de esta versión

- Reportes y exportación a Excel (CU-18, CU-19), baja de cuenta (CU-25), respaldos (CU-24) y 2FA TOTP (CU-22).
- Ejecutar Hindama contra sí misma en AWS.

## [0.1.0] — 2026-11-23

Primera versión entregable. Implementa el **contrato 0.7.0 completo**: 39 de 39 operaciones, cubiertas por 992 pruebas y verificadas con Schemathesis como analista y como administrador.

### Cuentas y sesión

- Validación del token de Amazon Cognito y sesión con RLS por petición (RF-07, RN-03, RN-04, ADR-013).
- Usuario de la sesión y aceptación de los términos de uso (CU-02, RF-16, RN-12).
- Límite de 100 peticiones por minuto por usuario, con Redis (RNF-09).

### Proyectos y verificación

- Crear, listar, consultar, editar y eliminar proyectos, con validación de la URL base (CU-05, CU-06, RF-10 a RF-16, RN-02).
- Verificación de propiedad por archivo y por DNS, y reverificación al iniciar una ejecución (CU-07, RF-17 a RF-21, RN-01).
- Guardia SSRF: toda petición a un destino del usuario pasa por `safe_http`, con IP fijada, redirecciones validadas y límites de tiempo y tamaño (RF-11, RF-50, ADR-008).

### Contratos, identidades y política

- Importar contratos OpenAPI 3 por archivo o URL, con versiones y operaciones (CU-08, RF-22 a RF-27).
- Propuesta automática de política y de parámetros de recurso al importar (RF-35, RF-40).
- Identidades con credenciales cifradas con AES-256-GCM y llaves versionadas; nunca se devuelven ni se registran (CU-09, RF-28 a RF-34, RN-11, ADR-007).
- Recursos por identidad, incluido el descubrimiento con las operaciones de listado (CU-10, RF-36 a RF-38).
- Política por operación y en bloque (CU-11, RF-39 a RF-43).

### Motor de pruebas

- Worker `scanner` con SAQ y Redis, con límite de peticiones por segundo (CU-12, ADR-012).
- Cuatro módulos, de solo lectura por defecto (RN-05, RN-06):
  - acceso a objetos (API1);
  - acceso a funciones (API5);
  - autenticación, con JWT falsificados (API2);
  - configuración: cabeceras, CORS, errores y versiones (API8).
- Evidencia enmascarada (RF-61, RF-62, RN-11).
- Progreso en tiempo real por SSE y cancelación (CU-13, CU-14, RF-51, RF-52, ADR-006).
- Reconciliación de ejecuciones interrumpidas (CU-23, RF-90, RNF-18).

### Resultados y seguimiento

- Ejecuciones y matriz identidad × operación (CU-15, RF-63, RF-64).
- Hallazgos por huella, con evidencia, historial y ocurrencias (RF-65, RF-66, RF-72, ADR-014).
- Resolución automática de lo que ya no se detecta (RF-68, RF-69, RF-78).
- Aceptar el riesgo o marcar falso positivo, y revertirlo (CU-16, RF-70).
- Volver a probar una ejecución terminada (CU-17, RF-71).

### Administración

- Bitácora inmutable de acciones sensibles, con el host protegido con HMAC y llaves versionadas (RF-81 a RF-83, RN-09, ADR-015).
- Consulta de la bitácora con filtros para el administrador, sin acceso al contenido de los proyectos (CU-21, RF-84, RN-03).

### Despliegue y calidad

- Imagen arm64 endurecida, publicada en GHCR.
- Compose de producción con Caddy y TLS interno, en EC2 con RDS PostgreSQL 16 (ADR-002, ADR-011).
- Procedimiento de despliegue reproducible, con scripts para encender, probar y apagar la demo (`deploy/PROCEDIMIENTO.md`, `deploy/lab/`).
- La CI ejecuta:
  - lint, tipos y pruebas;
  - migraciones de ida y vuelta;
  - `pip-audit`, Trivy y CodeQL;
  - comparación del OpenAPI generado con el contrato y Schemathesis (RNF-10, RNF-22, RNF-23, ADR-016).

### Fuera de esta versión

- **Módulos de prueba:** propiedades (API3, requiere la limpieza de recursos creados de RN-06), consumo de recursos (API4) e inyección SQL (CWE-89).
- **Funcionalidades:** reportes y exportación a Excel (CU-18, CU-19), estadísticas del administrador (CU-20), baja de cuenta (CU-25), respaldos (CU-24) y 2FA TOTP (CU-22).
- **Ejecutar Hindama contra sí misma:** se hará después de esta versión.

[0.2.0]: https://github.com/The-Tito/hindama-backend/releases/tag/v0.2.0
[0.1.0]: https://github.com/The-Tito/hindama-backend/releases/tag/v0.1.0
