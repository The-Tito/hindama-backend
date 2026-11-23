# Laboratorio en AWS y demo

Scripts para encender la plataforma desplegada y el laboratorio del catálogo, correr la prueba de punta a punta y apagar todo. El paso a paso está en [`PROCEDIMIENTO.md` §9](../PROCEDIMIENTO.md#9-laboratorio-y-demo).

| Archivo | Para qué |
| --- | --- |
| `demo.sh` | `status`, `start`, `stop`, `ca ARCHIVO` y `tunnel`. Busca los recursos por su etiqueta `Name`, sin IDs fijos. |
| `e2e.py` | Prueba de punta a punta por el túnel: crea proyectos sobre el laboratorio, los verifica por DNS, lanza los módulos e imprime hallazgos y tiempos (RNF-01). Con `N > 1` es la prueba de carga (RNF-04). |
| `cfdns.py` | Registros de la zona en Cloudflare: el A de `lab` y los TXT de verificación. El token sale de SSM y nunca se imprime. |
| `ssm-run.sh` | Corre un script en una EC2 por Session Manager, sin SSH. |
| `inventory.sh` | Lista en todas las regiones lo que cobra aunque esté apagado. Se corre después de apagar. |
| `create-lab.sh` y `lab-user-data.sh` | Crean la EC2 del laboratorio **una sola vez**. Ya existe: solo se usan para reconstruirla. |

**Nada de esto se versiona:** el token del analista, la raíz de Caddy descargada ni los tiempos medidos. Viven fuera del repositorio (por ejemplo, en `~/.hindama-demo/`, con permisos 0700).

Todos usan el perfil `hindama` y la región `us-east-1` salvo que se defina `AWS_PROFILE` o `AWS_REGION`. Los nombres se cambian con `HINDAMA_DB_ID`, `HINDAMA_BACKEND_NAME`, `HINDAMA_LAB_NAME`, `HINDAMA_LAB_HOST`, `HINDAMA_LAB_URL` y `HINDAMA_DNS_ZONE`.
