# Tools-LatamGCP

Panel local de gestion de vulnerabilidades sobre GCP (Security Command Center, Artifact Registry, Cloud Asset Inventory, CMDB en BigQuery). Solo lectura, corre en `127.0.0.1:8765`, todo en vivo, sin guardar credenciales.

Repo INTERNO: contiene IDs de organizacion y proyectos de LATAM. Mantenerlo privado.

## Instalacion rapida (con Codex)
Abre Codex y dile:

> Clona <URL_DEL_REPO>, lee AGENTS.md y dejalo funcionando en mi laptop.

Codex instala lo que falte, corre las pruebas y arranca el panel. Lo unico manual: `gcloud auth login` con tu cuenta corporativa.

## Instalacion manual
1. Python 3.10+ y Google Cloud SDK (`winget install Python.Python.3.12 Google.CloudSDK`).
2. `gcloud auth login` (una sola cuenta activa).
3. `git clone <URL_DEL_REPO>` y `cd Tools-LatamGCP\app`
4. `start.cmd` (o `python check_env.py` y luego `python run_local.py --open`)
5. Abrir http://127.0.0.1:8765

## Actualizar
`git pull` y volver a ejecutar `start.cmd`.

## Permisos que necesita tu cuenta
| Modulo | Permiso |
|---|---|
| Buscar CVE | Security Center Findings Viewer en la organizacion 766905427223 y uso del proyecto de facturacion `sp-te-secproject-prod-h5ls` |
| Artefactos | Cloud Asset Viewer (organizacion), Artifact Registry Reader en `pipeline-corporativo` |
| Squads / CMDB | BigQuery Data Viewer + Job User sobre `techgov-data-prod.cmdb_data_metrics` (acceso abierto) |
| Dashboard | Lectura de `sp-te-secproject-prod-h5ls.scce_tvm.findings` (pendiente de acceso) |

Un 403 en un modulo significa falta de permisos de tu cuenta; la app lo muestra como error, nunca como cero.

## Mas informacion
- `app/HANDOFF.md`: estado, arquitectura, pendientes.
- `app/README.md`: detalle por modulo.
