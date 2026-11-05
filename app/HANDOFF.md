# Panel GCP (Tools-LatamGCP): estado y handoff

Actualizado: 2026-11-04. Dueño: Ken (Cyber Security Analyst, IBM). Proyecto: AutomatizacionesLATAM (Vulnerability Management).

## 1. Qué es
Panel web local (Python stdlib, sin dependencias externas) que consulta GCP en vivo, solo lectura. Corre en `127.0.0.1:8765`. Reemplaza el flujo basado en Prisma.

Reglas que no se rompen:
- Cero Prisma. GCP solo lectura. Servidor solo en 127.0.0.1.
- Ningún token o llave en disco ni en el navegador. El token sale de `gcloud auth print-access-token`, efímero, en memoria.
- Un error de permisos nunca se muestra como "0 hallazgos".
- Todo en vivo desde GCP. Nada de Catalogo.csv, inventario ni snapshots locales como fuente.
- Squads y CMDB vienen de BigQuery (tablas techgov).

## 2. Estado por módulo
| Módulo | Estado | Notas |
|---|---|---|
| Buscar CVE | Funcional | SCC v2 en vivo. Filtros (tipo de recurso, proyecto, severidad, estado, muted), páginas de 100, total exacto, facetas. Probado con CVE-2026-111497 (87,949 hallazgos) |
| Artefactos/imágenes | Funcional | Busca por nombre. Cloud Asset Inventory (pods) + Artifact Registry (tags) + CMDB. Filtros por ambiente y versión (ej. "22x") |
| Clic en "Dónde corre" -> CVE de la imagen | Funcional | Consulta SCC por digest. Totales, severidad/estado, paginación, CSV. Ejemplo verificado: dev 6 CVE, intg/prod 9 CVE |
| Squads y CMDB | Funcional | `techgov-data-prod.cmdb_data_metrics.it_element` y `gcp_project`. Squad por proyecto (puede haber varios) |
| Squad Beta (pestaña) | Funcional | Elige un squad (50, 672 artefactos en `semilla/squads_artefactos.csv`, solo nombres) y consulta GCP en vivo: pods (Cloud Asset) -> proyecto/cluster/namespace/tag desplegado; Artifact Registry (packages + versions orderBy createTime desc) -> último tag; CMDB -> squads del proyecto. Cargo Cross (86 artefactos, 238 filas) tarda ~37 s. Módulo `squad_beta.py` |
| Dashboard (stock, activos, flapping, CVE únicos, filtros avanzados) | BLOQUEADO | 403 en `sp-te-secproject-prod-h5ls.scce_tvm.findings`. Falta pedir acceso de lectura (DataHub > Access Requests). Al tenerlo, reescribir el SQL con columnas tipadas (finding.state, finding.severity, finding.vulnerability.cve.id) y unir a gcp_project/it_element |
| Índice de salud | N/D | Falta que se apruebe la fórmula |
| Automatización 5am L-V | Solo diseñada | Cloud Scheduler + Cloud Run Job escribiendo a BigQuery. No creada: necesita tabla de escritura aprobada |

Pruebas: 24 unitarias pasando (`python -m unittest discover -s . -p "test_*.py"`).

## 3. Arquitectura y archivos
- `run_local.py`: arranque (usa `ManagedStore`). `start.cmd`: atajo.
- `interfaz/server.py`: rutas `/api/session` (token CSRF `X-Tools-Token`), `/api/cve/facets`, `/api/cve/page`, `/api/image/lookup`, `/api/image/cves`, `/api/live/{dashboard,artifacts,cmdb}`. Valida Host/Origin y CSP.
- `interfaz/app.js`, `index.html`, `style.css`: UI.
- `scc_browse.py`: filtros estrictos, facetas, páginas de CVE y de imagen por digest (`^sha256:[0-9a-f]{64}$`).
- `artifact_lookup.py`: pods + registry + CMDB.
- `bigquery_live.py`: CMDB y squads por proyecto (consultas parametrizadas).
- `configuracion.json`: organización 766905427223, proyecto de facturación SCC `sp-te-secproject-prod-h5ls`, tablas CMDB, repos de Artifact Registry.
- `evidence/consultas-paginadas/*.jsonl`: bitácora de cada consulta con su filtro.

## 4. Flujo de artefactos -> CVE
1. Cloud Asset Inventory `searchAllResources` (`k8s.io/Pod`) da proyecto, cluster, namespace, tag y digest.
2. Artifact Registry `versions?view=FULL` da tags, digests y fechas. Formato de tag: `<rama>-<version>-<sha>`.
3. CMDB une proyecto -> IT element -> squad.
4. Clic en fila: SCC con `resource.name:"sha256:<digest>" AND vulnerability.cve.id:"CVE-"`. Cada hallazgo devuelto se valida contra el digest; si no coincide se descarta la página.

## 5. Verificación hecha y límites
Hecho: cruce API directa vs UI (mismos IDs y totales), digests distintos dan conjuntos distintos, totales vienen de `totalSize` de SCC, errores no se disfrazan de cero.
Falta: contraste contra la consola web de SCC (prueba independiente); squad por recurso (hoy por proyecto); dashboard.

## 6. Pendientes
1. Pedir acceso de lectura a `scce_tvm.findings` y terminar el dashboard.
2. Aprobar fórmula del índice de salud.
3. Decidir tabla de escritura y crear el job de 5am L-V.
4. Ordenar CVE por severidad en el navegador (SCC ordena como texto: HIGH sale antes que CRITICAL).
5. Borrar carpetas parciales de `evidence` (`revision-CVE-2026-111497-20261104-095411`, 249 MB, y las de CVE-2026-63382 y CVE-2026-11497).
6. (Hecho) Rutas fijas de Ken eliminadas: start.cmd busca Python en el PATH y gcloud_path queda vacío (usa PATH).

## 7. Instalar en la laptop de un compañero
Requisitos en la laptop:
- Windows con Python 3.10+ (python.org o `winget install Python.Python.3.12`).
- Google Cloud SDK (`gcloud` y `bq`).
- Cuenta corporativa con permisos: SCC lector en la organización 766905427223, Cloud Asset Viewer, Artifact Registry Reader, BigQuery Data Viewer y Job User sobre techgov. La cuenta del compañero necesita sus propios permisos, no los de Ken.

Pasos:
1. Copiar la carpeta `app` SIN estos elementos: `evidence/`, `__pycache__/`, `gcp_status.json`, `gcp_vulnerabilities*.json`, `inventario*.json`, `Catalogo.csv`. Son datos locales de Ken y no deben viajar.
2. En la laptop: `gcloud auth login` con su cuenta (no usar la de Ken).
3. `cd app` y `python run_local.py --open` (la ruta del Python de Codex no existe allá; usar `python`).
4. Abrir `http://127.0.0.1:8765`. Arriba a la derecha debe verse su cuenta de gcloud.
5. Probar: Buscar CVE con uno conocido, y Artefactos con una imagen que conozca.
6. Si ve 403 en algún módulo es falta de permisos de su cuenta, no un bug (la app lo muestra como error, no como cero).

Antes de entregarlo (recomendado): revisar `start.cmd`, README y `configuracion.json` por rutas o valores personales de Ken, y comprimir en zip sin los archivos excluidos.

### Rutas fijas
Ya eliminadas: `start.cmd` busca Python en el PATH y `gcloud_path` queda vacio (se usa el gcloud del PATH). Instalacion para peers: ver `README.md` y `AGENTS.md` en la raiz del repo.
