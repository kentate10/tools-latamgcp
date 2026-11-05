# Tools LatamGCP — panel GCP en vivo

Aplicación web local, sin Prisma, que consulta fuentes corporativas de Google Cloud únicamente cuando el usuario solicita una operación.

## Regla principal

La interfaz nueva no carga `Catalogo.csv`, `inventario.json` ni `gcp_vulnerabilities.json`. Esos archivos permanecen como legado para no destruir información anterior, pero no son fuente del dashboard live.

Al abrir la página todos los módulos empiezan en **Sin consulta ejecutada**. Un error de red, autenticación o permisos se muestra como error y nunca como cero resultados.

## Fuentes vivas

| Módulo | Fuente |
| --- | --- |
| Dashboard y filtros | `sp-te-secproject-prod-h5ls.scce_tvm.findings` |
| Búsqueda exacta CVE | Security Command Center REST v2, organización `766905427223`, ubicación `global` |
| Artefactos e imágenes | `pipeline-corporativo.panel_images.v_container_images_cmdb` |
| CMDB / squads | `techgov-data-prod.cmdb_data_metrics.it_element` + `gcp_project` (descubierto en DATAHUB; acceso abierto; mismos campos que my-it-assets). La tabla `itsm_jira_cmdb_dlake.TBL_MASTER_IT-ELEMENT` es un catálogo de formularios ITSM, no la CMDB |
| Referencia de campos CMDB | Google Sheet `my-it-assets` (`1Da0FwE2QHSOkPBG5yKF3WMUJrTxyOEEgZR9tv7pPlw0`) |

La hoja `my-it-assets` confirmó campos como ID, Name, Business Criticality, Squad/Team, Journey, Enterprise Domain, Domain e Is PCI Compliance. El runtime usa la tabla BigQuery de CMDB porque la sesión estándar de `gcloud` no debe ampliar silenciosamente scopes hacia Drive.

## Iniciar

Ejecuta `start.cmd` o:

```powershell
python .\run_local.py --open
```

URL: `http://127.0.0.1:8765`

El backend requiere una sola cuenta activa de `gcloud`. Los access tokens son efímeros, se mantienen en memoria y no se envían al navegador.

## Cómo funciona cada módulo

### Dashboard

1. Selecciona un rango de hasta 32 días.
2. Pulsa **Ejecutar consulta**.
3. El backend inicia un job BigQuery en background.
4. Las métricas se calculan sobre toda la consulta; el detalle se limita a 5,000 filas.
5. Los selectores avanzados se llenan solamente con campos observados en la respuesta real.
6. Al aplicar un filtro se vuelve a consultar BigQuery; no es un filtro sobre un archivo local.

El índice de salud permanece `N/D` hasta que exista una fórmula corporativa aprobada. No se deriva de otros indicadores.

### Buscar CVE

1. Valida el identificador completo.
2. Ejecuta un filtro exacto en SCC.
3. Pagina en bloques de 1,000 hasta terminar.
4. Valida que cada fila corresponda al CVE solicitado.
5. Presenta ACTIVE, INACTIVE y MUTED por separado.
6. Guarda evidencia técnica en `evidence/`; la evidencia no se utiliza como fuente de la siguiente consulta.

### Artefactos

Consulta la vista BigQuery CMDB/imágenes al pulsar **Consultar artefactos**. El nombre y el squad opcionales se envían como parámetros; no se concatena entrada del usuario al SQL.

### Squads y CMDB

Consulta la tabla maestra en BigQuery al pulsar **Consultar CMDB**. El filtro posterior solo reduce la respuesta actual en pantalla. Ningún registro CMDB se copia a la configuración del panel.

## Filtros disponibles

Tipo de recurso, categoría, workload, service domain, squad, IT Element, proyecto, artefacto, namespace, ambiente, domain, subdomain, severidad, status, match level, priority, observed in the wild, es nuevo, tag, PCI, actividad de explotación, fuera de SLA, zero day, package, versión instalada, versión corregida, vector de ataque, CVE, journey y versión de imagen.

Un filtro se deshabilita y muestra **sin dato** si la fuente no entregó ese campo. No se inventan ambientes, squads, SLA o cumplimiento.

## Corner cases cubiertos

- CVE incompleto o inválido.
- Dos consultas iguales o incompatibles ejecutándose a la vez.
- Job perdido después de reiniciar el servidor.
- Cuenta `gcloud` ausente, múltiple o expirada.
- BigQuery 401, 403, 429, 5xx y timeout.
- JSON o esquema inesperado.
- Resultado SCC con un CVE distinto al solicitado.
- `nextPageToken` repetido.
- Rango de fechas invertido o mayor a 32 días.
- Filtros con caracteres no permitidos e intentos de inyección.
- Detalle truncado: las métricas y el límite se muestran por separado.
- CSV protegido contra fórmulas.
- Errores de fuente nunca se convierten en cero.

## Movimiento de artefactos entre squads

El panel anterior guardaba movimientos en JSON local. Ese mecanismo quedó fuera del runtime live porque contradice la nueva regla de fuente GCP.

Para habilitar movimientos persistentes se necesita una tabla GCP de asignaciones aprobada, por ejemplo `squad_artifact_overrides`, con auditoría, usuario, fecha de vigencia y origen. No se realizará `UPDATE` sobre la CMDB corporativa ni sobre `panel_images` sin confirmar la tabla de write-back y sus permisos.

## Automatización 05:00

Es útil para histórico, tendencias y flapping. La implementación correcta en producción es Cloud Scheduler, de lunes a viernes a las 05:00 `America/Guatemala`, ejecutando un Cloud Run Job que escriba snapshots en BigQuery.

No se creó una tarea de Windows: dependería de que la computadora estuviera encendida, de una sesión humana y de credenciales que pueden expirar.

## Validación

```powershell
$env:TEMP="$PWD\.tmp-tests"
$env:TMP="$PWD\.tmp-tests"
python -m unittest discover -s . -p 'test_*.py'
node --check .\interfaz\app.js
```

Estado actual: 18 pruebas automatizadas correctas.
