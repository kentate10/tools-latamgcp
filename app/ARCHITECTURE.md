# Arquitectura objetivo — Panel GCP LATAM

## Decisión ejecutiva

La aplicación debe desplegarse como un contenedor privado en Cloud Run, detrás de un Application Load Balancer global, IAP y el dominio corporativo de LATAM. La aplicación no usará Prisma ni archivos locales como fuente de datos.

Las consultas actuales se resuelven en vivo desde:

- Security Command Center REST v2 para búsquedas exactas de CVE.
- BigQuery para dashboard, filtros, artefactos, imágenes y CMDB.
- Una tabla propia y aislada para registrar movimientos de artefactos entre squads.
- Tablas históricas propias para las ejecuciones programadas de las 05:00.

## Estado actual

### Frontend

- HTML5, CSS3 y JavaScript nativo.
- Aplicación de una sola página sin React, Angular ni Vue.
- Tema claro blanco/rojo y tema oscuro negro/dorado.
- Todas las operaciones de datos se inician por acción explícita del usuario.
- Exportación CSV y tablas dinámicas en el navegador.

### Backend

- Python 3 con `http.server` y librerías estándar.
- Endpoints JSON para dashboard, CVE, artefactos y CMDB.
- Consultas BigQuery parametrizadas y llamadas REST a SCC.
- En local obtiene un token efímero desde la cuenta activa de `gcloud`.
- Los trabajos en curso se mantienen actualmente en memoria.

### Fuentes verificadas

- Findings: `sp-te-secproject-prod-h5ls.scce_tvm.findings`.
- Artefactos: `pipeline-corporativo.panel_images.v_container_images_cmdb`.
- Imágenes: `pipeline-corporativo.panel_images.cve_images_base`.
- CMDB: `techgov-data-prod.cmdb_data_metrics.it_element`.
- Proyectos CMDB: `techgov-data-prod.cmdb_data_metrics.gcp_project`.
- SCC: organización `766905427223`, ubicación `global`.

### Lo que no debe pasar a producción tal como está

- `http.server` no es un servidor de producción.
- Cloud Run no tendrá una sesión humana de `gcloud`.
- Los jobs no pueden depender de memoria local porque Cloud Run escala a múltiples instancias y puede reiniciarlas.
- La configuración corporativa no debe vivir como secretos en JSON dentro de la imagen.
- No se debe escribir directamente sobre CMDB ni sobre las vistas de `panel_images`.

## Arquitectura GCP propuesta

```text
Usuario LATAM
    |
    | HTTPS + identidad Google Workspace
    v
DNS corporativo + certificado administrado
    |
Application Load Balancer global
    |
Cloud Armor (WAF/rate limiting) + IAP
    |
Serverless NEG
    |
Cloud Run: panel-api
    |-- SCC REST v2 (consulta CVE exacta)
    |-- BigQuery (dashboard, filtros, CMDB, artefactos)
    |-- BigQuery dataset propio (asignaciones, auditoría, snapshots)
    |-- Cloud Logging / Error Reporting / Monitoring

Cloud Scheduler 05:00 L-V
    |
    v
Cloud Run Job: panel-snapshot
    |
    v
BigQuery dataset histórico
```

## Proyecto y ambientes

Recomendación:

- Un proyecto GCP dedicado para producción, por ejemplo `latam-security-panel-prod`.
- Un proyecto separado de desarrollo o pruebas, por ejemplo `latam-security-panel-dev`.
- Artifact Registry propio para la imagen del contenedor.
- Presupuesto, alertas, etiquetas de costo y responsables definidos desde el inicio.
- Región final elegida según política corporativa y ubicación de los datasets; si las fuentes están en la multirregión `US`, `us-central1` suele ser una candidata, pero debe verificarse antes del despliegue.

## Identidades y permisos

### Usuarios

El equipo entra con su cuenta corporativa mediante IAP. El acceso se concede a un Google Group, no persona por persona. No se necesita guardar contraseñas en la aplicación.

Grupos sugeridos:

- `gcp-vulnerability-panel-users`: consulta y reportes.
- `gcp-vulnerability-panel-operators`: movimientos de squad.
- `gcp-vulnerability-panel-admins`: configuración y soporte.

### Cuenta de servicio de runtime

Crear una cuenta dedicada, por ejemplo `panel-runtime@...`, con privilegio mínimo:

- `roles/bigquery.jobUser` en el proyecto que facture los jobs.
- `roles/bigquery.dataViewer` únicamente sobre los datasets/tablas fuente requeridos.
- `roles/securitycenter.findingsViewer` en el alcance mínimo que permita ver findings de la organización.
- Permiso de escritura únicamente en el dataset propio de asignaciones e históricos.
- `roles/logging.logWriter` y `roles/monitoring.metricWriter` cuando no estén cubiertos por la identidad del servicio.

No usar claves JSON de service account. Cloud Run obtiene credenciales automáticamente con su service identity.

### Cuenta de despliegue

Separada de runtime. Necesita permisos para publicar la imagen, desplegar Cloud Run y actuar como la service account de runtime, pero no necesita leer los findings durante el build.

## Dominio y acceso web

Para una URL como `vulnerabilidades.latam.com` se necesita:

1. Aprobación del subdominio por el equipo dueño de DNS.
2. Registro DNS apuntando al Load Balancer.
3. Certificado TLS administrado por Google.
4. Backend serverless NEG que apunte a Cloud Run.
5. Ingress de Cloud Run limitado a `internal-and-cloud-load-balancing` para impedir el bypass por `run.app`.
6. IAP habilitado en el backend y acceso otorgado al grupo corporativo.
7. Cloud Armor para reglas WAF, rate limiting y restricciones adicionales si la política de LATAM lo exige.

## Autenticación y autorización

### Producción

IAP autentica al usuario con Google Workspace. El backend valida la identidad firmada por IAP y aplica roles propios:

- `viewer`: consultar y exportar.
- `operator`: además puede proponer o ejecutar movimientos de squad.
- `admin`: administrar configuración funcional.

La identidad del usuario debe acompañar cada evento de auditoría.

### Piloto con clave fija

Solo como transición. La clave iría en Secret Manager; se compararía contra un hash Argon2/bcrypt y se usarían cookies `Secure`, `HttpOnly` y `SameSite=Strict`. No debe quedar en código, imagen, JavaScript ni variables visibles. Para el dominio corporativo se debe retirar este modo y usar IAP.

## Capa de datos

### Consultas live

No se replica el dato actual en archivos locales:

- El dashboard consulta BigQuery cuando el usuario pulsa ejecutar.
- Buscar CVE consulta SCC con coincidencia exacta y paginación completa.
- Artefactos consulta la vista de `panel_images`.
- Squads y propiedades corporativas se cruzan con CMDB en BigQuery.
- Un fallo de fuente se presenta como error; nunca como cero resultados.

### Dataset propio del panel

Se recomienda crear, por ejemplo, `latam_security_panel`, con tablas:

#### `artifact_squad_assignment_events`

Tabla append-only:

- `event_id`
- `artifact_key`
- `previous_squad`
- `new_squad`
- `reason`
- `requested_by`
- `approved_by`
- `status`
- `created_at`
- `effective_at`
- `source_version`

Una vista `v_current_artifact_squad_assignment` selecciona el último evento aprobado por artefacto. La CMDB fuente no se modifica.

#### `vulnerability_snapshot_runs`

Metadatos de cada ejecución programada:

- `run_id`, inicio, fin, estado, filas, bytes procesados, error resumido y versión del colector.

#### `vulnerability_snapshots`

Estado diario para tendencias, flapping y comparaciones. Particionada por fecha y agrupada por claves de consulta frecuentes.

#### `audit_events`

Eventos funcionales sensibles: movimiento, aprobación, exportación administrativa y cambio de configuración.

BigQuery es suficiente para esta primera versión porque el volumen de escrituras operativas será bajo y el producto ya necesita joins y reportería analítica. Si los movimientos crecen o requieren transacciones complejas, se puede agregar Firestore como almacén operacional sin cambiar las fuentes analíticas.

## Cómo se hacen las consultas

### BigQuery

- Usar el cliente oficial de Google Cloud para Python y Application Default Credentials.
- SQL con parámetros nombrados; nunca concatenar texto recibido del navegador.
- Consultar columnas concretas, no convertir filas completas a JSON en producción.
- Exigir rango temporal y aprovechar particiones.
- Paginación del lado del servidor.
- `maximumBytesBilled` por consulta y cuotas diarias del proyecto.
- Dry run para las consultas configurables o especialmente pesadas.
- Mostrar bytes procesados, tiempo de consulta y si el detalle fue truncado.
- Para garantizar lectura actual, desactivar la caché de resultados en las consultas que el producto etiquete como live.

### Security Command Center

- Usar el cliente/API v2 con el filtro exacto del CVE.
- Paginar hasta agotar `nextPageToken`.
- Validar que cada finding corresponda al CVE solicitado.
- Mantener separados `ACTIVE`, `INACTIVE` y `MUTED`.
- Conservar evidencia de proyecto, recurso, imagen, paquete, versión instalada/corregida, severidad, timestamps y fuente.
- Campos ausentes se muestran como `N/D`, no se inventan.

### Cruce de squads

- Normalizar project ID, artifact URI y nombre de IT Element.
- Cruzar findings/artefactos con `gcp_project` e `it_element`.
- Aplicar al final la vista de asignaciones aprobadas del panel.
- Señalar ambigüedades: cero coincidencias, múltiples IT Elements o squad ausente.

## Backend de producción

Migrar el servidor a FastAPI con Uvicorn/Gunicorn o un servidor ASGI equivalente. Mantener los contratos JSON ya creados.

Cambios obligatorios:

- Sustituir `gcloud auth print-access-token` por ADC/service identity.
- Sustituir estado de jobs en memoria por identificadores persistentes de BigQuery y una tabla de estado.
- Health checks separados: proceso vivo y dependencias disponibles.
- Timeouts, reintentos con backoff y cancelación.
- Límites de concurrencia y rate limiting.
- Respuestas paginadas y límites de exportación.
- Validación estructurada con Pydantic.
- Headers de seguridad, CSP, CSRF para escrituras y CORS cerrado al dominio oficial.
- No registrar tokens, findings completos sensibles ni SQL con datos personales.

## Frontend de producción

El frontend actual puede conservarse; no hay obligación de adoptar React. Antes de producción necesita:

- Mostrar usuario y rol obtenidos desde el backend.
- Paginación y ordenamiento server-side.
- Estados uniformes: sin consulta, ejecutando, parcial, completado, error y cancelado.
- Confirmación y motivo obligatorio para mover un artefacto.
- Vista de historial y aprobación del movimiento.
- Accesibilidad de teclado, contraste y lector de pantalla.
- Exportaciones con límites y registro cuando sean sensibles.

Si el crecimiento funcional vuelve difícil mantener JavaScript nativo, la migración natural sería TypeScript más un framework ligero, pero no es requisito del primer despliegue.

## Automatización de las 05:00

Crear un Cloud Run Job independiente y un Cloud Scheduler:

- Cron: `0 5 * * 1-5`.
- Zona horaria: `America/Guatemala`.
- Autenticación OIDC con una service account invocadora.
- El job consulta las fuentes, escribe snapshot y metadatos de ejecución.
- Reintentos acotados; una corrida no debe solaparse con otra.
- Alerta si falla, tarda más del umbral o devuelve un cambio anómalo de volumen.

Los datos actuales del panel siguen consultándose en vivo. El snapshot se usa únicamente para tendencias, comparaciones, flapping y reportes históricos.

## Observabilidad

- Cloud Logging con JSON estructurado y correlation ID.
- Cloud Monitoring para latencia, errores, jobs, bytes de BigQuery y tasa de consultas.
- Error Reporting para excepciones no controladas.
- Alertas sobre 5xx, 403 de fuentes, cuota, timeout, fallos del job de las 05:00 y costo.
- Cloud Audit Logs para accesos y cambios de IAM/datos.
- Dashboard operativo separado del dashboard funcional.

## Seguridad adicional

- Secret Manager solo para secretos reales; IDs de proyecto y tablas son configuración, no secretos.
- VPC Service Controls si las fuentes están dentro de un perímetro corporativo.
- Binary Authorization y escaneo de vulnerabilidades de la imagen si la política lo requiere.
- Imagen base mínima, usuario no root, sistema de archivos de solo lectura cuando sea viable.
- Dependencias fijadas y actualizadas; SBOM y escaneo en CI.
- Protección contra CSV injection, XSS, SQL injection, CSRF y open redirects.
- Retención y clasificación de logs/resultados acordes con política LATAM.

## CI/CD

1. Repositorio corporativo.
2. Pull request con revisión.
3. Cloud Build ejecuta pruebas Python, validación JavaScript, lint y escaneo.
4. Construye una imagen inmutable y la publica en Artifact Registry.
5. Despliega primero a desarrollo/staging.
6. Pruebas smoke contra fuentes con permisos de solo lectura.
7. Aprobación manual para producción.
8. Cloud Run crea una nueva revisión con rollback disponible.

Infraestructura recomendada como código: Terraform para APIs, service accounts, IAM, Artifact Registry, Cloud Run, Load Balancer, IAP, DNS/certificado, Scheduler, dataset y alertas.

## APIs que se deben habilitar

- Cloud Run Admin API
- Artifact Registry API
- Cloud Build API
- BigQuery API
- Security Command Center API
- Identity-Aware Proxy API
- Compute Engine API para Load Balancer/NEG
- Certificate Manager API
- Cloud Scheduler API
- Cloud Logging y Cloud Monitoring APIs
- Secret Manager API solo si se mantiene temporalmente la clave fija

## Información y aprobaciones necesarias de LATAM

1. Proyecto host y cost center donde desplegar.
2. Subdominio corporativo y equipo de DNS.
3. Región permitida y requisitos de residencia.
4. Google Group autorizado para entrar.
5. Dueño y aprobador de movimientos de squad.
6. Permiso de lectura para la service account sobre SCC y los tres proyectos de datos.
7. Dataset propio autorizado para asignaciones, auditoría e históricos.
8. Retención de snapshots y logs.
9. Presupuesto/cuota BigQuery por consulta y por día.
10. Requisitos de VPC Service Controls, CMEK, Cloud Armor y Binary Authorization.

## Orden de implementación

### Fase 1 — endurecer el código

- FastAPI/ASGI, ADC, cliente oficial BigQuery/SCC, paginación, jobs persistentes, Dockerfile y pruebas.

### Fase 2 — infraestructura no productiva

- Proyecto dev, IAM, dataset propio, Artifact Registry, Cloud Run y acceso privado temporal.

### Fase 3 — seguridad y dominio

- Load Balancer, certificado, DNS, IAP, grupos, ingress restringido, Cloud Armor y pruebas de penetración básicas.

### Fase 4 — funciones operativas

- Movimiento auditado de squad, aprobaciones, snapshots de las 05:00, reportes y alertas.

### Fase 5 — producción

- UAT con el equipo, runbook, rollback, monitoreo, responsables y aprobación final.

## Criterios de aceptación de producción

- Ninguna fuente funcional depende de archivos locales ni de una sesión humana.
- Usuario no autorizado no puede llegar al servicio ni por el dominio ni por `run.app`.
- La service account solo puede leer fuentes aprobadas y escribir el dataset propio.
- Una falla de SCC/BigQuery se ve como falla, no como cero.
- Toda modificación de squad tiene actor, motivo, hora, estado y trazabilidad.
- Consultas pesadas tienen límite de bytes y rango temporal.
- El job de las 05:00 es idempotente y alerta al fallar.
- Existe rollback probado y documentación operativa.
