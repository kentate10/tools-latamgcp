# Tools LatamGCP — plan y bitácora

Última actualización: 2026-09-24

## Contexto

Prisma será dado de baja. Tools LatamGCP debe conservar la vista operacional por squad, pero sus vulnerabilidades se construirán exclusivamente con fuentes GCP. Los datos de vulnerabilidad del panel anterior no se importan, mezclan ni usan como referencia, porque provienen de otro motor de escaneo.

El panel nuevo debe permitir, como mínimo:

- Ver squads y los proyectos GCP asignados a cada squad.
- Inventariar repositorios, artefactos, imágenes, digests y tags.
- Identificar imágenes base cuando exista evidencia confiable.
- Ver vulnerabilidades por squad, proyecto, repositorio, artefacto e imagen.
- Clasificar severidad, SLA, antigüedad, disponibilidad de fix y estado.
- Distinguir imágenes almacenadas de imágenes realmente desplegadas.
- Mostrar datos sin otorgar al usuario final acceso directo a producción.
- Mantener trazabilidad, controles de acceso individuales y auditoría.

El panel actual de Railway es una referencia de experiencia de usuario y reglas de negocio. No debe convertirse directamente en el sistema productivo nuevo: usa una contraseña compartida, carga resúmenes manuales y almacenamiento local en un volumen. Esas decisiones fueron adecuadas para el prototipo, pero no para información confidencial conectada a producción.

## Decisiones iniciales

1. Crear un proyecto GCP dedicado para la herramienta, separado de los proyectos productivos observados. Nombre provisional: `latam-tools-prod`.
2. El acceso a producción será de solo lectura y mediante identidades de servicio de GCP; no se guardarán llaves JSON.
3. La aplicación web no consultará producción directamente por cada visita. Recolectores programados obtendrán datos, los normalizarán y publicarán snapshots para el panel.
4. Los permisos de lectura se limitarán a la carpeta o lista de proyectos acordada. No se solicitará acceso a toda la organización si no es necesario.
5. Los usuarios ingresarán con sus cuentas corporativas por Identity-Aware Proxy (IAP), preferiblemente mediante un Google Group. No habrá contraseña compartida del panel.
6. El dominio personalizado irá detrás de un Application Load Balancer externo, certificado TLS administrado e IAP. No se usará el domain mapping de Cloud Run como opción productiva principal.
7. El primer piloto será con un squad y proyectos no productivos o de alcance reducido. Producción se conecta después de validar exactitud, permisos y auditoría.
8. Prisma no se retira hasta completar los criterios operativos de aceptación de la nueva herramienta. La validación de vulnerabilidades se hará contra consultas directas de SCC y Artifact Analysis, no contra los datos del panel anterior.

## Arquitectura propuesta

```text
Usuarios del equipo
        |
        v
Dominio LATAM + HTTPS + Load Balancer + IAP
        |
        v
Cloud Run: aplicación web/API
        |-----------------------> Firestore: squads, ownership, notas y excepciones
        |
        +-----------------------> BigQuery: inventario, snapshots y vulnerabilidades

Cloud Scheduler
        |
        v
Cloud Run Jobs: recolectores de solo lectura
        |----> Cloud Asset Inventory: organización, carpetas, proyectos y recursos
        |----> Artifact Registry: repositorios, artefactos, imágenes, digests y tags
        |----> Artifact Analysis: CVE/paquetes/fix por digest
        |----> Security Command Center: findings y postura de seguridad
        `----> GKE/Cloud Run: referencias de imágenes desplegadas, en una segunda etapa

Cloud Logging + Audit Logs + Monitoring
```

### Componentes

| Componente | Uso |
|---|---|
| Proyecto host dedicado | Aísla la herramienta de los workloads productivos. |
| Cloud Run | Hospeda la aplicación web y API sin administrar servidores. |
| Application Load Balancer | Publica el dominio corporativo, termina TLS y dirige tráfico a Cloud Run. |
| IAP | Autentica usuarios corporativos y autoriza por grupo. |
| Cloud Run Jobs | Ejecuta recolectores sin exponer endpoints públicos. |
| Cloud Scheduler | Programa recolecciones periódicas. |
| BigQuery | Guarda snapshots, historia y tablas de consulta del inventario/vulnerabilidades. |
| Firestore | Guarda catálogo editable: squads, owners, notas, excepciones y configuración. |
| Secret Manager | Guarda únicamente secretos de aplicación que realmente sean necesarios. |
| Cloud Logging/Monitoring | Auditoría, errores, métricas, alertas y operación. |
| Terraform | Define de forma revisable IAM, APIs, servicios, datasets, jobs, red y dominio. |

## Fuentes de datos

### 1. Organización, carpetas y proyectos

Cloud Asset Inventory será la fuente principal para descubrir recursos en el alcance aprobado. El mapeo squad-proyecto no debe depender solamente del nombre del proyecto.

Convención recomendada de metadatos:

- `latam_squad`: identificador estable del squad.
- `latam_owner`: grupo o responsable operativo.
- `latam_environment`: `prod`, `stage`, `dev`, etc.
- `latam_business_service`: servicio o IT element, si aplica.

Si todavía no existen esos tags/labels, se mantiene una tabla manual `squad_projects` y se muestra explícitamente todo proyecto sin asignar. La meta posterior es que la metadata de GCP sea la fuente de verdad.

### 2. Artefactos, imágenes y tags

Artifact Registry entregará repositorios, packages, versions/digests, tags y fechas. La recolección será read-only.

No se debe usar únicamente un tag como identidad de una imagen: los tags pueden moverse. El identificador técnico será el digest y la interfaz mostrará los tags asociados.

### 3. Vulnerabilidades

- Artifact Analysis será la fuente directa para vulnerabilidades de imágenes y paquetes por digest.
- SCC aportará findings de seguridad y postura del recurso. No se debe asumir que todos los findings de SCC equivalen a un CVE de una imagen.
- La interfaz mantendrá separadas las fuentes y documentará cobertura, fecha de actualización y alcance.

Clave de negocio propuesta para evitar dobles conteos:

```text
source + project + image_digest + vulnerability_id + package_name + installed_version
```

Se conservarán también los identificadores nativos del finding/occurrence. Un mismo CVE en dos paquetes, versiones o digests representa exposiciones distintas; el panel podrá mostrar tanto CVE únicos como hallazgos.

### 4. Imágenes realmente desplegadas

El inventario de registry no indica por sí solo qué imagen está corriendo. En una segunda etapa se recopilarán referencias de imágenes de:

- Deployments/Pods de GKE.
- Revisiones de Cloud Run.
- Otros runtimes que el equipo confirme.

Siempre que sea posible, la correlación se hará por digest. Si un workload usa solo un tag, se marcará como referencia mutable y con menor confianza.

### 5. Imágenes base

La imagen final no siempre permite reconstruir de forma confiable la imagen base usada en el build. Para tener esta vista se requiere una de estas evidencias:

- Provenance/attestations del pipeline de build.
- SBOM asociado al digest.
- Metadata normalizada emitida por CI/CD, incluyendo `base_image` y `base_digest`.
- Como transición, labels OCI acordados o análisis del Dockerfile, si el repositorio fuente es accesible.

El panel no debe adivinar la imagen base. Mostrará `desconocida` cuando la evidencia no exista. Para builds nuevos, la recomendación es exigir base image por digest y publicar provenance/SBOM.

## Modelo mínimo de datos

| Entidad | Campos principales |
|---|---|
| `squads` | id, nombre, owner_group, estado |
| `squad_projects` | squad_id, project_id, environment, fuente, vigencia |
| `repositories` | project_id, location, repository, formato |
| `images` | repository, package, digest, created_at, updated_at |
| `image_tags` | digest, tag, first_seen, last_seen |
| `deployments` | project, runtime, workload, namespace, image_ref, digest, observed_at |
| `vulnerability_findings` | fuente, CVE, digest, paquete, versión, severidad, CVSS, fix, estado, fechas |
| `base_images` | child_digest, base_ref, base_digest, evidence_type, confidence |
| `exceptions` | finding_key, razón, aprobador, fecha_expiración, estado |
| `snapshots` | source, scope, collected_at, status, row_count, error |

## Clasificación funcional

El panel debe permitir filtros y métricas por:

- Squad, proyecto, ambiente, región y repositorio.
- Artefacto, digest, tag y workload desplegado.
- Severidad original de la fuente y severidad normalizada.
- CVE, paquete, versión instalada y versión con fix.
- Con fix/sin fix.
- Activa, resuelta, muted/exceptuada o desconocida.
- Dentro/fuera de SLA y días vencidos.
- Desplegada en producción, desplegada fuera de producción o solo almacenada.
- Imagen base, dependencia de aplicación o clasificación desconocida, únicamente cuando exista evidencia.

Las reglas de SLA serán configuración versionada, no lógica escondida en la interfaz. Ejemplo pendiente de aprobación: Critical, High, Medium y Low con días distintos según ambiente y disponibilidad de fix.

## IAM y seguridad

### Acceso humano

- Un Google Group, por ejemplo `gcp-tools-latam@dominio`, obtiene acceso IAP.
- Grupos separados para viewer y administrador del catálogo si se permiten ediciones.
- Ningún usuario final recibe permisos directos sobre los proyectos productivos por usar el panel.
- MFA y políticas corporativas continúan aplicando a las cuentas del dominio.

### Identidades de servicio

Separar como mínimo:

1. `tools-web`: lee BigQuery/Firestore y escribe solo las notas/configuración permitidas.
2. `tools-collector-assets`: lectura de Cloud Asset Inventory en el alcance aprobado.
3. `tools-collector-artifacts`: `roles/artifactregistry.reader` en los repositorios/proyectos aprobados y `roles/containeranalysis.occurrences.viewer` para resultados de vulnerabilidades.
4. `tools-collector-scc`: `roles/securitycenter.findingsViewer` en la carpeta/proyectos aprobados; acceso organizacional solo si el alcance realmente lo requiere.
5. `tools-scheduler`: únicamente permiso para ejecutar los jobs correspondientes.
6. `tools-deployer`: permisos de despliegue, sin permisos de lectura de findings productivos durante runtime.

Aplicar mínimo privilegio. Si un rol predefinido contiene permisos innecesarios, evaluar un custom role después de observar las llamadas reales del piloto.

### Controles adicionales

- Restringir Cloud Run a tráfico de Load Balancer/IAP y evitar acceso público anónimo.
- No crear ni descargar service account keys; usar service identities/ADC.
- Secret Manager con acceso por secreto, no por proyecto completo.
- Registrar accesos y cambios de configuración; habilitar Data Access audit logs donde el riesgo/costo lo justifique.
- No registrar tokens, payloads completos de findings ni datos confidenciales en logs de aplicación.
- Definir retención de BigQuery y Logging antes de producción.
- Backups/export de Firestore y estrategia de recuperación del catálogo manual.
- Alertas por fallas de recolección, snapshot vencido y aumento anormal de findings críticos.
- Separar `dev`, `stage` y `prod`, al menos por proyectos distintos para la plataforma.

## Etapas de implementación

### Fase 0 — Descubrimiento y reglas (2–4 días)

- Confirmar organización/folder/proyectos en alcance.
- Confirmar SCC tier, ubicación y fuentes habilitadas.
- Confirmar Artifact Analysis y repositorios existentes.
- Obtener la fuente actual squad-proyecto-IT element.
- Definir reglas de severidad, SLA, deduplicación y excepción.
- Elegir región y requisitos de residencia/retención.
- Acordar dominio y Google Group de acceso.

Salida: matriz de alcance, modelo de datos y permisos aprobados.

### Fase 1 — Prueba read-only con un squad (3–5 días)

- Crear proyecto sandbox/dev de Tools LatamGCP.
- Habilitar APIs necesarias.
- Crear service accounts sin llaves.
- Conceder permisos de lectura a uno o pocos proyectos.
- Probar inventario de proyectos, Artifact Registry, Artifact Analysis y SCC.
- Validar resultados con consultas directas de SCC y Artifact Analysis y documentar su cobertura propia.

Salida: evidencia de cobertura, huecos y permisos mínimos reales.

### Fase 2 — Pipeline y almacenamiento (4–7 días)

- Crear BigQuery y Firestore.
- Implementar recolectores idempotentes como Cloud Run Jobs.
- Programarlos con Cloud Scheduler.
- Guardar snapshots y estado de cada ejecución.
- Implementar normalización, deduplicación y pruebas de conteos.

Salida: datos automáticos y trazables sin interfaz final.

### Fase 3 — Panel MVP (5–8 días)

- Reutilizar conceptos visuales del panel actual, no su autenticación/almacenamiento.
- Vistas por squad, proyecto, artefacto, imagen, tag y vulnerabilidad.
- Mostrar cobertura, última recolección y errores de fuente.
- Agregar filtros SLA/severidad/fix/despliegue.
- Mantener exportación controlada si el equipo la necesita.

Salida: MVP validado por usuarios designados.

### Fase 4 — Acceso seguro y dominio (3–5 días)

- Cloud Run productivo.
- Load Balancer, certificado TLS e IAP.
- Grupo corporativo y roles de viewer/admin.
- DNS para el subdominio acordado.
- Audit logs, alertas, budgets y runbook.
- Pruebas de usuario autorizado/no autorizado.

Salida: panel productivo privado.

### Fase 5 — Producción completa y retiro de Prisma (1–2 semanas de observación)

- Expandir permisos read-only al alcance aprobado.
- Validar diariamente la cobertura y conteos contra las fuentes GCP directas.
- Corregir diferencias internas entre el panel y sus fuentes GCP.
- Obtener aprobación de Seguridad, Cloud Platform y dueños de squads.
- Congelar reportes de cierre y plan de rollback.
- Retirar Prisma únicamente tras la aprobación formal.

Estimación inicial: 3–5 semanas para un MVP productivo, condicionada por IAM, calidad del mapeo squad-proyecto, cantidad de registries/runtimes y aprobaciones de dominio/seguridad.

## Criterios para considerar el panel listo

- 100% de proyectos en alcance están asignados a un squad o marcados explícitamente como sin asignar.
- Conteos por fuente reconcilian con consultas directas de GCP en una muestra acordada.
- Cada métrica indica fuente, alcance y fecha de recolección.
- No existen credenciales estáticas ni acceso anónimo.
- Usuarios fuera del grupo no pueden entrar; viewers no pueden modificar configuración.
- Los recolectores solo tienen permisos read-only sobre producción.
- Existe auditoría de acceso y cambios administrativos.
- Fallas de recolección no borran el último snapshot válido y se muestran como datos vencidos.
- Existen runbook, respaldo y rollback.
- Cobertura, limitaciones y reglas de clasificación de SCC/Artifact Analysis están documentadas y aceptadas antes del retiro.

## Información pendiente del equipo

1. ID de organización y carpeta(s) que contienen el alcance LATAM.
2. Lista inicial de proyectos productivos y no productivos.
3. Regiones y repositorios Artifact Registry; confirmar si aún existe Container Registry.
4. SCC tier/activation level y fuentes actualmente habilitadas.
5. Confirmar si Artifact Analysis scanning está habilitado en todos los proyectos relevantes.
6. Fuente oficial de squads, owners, proyectos e IT elements.
7. Runtimes a cubrir: GKE, Cloud Run, Compute Engine u otros.
8. Grupo corporativo que accederá y quién administrará membresía.
9. Subdominio deseado y responsable de DNS, por ejemplo `tools.latam.<dominio>`.
10. Región GCP permitida, retención de información y requisitos regulatorios.
11. Frecuencia esperada: cada hora, cada 6 horas o diaria.
12. Reglas de SLA y flujo de aprobación de excepciones.

## Próximo paso recomendado

Hacer una sesión de descubrimiento de 60–90 minutos y completar la información pendiente. Después, ejecutar un PoC read-only con un squad y 1–3 proyectos. No empezar con toda la organización: el PoC debe probar cobertura, costos, permisos y granularidad antes de ampliar el alcance.

## Bitácora de decisiones

### 2026-09-24

- Se inicia el diseño de `Tools LatamGCP` como sucesor del seguimiento basado en Prisma.
- El panel existente se usará como referencia funcional.
- Se recomienda una arquitectura GCP nativa, con acceso individual por IAP y recolección read-only.
- Se identifica que la relación squad-proyecto y la imagen base necesitan fuentes de verdad explícitas; no deben inferirse silenciosamente.
- No se realizaron cambios en Railway ni en producción durante esta etapa.

### 2026-09-24 — inicio del MVP local

- Se confirmó Google Cloud SDK 583.0.0 y sesión activa con la cuenta corporativa.
- Se identificó la organización `lan.com` (`766905427223`).
- Se validó acceso read-only al proyecto `pipeline-corporativo` y a sus repositorios Artifact Registry.
- Se creó `app/`, un panel local en loopback que conserva el gestor de squads, IT elements y artefactos.
- Se importaron 672 artefactos y 50 squads del catálogo manual. El grupo adicional visible corresponde a asignaciones pendientes.
- El inventario inicial contiene 6,314 imágenes del resumen del 2026-09-24; no contiene vulnerabilidades.
- Se configuraron los repositorios `application-master`, `application-intg`, `application-cert`, `application-develop`, `application-feature` y `base-images` para la recolección GCP.
- Se validó la lectura real de digests y tags de Artifact Registry, incluida la interpretación de tags como `master-214-...`.
- No se importará `vulnerabilidades.json` ni ningún conteo de Prisma. SCC y Artifact Analysis serán las únicas fuentes de vulnerabilidad.
- Bloqueo confirmado: falta `containeranalysis.occurrences.list` en `pipeline-corporativo`.
- Se corrigió el proyecto de cuota SCC a `sp-te-secproject-prod-h5ls` y se validó la ubicación `global`.
- Se generó el primer snapshot SCC local: 1,000 hallazgos con CVE, 258 CVE únicos y 77 hallazgos con imagen. La consulta alcanzó su límite y se presenta como cobertura parcial.
- Los hallazgos SCC sin coincidencia exacta con el catálogo permanecen en `Por validar asignacion`; no se asignan a un squad por inferencia.
- Se agregó gestión manual de proyectos por squad. Las altas, movimientos y bajas de esa relación actualizan inmediatamente la clasificación de hallazgos SCC.
- El servidor local permanece ligado exclusivamente a `127.0.0.1:8765`, sin IP pública.
- No existe fuente de verdad de squads. El catálogo curado desde el panel será la fuente operativa inicial y permitirá altas, bajas, movimientos y archivo lógico.

## Referencias oficiales

- Cloud Asset Inventory — búsqueda de recursos: https://docs.cloud.google.com/asset-inventory/docs/search-resources
- Cloud Asset Inventory — roles y permisos: https://docs.cloud.google.com/asset-inventory/docs/roles-permissions
- Artifact Registry — listar imágenes y tags: https://cloud.google.com/artifact-registry/docs/docker/manage-images
- Artifact Analysis — container scanning: https://docs.cloud.google.com/artifact-analysis/docs/container-scanning-overview
- Artifact Analysis — investigar vulnerabilidades: https://docs.cloud.google.com/artifact-analysis/docs/investigate-vulnerabilities
- Artifact Analysis — SBOM: https://docs.cloud.google.com/artifact-analysis/docs/sbom-overview
- SCC — exportar datos: https://docs.cloud.google.com/security-command-center/docs/how-to-export-data
- SCC — control de acceso: https://docs.cloud.google.com/security-command-center/docs/access-control-org
- Cloud Run — IAP: https://docs.cloud.google.com/run/docs/securing/identity-aware-proxy-cloud-run
- Cloud Run — custom domains: https://docs.cloud.google.com/run/docs/mapping-custom-domains
- Cloud Run — ingress: https://docs.cloud.google.com/run/docs/securing/ingress
- Cloud Run Jobs con Scheduler: https://docs.cloud.google.com/run/docs/execute/jobs-on-schedule
- Secret Manager — buenas prácticas: https://docs.cloud.google.com/secret-manager/docs/best-practices
- Cloud Audit Logs: https://docs.cloud.google.com/logging/docs/audit
