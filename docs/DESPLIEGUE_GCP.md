# Despliegue del panel en GCP (analisis, no implementado)

Estado: solo analisis. El panel sigue corriendo local. Fecha: 2026-11-05.

## 1. Stack actual
- Backend: Python 3 puro (`http.server`, sin framework ni librerias externas).
- Frontend: HTML, CSS y JavaScript sin framework.
- Base de datos: ninguna. Estado en JSON locales (ediciones manuales) y CSV semilla (`app/semilla/`). Trabajos largos en memoria.
- Consultas: REST a Security Command Center, Cloud Asset Inventory, Artifact Registry y BigQuery (parametrizado).
- Identidad: token efimero de `gcloud` de quien lo corre; cada persona ve lo que ve su cuenta.

## 2. Que cambia al pasar a la nube
| Hoy | En la nube | Cambio |
|---|---|---|
| Token de gcloud del usuario | No hay gcloud ni sesion de usuario | Cuenta de servicio (token del servidor de metadatos, sin llaves) |
| Trabajos en memoria con sondeo | Varias instancias o escala a cero | Mientras tanto: 1 instancia minima y 1 maxima. Luego estado compartido (Firestore) |
| Evidencia en archivos | Disco efimero | Cloud Logging o tabla de BigQuery |
| Solo 127.0.0.1 | Dominio propio | Ajustar validacion Host/Origin y CSRF |
| Cualquiera en la PC | Cualquiera en el dominio | Validar JWT de IAP en la app |
| Codigo viejo con CLI (`gcp_collect.py`) | Sin CLI | Retirar o reemplazar |

## 3. Decision clave: identidad
- A. Cuenta de servicio + acceso por grupo (IAP). Recomendada. Costo: todos los del grupo ven lo que ve la cuenta de servicio; requiere aprobacion de seguridad por el acceso a nivel organizacion y auditoria de consultas.
- B. Identidad de cada usuario. Mas estricta y mucho mas compleja (OAuth por usuario); IAP no entrega tokens para llamar a GCP.
- Si cada squad debe ver solo lo suyo, hace falta una capa de autorizacion en la app. Definirlo antes de empezar.

## 4. Permisos de la cuenta de servicio
- Security Center Findings Viewer (organizacion) y Cloud Asset Viewer (organizacion).
- Artifact Registry Reader sobre `pipeline-corporativo`.
- BigQuery Data Viewer sobre findings y CMDB; BigQuery Job User en el proyecto de facturacion.
- Escritura en un dataset propio (auditoria, historicos) y Logging Writer.
- APIs habilitadas: Security Command Center, Cloud Asset, Artifact Registry, BigQuery, Cloud Run, IAP, Scheduler.
- Pendiente tambien para el dashboard: resolver el 403 en `sp-te-secproject-prod-h5ls.scce_tvm.findings`.

## 5. Arquitectura propuesta por Codex y ajustes
Usuario -> dominio LATAM + TLS -> Load Balancer -> Cloud Armor + IAP -> Cloud Run (web) -> SCC API, BigQuery (findings, artefactos, CMDB, propio). Cloud Scheduler 05:00 L-V -> Cloud Run Job -> snapshots en BigQuery.

Ajustes:
- Balanceador y Cloud Armor: no en el dia uno si IAP ya limita a cuentas corporativas, salvo estandar de LATAM. Cloud Run permite IAP directo; confirmar patron con PaaS.
- BigQuery para historicos y auditoria (solo agregar). Para estado editable o de trabajos, Firestore.
- Agregar Cloud Logging para auditoria (usuario, filtros, hora).
- Dos caminos de datos: BigQuery para el dashboard (particion por fecha, tope de bytes facturados, agregados precalculados por el job de las 5am) y la API de SCC para CVE exacto y escaneo por imagen.
- Decidir Cloud Run contra GKE: los despliegues de LATAM corren en GKE con pipeline corporativo.

## 6. Pasos en orden
1. Aprobaciones: proyecto dedicado con facturacion, runtime permitido, patron IAP y dominio, revision de seguridad, registro en CMDB, grupo de usuarios.
2. Codigo: proveedor de token por metadatos, Dockerfile, configuracion por variables de entorno (puerto, dominio, modo nube o local), validacion de JWT de IAP, bitacora a Cloud Logging, instancia fija mientras los trabajos sean en memoria.
3. Despliegue en proyecto de pruebas con grupo pequeno; luego produccion por el pipeline corporativo.
4. Segunda fase: dashboard sobre BigQuery, snapshots diarios (idempotentes, con alertas si falla), definicion de flapping (requiere historico diario por hallazgo).
5. Endurecimiento: estado compartido, cuotas de SCC y Cloud Asset con varios usuarios, alertas y monitoreo.
Nota: la app aparecera en SCC como otro artefacto con sus CVE; mantenerla limpia.

## 7. Preguntas para PaaS y seguridad
- Cloud Run permitido o estandar GKE con pipeline corporativo?
- Como se publica un servicio interno con IAP y dominio LATAM, y quien lo configura?
- Se aprueba una cuenta de servicio con lectura en SCC y Cloud Asset a nivel organizacion? Que revision pide seguridad?
- Cada squad ve todo o solo lo suyo?
- Quien es el dueno operativo y quien responde si falla el trabajo de las 5am?
