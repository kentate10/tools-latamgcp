# Tools LatamGCP — bloqueos y estado local

Última actualización: 2026-09-24

| Área | Estado | Evidencia / bloqueo | Acción necesaria |
|---|---|---|---|
| Autenticación gcloud | Disponible | Cuenta activa `kendertate.ibm@latam.com`; SDK 583.0.0. | Ninguna para el MVP local. |
| Organización | Disponible | Organización `lan.com`, ID `766905427223`. | Definir el folder/proyectos finales antes de producción. |
| Artifact Registry | Disponible, cobertura parcial | Primera sincronización: 15,596 tags. `application-intg` y `application-cert` terminaron completos; cuatro repositorios alcanzaron el límite de 5,000 digests. Los registros iniciales no vistos se preservan como `stale`, no como eliminados. | Implementar recolección por paquete/catálogo o paginación persistente para cobertura completa y eficiente. |
| Artifact Analysis | Bloqueado | Falta `containeranalysis.occurrences.list` en `pipeline-corporativo`. | Otorgar `roles/containeranalysis.occurrences.viewer` o custom role equivalente al usuario/identidad recolectora. |
| Security Command Center | Disponible, cobertura parcial | Consulta validada en `global` con `sp-te-secproject-prod-h5ls` como proyecto de cuota. Snapshot: 1,000 hallazgos, 258 CVE únicos, 77 con imagen; se alcanzó el límite y todos están todavía sin asociación de squad. | Implementar paginación/exportación persistente y completar el mapeo proyecto/imagen → squad. |
| Squads y proyectos | Manual, funcional | No existe fuente corporativa. Se importaron 672 artefactos y 50 squads. El gestor permite asignar/mover/quitar proyectos y aplica esa relación a SCC. Cuatro proyectos detectados siguen sin asignación. | Completar el mapeo manual y posteriormente definir governance/owners. |
| Imágenes base | Parcial | No hay evidencia `base_version` para todas las imágenes; no se debe inferir. | Conservar correcciones manuales y solicitar labels/provenance/SBOM para builds nuevos. |
| Imágenes desplegadas | Pendiente | Artifact Registry indica imágenes almacenadas, no necesariamente en ejecución. | Incorporar GKE/Cloud Run después de definir proyectos/clusters en alcance. |
| Producción/dominio | Fuera de esta etapa | El usuario indicó correr local por ahora. | Se abordará después del MVP local y permisos read-only. |
| Exposición de red | Cerrada | El servidor escucha exclusivamente en `127.0.0.1:8765`; no existe IP pública ni bind a la LAN. | Mantener esta restricción durante la etapa local. |

## Regla de datos

Las vulnerabilidades del panel anterior no se importan ni se comparan. El panel anterior aporta únicamente:

- Catálogo manual de squads, IT elements y artefactos.
- Notas y asignaciones manuales.
- Reglas de interpretación de tags/versiones.
- Evidencia explícita de imagen base, cuando exista.

Las vulnerabilidades de Tools LatamGCP provendrán exclusivamente de GCP: SCC y Artifact Analysis.
