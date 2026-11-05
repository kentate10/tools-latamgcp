"""Recolector read-only de CVE desde Security Command Center."""

from __future__ import annotations

import csv
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from gcp_collect import ROOT, atomic, read_json, run_gcloud


SCC_FILTER = 'vulnerability.cve.id:"CVE-"'
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SAFE_LOCATION = re.compile(r"^(global|us|eu|sa)$")
SAFE_PROJECT = re.compile(r"^[a-z][a-z0-9-]{3,62}$")
SAFE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
GUATEMALA_TZ = timezone(timedelta(hours=-6), name="America/Guatemala")


def classify_resource(resource_type="", category="", resource_name="", has_kubernetes=False):
    """Clasifica el hallazgo en una familia estable para filtros y reportes."""
    value = " ".join((resource_type, category, resource_name)).casefold()
    if has_kubernetes or "google.container." in value or "container.googleapis.com" in value:
        return "CLUSTERS"
    if "artifactregistry" in value or "container_image_vulnerability" in value:
        return "ARTIFACTS"
    if "google.compute." in value or "compute.googleapis.com" in value:
        return "COMPUTE"
    if "google.cloud.run" in value or "run.googleapis.com" in value:
        return "CLOUD_RUN"
    return "OTHER"


def classify_normalized_finding(finding):
    """Compatibilidad para snapshots anteriores a resourceCategory."""
    return classify_resource(
        finding.get("resourceType", ""),
        finding.get("category", ""),
        finding.get("resource", ""),
        bool(finding.get("components")),
    )


def validate_scc_config(config):
    scc = config.get("scc") or {}
    billing_project = scc.get("billing_project", "")
    location = scc.get("location", "global")
    limit = scc.get("max_findings", 1000)
    request_timeout = scc.get("request_timeout_seconds", 1800)
    if not SAFE_PROJECT.fullmatch(billing_project):
        raise ValueError("scc.billing_project no es válido")
    if not SAFE_LOCATION.fullmatch(location):
        raise ValueError("scc.location debe ser global, us, eu o sa")
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise ValueError("scc.max_findings debe estar entre 1 y 10000")
    if type(request_timeout) is not int or not 60 <= request_timeout <= 3600:
        raise ValueError("scc.request_timeout_seconds debe estar entre 60 y 3600")
    return scc


def catalog_rows(root):
    with (Path(root) / "Catalogo.csv").open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def image_leaf(reference):
    value = str(reference or "").split("@", 1)[0].rstrip("/")
    leaf = value.rsplit("/", 1)[-1]
    if ":" in leaf:
        leaf = leaf.split(":", 1)[0]
    return leaf.casefold()


def image_references(finding):
    found = []

    def add(container):
        if not isinstance(container, dict):
            return
        uri = container.get("uri") or container.get("imageUri") or ""
        image_id = container.get("imageId") or ""
        reference = uri or image_id
        if reference:
            digest = image_id.split("@", 1)[-1] if "@" in image_id else image_id
            found.append({
                "uri": uri,
                "imageId": image_id,
                "reference": reference,
                "digest": digest,
                "containerName": container.get("name") or "",
            })

    for container in finding.get("containers") or []:
        add(container)
    for obj in (finding.get("kubernetes") or {}).get("objects") or []:
        for container in obj.get("containers") or []:
            add(container)
    unique = {}
    for item in found:
        unique[(item["uri"], item["imageId"])] = item
    return list(unique.values())


def kubernetes_components(finding):
    components = []
    for obj in (finding.get("kubernetes") or {}).get("objects") or []:
        containers = []
        for container in obj.get("containers") or []:
            containers.append({
                "name": container.get("name") or "",
                "uri": container.get("uri") or container.get("imageUri") or "",
                "imageId": container.get("imageId") or "",
            })
        components.append({
            "kind": obj.get("kind") or "",
            "name": obj.get("name") or "",
            "namespace": obj.get("ns") or obj.get("namespace") or "",
            "containers": containers,
        })
    return components


def artifact_mapping(images, catalog):
    artifacts = set()
    squads = set()
    for image in images:
        reference = image["reference"].casefold()
        leaf = image_leaf(reference)
        for row in catalog:
            query = (row.get("Buscar como") or row.get("Artefacto") or "").strip().casefold()
            if not query:
                continue
            matched = query == leaf or ("/" in query and query in reference)
            if matched:
                artifacts.add(row.get("Artefacto") or query)
                squad = (row.get("Squad") or "").strip()
                if squad and squad != "Por validar":
                    squads.add(squad)
    return sorted(artifacts), sorted(squads) or ["Por validar asignacion"]


def normalize_result(item, catalog):
    finding = item.get("finding") or {}
    resource = item.get("resource") or {}
    metadata = resource.get("gcpMetadata") or {}
    vulnerability = finding.get("vulnerability") or {}
    cve = vulnerability.get("cve") or {}
    offending = vulnerability.get("offendingPackage") or {}
    fixed = vulnerability.get("fixedPackage") or {}
    images = image_references(finding)
    components = kubernetes_components(finding)
    artifacts, squads = artifact_mapping(images, catalog)
    files = [entry.get("path") for entry in finding.get("files") or [] if entry.get("path")]
    score = (cve.get("cvssv3") or {}).get("baseScore")
    return {
        "id": finding.get("name") or finding.get("canonicalName"),
        "cve": cve.get("id") or "Sin CVE",
        "severity": finding.get("severity") or "UNSPECIFIED",
        "state": finding.get("state") or "UNSPECIFIED",
        "mute": finding.get("mute") or "UNDEFINED",
        "deactivationReason": (finding.get("sourceProperties") or {}).get("DeactivationReason") or "",
        "category": finding.get("category") or "",
        "source": finding.get("parentDisplayName") or "Security Command Center",
        "module": finding.get("moduleName") or "",
        "eventTime": finding.get("eventTime"),
        "createTime": finding.get("createTime"),
        "project": metadata.get("projectDisplayName") or "No determinado",
        "location": resource.get("location") or "No determinada",
        "resource": finding.get("resourceName") or resource.get("name") or "",
        "resourceType": resource.get("type") or "",
        "resourceCategory": classify_resource(
            resource.get("type") or "",
            finding.get("category") or "",
            finding.get("resourceName") or resource.get("name") or "",
            bool(components),
        ),
        "resourceDisplayName": resource.get("displayName") or "",
        "folders": [folder.get("resourceFolderDisplayName") for folder in metadata.get("folders") or [] if folder.get("resourceFolderDisplayName")],
        "images": images,
        "components": components,
        "files": files[:20],
        "artifacts": artifacts,
        "squads": squads,
        "package": {
            "name": offending.get("packageName") or "",
            "type": offending.get("packageType") or "",
            "version": offending.get("packageVersion") or "",
            "fixedVersion": fixed.get("packageVersion") or "",
        },
        "cvss": score,
        "fixAvailable": bool(cve.get("upstreamFixAvailable") or fixed.get("packageVersion")),
        "exploitationActivity": cve.get("exploitationActivity") or "",
        "lastSeen": finding.get("eventTime") or finding.get("createTime"),
    }


def summarize(findings):
    counts = {"total": len(findings), "active": 0, "inactive": 0, "muted": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "other": 0}
    by_squad = defaultdict(lambda: {key: 0 for key in counts})
    for finding in findings:
        severity = finding["severity"].lower()
        severity_key = severity if severity in {"critical", "high", "medium", "low"} else "other"
        state = finding["state"].lower()
        muted = finding["mute"] == "MUTED"
        counts[severity_key] += 1
        counts["muted"] += int(muted)
        if state in ("active", "inactive"):
            counts[state] += 1
        for squad in finding["squads"]:
            group = by_squad[squad]
            group["total"] += 1
            group[severity_key] += 1
            group["muted"] += int(muted)
            if state in ("active", "inactive"):
                group[state] += 1
    return counts, [{"squad": squad, **values} for squad, values in sorted(by_squad.items())]


def summarize_categories(findings):
    categories = defaultdict(lambda: {"findings": 0, "active": 0, "uniqueCves": set(), "projects": set()})
    for finding in findings:
        category = finding.get("resourceCategory") or classify_normalized_finding(finding)
        row = categories[category]
        row["findings"] += 1
        row["active"] += int(finding.get("state") == "ACTIVE")
        if finding.get("cve"):
            row["uniqueCves"].add(finding["cve"])
        if finding.get("project") and finding.get("project") != "No determinado":
            row["projects"].add(finding["project"])
    return [{
        "category": category,
        "findings": row["findings"],
        "active": row["active"],
        "uniqueCves": len(row["uniqueCves"]),
        "projects": len(row["projects"]),
    } for category, row in sorted(categories.items())]


def _evidence_directory(root, cve):
    parent = Path(root) / "evidence"
    parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(GUATEMALA_TZ).strftime("%Y%m%d-%H%M%S")
    candidate = parent / f"revision-{cve}-{stamp}"
    suffix = 2
    while candidate.exists():
        candidate = parent / f"revision-{cve}-{stamp}-{suffix}"
        suffix += 1
    candidate.mkdir()
    return candidate


def _markdown_cell(value):
    return str(value or "").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _write_cve_report(directory, result):
    findings = result["findings"]
    active = sum(item.get("state") == "ACTIVE" for item in findings)
    certainty = "Afectación reportada explícitamente por SCC" if findings else "Sin coincidencias SCC; cobertura limitada a las fuentes y permisos disponibles"
    lines = [
        f"# Resultado {result['query']['cve']}",
        "",
        f"**Resultado:** {len(findings)} hallazgos, {active} ACTIVE. **Certeza:** {certainty}.",
        "",
        f"- Fecha: {result['collectedAt']} (America/Guatemala)",
        f"- Organización: {result['coverage']['organization']}",
        f"- Ubicación SCC: {result['coverage']['location']}",
        f"- Filtro exacto: `{result['coverage']['filter']}`",
        f"- Resultado crudo: `{directory / 'scc-findings.json'}`",
        f"- Registros normalizados completos: `{directory / 'findings-normalizados.json'}`",
        "",
        "| Ambiente | Proyecto | Namespace / recurso | Imagen afectada | CVE | Severidad | Estado |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    if not findings:
        lines.append(f"| No determinado | No identificado | No identificado | No identificada | {result['query']['cve']} | Sin hallazgo SCC | Sin coincidencias SCC |")
    else:
        for finding in findings[:200]:
            component = (finding.get("components") or [{}])[0]
            namespace_resource = component.get("namespace") or finding.get("resourceDisplayName") or finding.get("resource") or "No identificado"
            image = (finding.get("images") or [{}])[0].get("reference")
            if not image:
                image = "No aplica (VM)" if finding.get("resourceCategory") == "COMPUTE" else "No identificada"
            state = finding.get("state") or "UNSPECIFIED"
            if state == "INACTIVE" and finding.get("deactivationReason"):
                state += f" ({finding['deactivationReason']})"
            lines.append("| " + " | ".join(_markdown_cell(value) for value in [
                "No determinado", finding.get("project"), namespace_resource, image,
                finding.get("cve"), finding.get("severity"), state,
            ]) + " |")
        if len(findings) > 200:
            lines.extend(["", f"La tabla muestra 200 de {len(findings)} hallazgos. El JSON normalizado conserva todas las filas."])
    lines.extend([
        "",
        "## Limitación",
        "",
        "El panel consulta SCC con los permisos actuales. La ausencia de coincidencias no certifica que el CVE no exista en recursos sin cobertura, imágenes no analizadas o fuentes no habilitadas. El boletín del fabricante no forma parte de esta consulta automática.",
        "",
    ])
    (directory / "resultado.md").write_text("\n".join(lines), encoding="utf-8")


def _list_scc_findings_rest(config, organization, scc, exact_filter, directory):
    """SCC v2 con token efímero de gcloud; el token nunca se persiste."""
    token = run_gcloud(config, ["auth", "print-access-token"], timeout=60).strip()
    if not token or any(character.isspace() for character in token):
        raise RuntimeError("gcloud no pudo entregar un access token válido")
    endpoint = (
        "https://securitycenter.googleapis.com/v2/organizations/"
        f"{organization}/sources/-/locations/{scc['location']}/findings"
    )
    page_directory = directory / "scc-pages"
    page_directory.mkdir()
    findings = []
    page_token = ""
    seen_tokens = set()
    pages = 0
    total_size = None
    while True:
        parameters = {
            "filter": exact_filter,
            "orderBy": "eventTime desc",
            "pageSize": "1000",
        }
        if page_token:
            parameters["pageToken"] = page_token
        url = endpoint + "?" + urllib.parse.urlencode(parameters)
        request = urllib.request.Request(url, headers={
            "Authorization": "Bearer " + token,
            "X-Goog-User-Project": scc["billing_project"],
            "Accept": "application/json",
            "User-Agent": "Tools-LatamGCP-local/1.0",
        })
        last_error = None
        for attempt in range(4):
            try:
                with urllib.request.urlopen(request, timeout=scc.get("request_timeout_seconds", 1800)) as response:
                    body = response.read().decode("utf-8")
                page = json.loads(body)
                last_error = None
                break
            except urllib.error.HTTPError as error:
                detail = error.read().decode("utf-8", errors="replace")[-4000:]
                if error.code not in (429, 500, 502, 503, 504) or attempt == 3:
                    raise RuntimeError(f"SCC REST respondió HTTP {error.code}: {detail}") from error
                last_error = error
            except TimeoutError as error:
                raise RuntimeError(f"SCC REST excedió el timeout configurado: {error}") from error
            except urllib.error.URLError as error:
                if isinstance(getattr(error, "reason", None), TimeoutError):
                    raise RuntimeError(f"SCC REST excedió el timeout configurado: {error}") from error
                if attempt == 3:
                    raise RuntimeError(f"No se pudo conectar a SCC REST: {error}") from error
                last_error = error
            time.sleep(2 ** attempt)
        if last_error is not None:
            raise RuntimeError(str(last_error))
        if not isinstance(page, dict) or not isinstance(page.get("listFindingsResults", []), list):
            raise RuntimeError("SCC REST devolvió una página con formato inesperado")
        pages += 1
        (page_directory / f"page-{pages:04d}.json").write_text(
            json.dumps(page, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        findings.extend(page.get("listFindingsResults") or [])
        if total_size is None:
            total_size = page.get("totalSize")
        next_token = page.get("nextPageToken") or ""
        if not next_token:
            break
        if next_token in seen_tokens:
            raise RuntimeError("SCC REST repitió el page token; resultado descartado por seguridad")
        seen_tokens.add(next_token)
        page_token = next_token
    return findings, {"transport": "scc-rest-v2", "pages": pages, "totalSize": total_size}


def query_exact_cve(cve, root=ROOT):
    """Consulta exacta sin límite configurado, conserva evidencia y devuelve el mismo esquema de la UI."""
    root = Path(root)
    normalized_cve = str(cve or "").strip().upper()
    if not SAFE_CVE.fullmatch(normalized_cve):
        raise ValueError("Usa un identificador CVE válido, por ejemplo CVE-2026-12345")
    config = read_json(root / "configuracion.json")
    scc = validate_scc_config(config)
    organization = str(config.get("organization_id", ""))
    if not organization.isdigit():
        raise ValueError("organization_id debe ser numérico")
    exact_filter = f'vulnerability.cve.id="{normalized_cve}"'
    directory = _evidence_directory(root, normalized_cve)
    flags = "\n".join([
        f"--organization: '{organization}'",
        "--source: '-'",
        f"--location: '{scc['location']}'",
        f"--billing-project: '{scc['billing_project']}'",
        f"--filter: '{exact_filter}'",
        "--order-by: 'event_time desc'",
        "--page-size: 1000",
        "--format: 'json'",
        "--quiet: true",
        "",
    ])
    flag_path = directory / "scc-query.yaml"
    raw_path = directory / "scc-findings.json"
    error_path = directory / "scc-findings.err.txt"
    flag_path.write_text(flags, encoding="utf-8")
    started_at = datetime.now(GUATEMALA_TZ)
    started = time.time()
    status = {
        "startedAt": started_at.isoformat(),
        "completedAt": None,
        "organization": organization,
        "billingProject": scc["billing_project"],
        "location": scc["location"],
        "cves": [normalized_cve],
        "filter": exact_filter,
        "transport": "scc-rest-v2",
        "exitCode": None,
        "validResult": False,
        "findingCount": None,
        "parseError": None,
    }
    try:
        payload, transport = _list_scc_findings_rest(config, organization, scc, exact_filter, directory)
        raw_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        error_path.write_text("", encoding="utf-8")
        completed_at = datetime.now(GUATEMALA_TZ)
        status["completedAt"] = completed_at.isoformat()
        status.update(transport)
        status["exitCode"] = 0
        status["validResult"] = True
        status["findingCount"] = len(payload)
    except Exception as error:
        completed_at = datetime.now(GUATEMALA_TZ)
        status["completedAt"] = completed_at.isoformat()
        status["exitCode"] = 1
        status["parseError"] = str(error)
        error_path.write_text(str(error), encoding="utf-8")
        atomic(directory / "query-status.json", status)
        raise RuntimeError(f"Consulta SCC no válida. Evidencia: {directory}. {error}") from error
    # La consulta viva no usa Catalogo.csv ni asignaciones locales como fuente.
    findings = [normalize_result(item, []) for item in payload]
    mismatched = [item for item in findings if item["cve"].upper() != normalized_cve]
    if mismatched:
        status["validResult"] = False
        status["parseError"] = f"SCC devolvió {len(mismatched)} filas que no corresponden al CVE solicitado"
        atomic(directory / "query-status.json", status)
        atomic(directory / "findings-normalizados.json", findings)
        raise RuntimeError(f"La respuesta SCC no pasó la validación exacta. Evidencia: {directory}")
    counts, by_squad = summarize(findings)
    result = {
        "schema": "gcp-vulnerabilities-v1",
        "available": True,
        "source": "GCP Security Command Center",
        "collectedAt": completed_at.isoformat(),
        "rows": len(findings),
        "uniqueCves": len({item["cve"] for item in findings}),
        "counts": counts,
        "bySquad": by_squad,
        "byCategory": summarize_categories(findings),
        "findings": findings,
        "coverage": {
            "organization": organization,
            "location": scc["location"],
            "filter": exact_filter,
            "limitReached": False,
            "limitApplied": False,
            "paginationManagedByGcloud": False,
            "paginationManagedByClient": True,
            "transport": status["transport"],
            "pages": status.get("pages"),
            "totalSize": status.get("totalSize"),
            "scope": "Consulta exacta SCC; incluye ACTIVE, INACTIVE y MUTED de todas las fuentes accesibles.",
        },
        "query": {"cve": normalized_cve, "mode": "exact-live"},
        "seconds": round(time.time() - started, 2),
        "message": "Consulta exacta ejecutada en vivo contra SCC. No se usaron datos de Prisma.",
        "evidenceDirectory": str(directory.resolve()),
    }
    atomic(directory / "query-status.json", status)
    atomic(directory / "findings-normalizados.json", findings)
    atomic(directory / "resultado.json", result)
    _write_cve_report(directory, result)
    return result


def collect_vulnerabilities(root=ROOT):
    root = Path(root)
    config = read_json(root / "configuracion.json")
    scc = validate_scc_config(config)
    organization = str(config.get("organization_id", ""))
    if not organization.isdigit():
        raise ValueError("organization_id debe ser numérico")
    flags = "\n".join([
        f"--organization: '{organization}'",
        "--source: '-'",
        f"--location: '{scc['location']}'",
        f"--billing-project: '{scc['billing_project']}'",
        f"--filter: '{SCC_FILTER}'",
        "--order-by: 'event_time desc'",
        f"--limit: {scc['max_findings']}",
        "--page-size: 1000",
        "--format: 'json'",
        "--quiet: true",
        "",
    ])
    descriptor, flag_name = tempfile.mkstemp(prefix="scc-flags-", suffix=".yaml", dir=root)
    os.close(descriptor)
    flag_path = Path(flag_name)
    started = time.time()
    try:
        flag_path.write_text(flags, encoding="utf-8")
        payload = json.loads(run_gcloud(config, ["scc", "findings", "list", f"--flags-file={flag_path}"], timeout=1800))
    finally:
        flag_path.unlink(missing_ok=True)
    catalog = catalog_rows(root)
    findings = [normalize_result(item, catalog) for item in payload]
    findings = [item for item in findings if item["cve"] != "Sin CVE"]
    counts, by_squad = summarize(findings)
    by_category = summarize_categories(findings)
    finished = datetime.now(timezone.utc)
    limit_reached = len(payload) >= scc["max_findings"]
    status_path = root / "gcp_status.json"
    status = read_json(status_path) if status_path.exists() else {"schema": "latam-gcp-status-v1"}
    status["updatedAt"] = finished.isoformat()
    status["securityCommandCenter"] = {
        "status": "partial" if limit_reached else "ok",
        "message": f"{len(findings)} hallazgos con CVE recuperados desde SCC." + (" Se alcanzó el límite configurado." if limit_reached else ""),
        "billingProject": scc["billing_project"],
        "location": scc["location"],
        "filter": SCC_FILTER,
    }
    atomic(status_path, status)
    result = {
        "schema": "gcp-vulnerabilities-v1",
        "available": True,
        "source": "GCP Security Command Center",
        "collectedAt": finished.isoformat(),
        "rows": len(findings),
        "uniqueCves": len({item["cve"] for item in findings}),
        "counts": counts,
        "bySquad": by_squad,
        "byCategory": by_category,
        "findings": findings,
        "coverage": {
            "organization": organization,
            "location": scc["location"],
            "filter": SCC_FILTER,
            "maxFindings": scc["max_findings"],
            "limitReached": limit_reached,
            "scope": "Hallazgos SCC con CVE; incluye ACTIVE, INACTIVE y MUTED.",
        },
        "seconds": round(time.time() - started, 2),
        "message": "Datos obtenidos exclusivamente desde SCC. No se importaron vulnerabilidades del panel anterior.",
        "gcpStatus": status,
    }
    output = root / "gcp_vulnerabilities.json"
    if output.exists():
        atomic(root / "gcp_vulnerabilities.anterior.json", read_json(output))
    atomic(output, result)
    return result


if __name__ == "__main__":
    summary = collect_vulnerabilities()
    print(json.dumps({
        "rows": summary["rows"],
        "uniqueCves": summary["uniqueCves"],
        "counts": summary["counts"],
        "coverage": summary["coverage"],
        "seconds": summary["seconds"],
    }, ensure_ascii=False, indent=2))
