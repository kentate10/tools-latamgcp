"""Consultas BigQuery on-demand usando el token efímero de la sesión gcloud."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime
from pathlib import Path

from gcp_collect import run_gcloud


ROOT = Path(__file__).resolve().parent
SAFE_TABLE = re.compile(r"^[a-z][a-z0-9-]{3,62}\.[A-Za-z_][A-Za-z0-9_-]{0,1023}\.[A-Za-z_][A-Za-z0-9_-]{0,1023}$")
SAFE_FILTER = re.compile(r"^[\w .:/@,+()\-]{1,300}$", re.UNICODE)

FILTER_KEYS = {
    "resourceType": ["resource_type", "tiporecurso", "tipo_recurso", "asset_type"],
    "category": ["category", "categoria", "finding_category"],
    "workload": ["workload", "workload_name", "deployment", "pod"],
    "serviceDomain": ["service_domain", "service_dom", "servicedomain"],
    "squad": ["squad", "squad_team", "team"],
    "itElement": ["it_element", "itelement", "it_asset", "asset_id"],
    "project": ["project", "project_id", "projectid", "project_display_name"],
    "artifact": ["artifact", "artefacto", "package", "image_name"],
    "namespace": ["namespace", "kubernetes_namespace"],
    "environment": ["environment", "ambiente", "env"],
    "domain": ["domain", "dominio", "enterprise_domain"],
    "subdomain": ["subdomain", "subdominio"],
    "severity": ["severity", "severidad"],
    "state": ["state", "status", "estado"],
    "matchLevel": ["match_level", "matchlevel"],
    "priority": ["priority", "prioridad"],
    "observedInTheWild": ["observed_in_the_wild", "observedinthewild"],
    "isNew": ["is_new", "es_nuevo", "new_finding"],
    "tag": ["tag", "image_tag"],
    "pci": ["is_pci", "pci", "is_pci_compliance"],
    "exploitation": ["exploitation_activity", "exploitation", "actividad_explotacion"],
    "outsideSla": ["out_sla", "outside_sla", "fuera_sla"],
    "zeroDay": ["zero_day", "cve_zero_day", "zeroday"],
    "package": ["package", "package_name", "offending_package_name"],
    "installedVersion": ["installed_version", "offending_package_version", "package_version"],
    "fixedVersion": ["fixed_version", "fixed_package_version"],
    "attackVector": ["attack_vector", "vector_ataque"],
    "cve": ["cve", "cve_id", "vulnerability_id"],
    "journey": ["journey"],
    "imageVersion": ["image_version", "version_imagen"],
}


def _read_config(root):
    config = json.loads((Path(root) / "configuracion.json").read_text(encoding="utf-8-sig"))
    bq = config.get("bigquery") or {}
    for key in ("billing_project", "findings_table", "artifacts_table", "cmdb_table"):
        if not bq.get(key):
            raise ValueError(f"Falta bigquery.{key} en configuracion.json")
    if not re.fullmatch(r"[a-z][a-z0-9-]{3,62}", bq["billing_project"]):
        raise ValueError("bigquery.billing_project no es válido")
    for key in ("findings_table", "artifacts_table", "images_table", "cmdb_table", "gcp_project_table"):
        if bq.get(key) and not SAFE_TABLE.fullmatch(bq[key]):
            raise ValueError(f"bigquery.{key} no es una tabla válida")
    timeout = bq.get("request_timeout_seconds", 180)
    if type(timeout) is not int or not 30 <= timeout <= 1800:
        raise ValueError("bigquery.request_timeout_seconds debe estar entre 30 y 1800")
    limit = bq.get("max_result_rows", 5000)
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise ValueError("bigquery.max_result_rows debe estar entre 1 y 10000")
    return config, bq


def _token(config):
    value = run_gcloud(config, ["auth", "print-access-token"], timeout=60).strip()
    if not value or any(character.isspace() for character in value):
        raise RuntimeError("gcloud no pudo entregar un token efímero válido")
    return value


def _api(method, url, token, billing_project, payload=None, timeout=180):
    raw = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=raw, method=method, headers={
        "Authorization": "Bearer " + token,
        "X-Goog-User-Project": billing_project,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Tools-LatamGCP-live/2.0",
    })
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8")
            result = json.loads(body)
            if not isinstance(result, dict):
                raise RuntimeError("BigQuery devolvió una respuesta inesperada")
            return result
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[-2000:]
            if error.code == 401:
                raise RuntimeError("La sesión gcloud expiró. Ejecuta gcloud auth login y vuelve a intentar.") from error
            if error.code == 403:
                raise RuntimeError("BigQuery denegó la consulta. Revisa bigquery.jobs.create y acceso de lectura a la tabla.") from error
            if error.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise RuntimeError(f"BigQuery respondió HTTP {error.code}: {detail}") from error
        except (TimeoutError, urllib.error.URLError) as error:
            if attempt == 2:
                raise RuntimeError("BigQuery no respondió antes del timeout; no se interpretó como cero resultados.") from error
        time.sleep(2 ** attempt)
    raise RuntimeError("BigQuery no pudo completar la solicitud")


def _parameter(name, value, kind="STRING"):
    return {"name": name, "parameterType": {"type": kind}, "parameterValue": {"value": str(value)}}


def _decode_value(field, value):
    if value is None:
        return None
    raw = value.get("v") if isinstance(value, dict) else value
    mode = field.get("mode")
    children = field.get("fields") or []
    if mode == "REPEATED":
        return [_decode_value({**field, "mode": "NULLABLE"}, item) for item in (raw or [])]
    if children and isinstance(raw, dict):
        cells = raw.get("f") or []
        return {child.get("name"): _decode_value(child, cells[index] if index < len(cells) else None) for index, child in enumerate(children)}
    return raw


def _decode_rows(response):
    fields = ((response.get("schema") or {}).get("fields") or [])
    rows = []
    for row in response.get("rows") or []:
        cells = row.get("f") or []
        rows.append({field.get("name"): _decode_value(field, cells[index] if index < len(cells) else None) for index, field in enumerate(fields)})
    return rows


def run_query(sql, parameters=None, root=ROOT, maximum_bytes_billed=None):
    config, bq = _read_config(root)
    project = bq["billing_project"]
    token = _token(config)
    endpoint = f"https://bigquery.googleapis.com/bigquery/v2/projects/{project}/queries"
    payload = {
        "query": sql,
        "useLegacySql": False,
        "parameterMode": "NAMED",
        "queryParameters": parameters or [],
        "timeoutMs": min(bq["request_timeout_seconds"] * 1000, 200000),
        "formatOptions": {"useInt64Timestamp": False},
    }
    if maximum_bytes_billed:
        payload["maximumBytesBilled"] = str(maximum_bytes_billed)
    result = _api("POST", endpoint, token, project, payload, bq["request_timeout_seconds"])
    reference = result.get("jobReference") or {}
    while not result.get("jobComplete", True):
        job_id = reference.get("jobId")
        if not job_id:
            raise RuntimeError("BigQuery inició un job sin identificador")
        query = {"timeoutMs": "200000", "maxResults": "10000"}
        if reference.get("location"):
            query["location"] = reference["location"]
        url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{reference.get('projectId', project)}/queries/{urllib.parse.quote(job_id)}?{urllib.parse.urlencode(query)}"
        result = _api("GET", url, token, project, timeout=bq["request_timeout_seconds"])
    errors = result.get("errors") or []
    if errors:
        raise RuntimeError("BigQuery rechazó la consulta: " + " | ".join(str(item.get("message") or item) for item in errors)[:3000])
    return _decode_rows(result), result


def _validated_date(value, label):
    try:
        parsed = date.fromisoformat(str(value))
    except ValueError as error:
        raise ValueError(f"{label} debe usar formato YYYY-MM-DD") from error
    return parsed


def _json_filter_pattern(keys, value):
    if not SAFE_FILTER.fullmatch(str(value)):
        raise ValueError("Un filtro contiene caracteres no permitidos")
    names = "|".join(re.escape(key.lower()) for key in keys)
    escaped = re.escape(str(value).lower())
    return rf'"(?:{names})"\s*:\s*(?:"[^"\\]*{escaped}[^"\\]*"|{escaped})'


def query_dashboard(start_date, end_date, filters=None, root=ROOT):
    started = time.time()
    start = _validated_date(start_date, "Fecha inicial")
    end = _validated_date(end_date, "Fecha final")
    if end < start:
        raise ValueError("La fecha final no puede ser anterior a la inicial")
    if (end - start).days > 31:
        raise ValueError("El panel en vivo permite hasta 32 días por consulta")
    _, bq = _read_config(root)
    clauses = ["DATE(event_time) BETWEEN @start_date AND @end_date"]
    parameters = [_parameter("start_date", start, "DATE"), _parameter("end_date", end, "DATE")]
    applied = {}
    for index, (logical, value) in enumerate((filters or {}).items()):
        if value in (None, "", "all"):
            continue
        if logical not in FILTER_KEYS:
            raise ValueError(f"Filtro no soportado: {logical}")
        parameter_name = f"filter_{index}"
        clauses.append(f"REGEXP_CONTAINS(LOWER(TO_JSON_STRING(t)), @{parameter_name})")
        parameters.append(_parameter(parameter_name, _json_filter_pattern(FILTER_KEYS[logical], value)))
        applied[logical] = str(value)
    where = " AND ".join(clauses)
    table = bq["findings_table"]
    limit = bq["max_result_rows"]
    metrics_sql = f"""
SELECT
  COUNT(*) AS total,
  COUNTIF(REGEXP_CONTAINS(LOWER(TO_JSON_STRING(t)), r'\"(?:state|status|estado)\"\\s*:\\s*\"active\"')) AS active,
  COUNTIF(REGEXP_CONTAINS(LOWER(TO_JSON_STRING(t)), r'\"(?:state|status|estado)\"\\s*:\\s*\"inactive\"')) AS inactive,
  COUNTIF(REGEXP_CONTAINS(LOWER(TO_JSON_STRING(t)), r'\"(?:mute|muted)\"\\s*:\\s*\"muted\"')) AS muted,
  COUNTIF(REGEXP_CONTAINS(LOWER(TO_JSON_STRING(t)), r'\"(?:flapping|is_flapping)\"\\s*:\\s*(?:true|\"true\")')) AS flapping,
  COUNT(DISTINCT REGEXP_EXTRACT(UPPER(TO_JSON_STRING(t)), r'\"(CVE-[0-9]{{4}}-[0-9]{{4,}})\"')) AS unique_cves
FROM `{table}` AS t
WHERE {where}
"""
    detail_sql = f"SELECT TO_JSON_STRING(t) AS row_json FROM `{table}` AS t WHERE {where} ORDER BY event_time DESC LIMIT {limit}"
    metric_rows, metric_response = run_query(metrics_sql, parameters, root)
    detail_rows, detail_response = run_query(detail_sql, parameters, root)
    records = []
    for row in detail_rows:
        try:
            value = json.loads(row.get("row_json") or "{}")
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    metrics = metric_rows[0] if metric_rows else {"total": "0", "active": "0", "inactive": "0", "muted": "0", "flapping": "0", "unique_cves": "0"}
    total = int(metrics.get("total") or 0)
    return {
        "schema": "latam-gcp-live-dashboard-v1",
        "available": True,
        "source": table,
        "queriedAt": datetime.now().astimezone().isoformat(),
        "dateRange": {"start": str(start), "end": str(end)},
        "filters": applied,
        "metrics": {key: int(metrics.get(key) or 0) for key in ("total", "active", "inactive", "muted", "flapping", "unique_cves")},
        "healthIndex": None,
        "healthIndexMessage": "Pendiente de fórmula corporativa aprobada; no se calcula ni se inventa.",
        "rows": records,
        "returnedRows": len(records),
        "truncated": total > len(records),
        "maximumRows": limit,
        "bytesProcessed": str(detail_response.get("totalBytesProcessed") or metric_response.get("totalBytesProcessed") or ""),
        "seconds": round(time.time() - started, 2),
    }


def _normalize_key(value):
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


CMDB_COLUMNS = """it_element_identifier AS it_element, name, criticality, status, is_pci_compliance AS pci,
  is_sox_compliance AS sox, journey, enterprise_domain, domain, service_domain_name AS service_domain,
  subdomain_name AS subdomain, squad_team AS squad, platform, touchpoint, chapter_devsecops, load_datetime"""


def _json_rows(rows):
    records = []
    for row in rows:
        try:
            value = json.loads(row.get("row_json") or "{}")
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def query_cmdb(root=ROOT):
    _, bq = _read_config(root)
    table = bq["cmdb_table"]
    sql = f"SELECT TO_JSON_STRING(STRUCT({CMDB_COLUMNS})) AS row_json FROM `{table}` AS t LIMIT 10000"
    rows, response = run_query(sql, root=root)
    records = _json_rows(rows)
    return {
        "schema": "latam-cmdb-live-v1",
        "available": True,
        "source": table,
        "queriedAt": datetime.now().astimezone().isoformat(),
        "rows": records,
        "returnedRows": len(records),
        "truncated": len(records) >= 10000,
        "bytesProcessed": str(response.get("totalBytesProcessed") or ""),
    }


def query_project_squads(projects, root=ROOT):
    """Proyecto GCP -> IT Elements con squad/journey/dominio/criticidad/PCI, consultado en vivo en la CMDB."""
    names = sorted({str(item).strip() for item in projects if item and str(item).strip() != "No determinado"})
    if not names:
        return {}
    for name in names:
        if not re.fullmatch(r"[a-z][a-z0-9-]{3,62}", name):
            raise ValueError("Nombre de proyecto no válido para consultar la CMDB")
    _, bq = _read_config(root)
    sql = f"""SELECT TO_JSON_STRING(STRUCT(p.gcp_project_identifier AS project, p.gcp_project_environment AS environment,
  e.it_element_identifier AS it_element, e.name, e.criticality, e.is_pci_compliance AS pci, e.is_sox_compliance AS sox,
  e.journey, e.enterprise_domain, e.domain, e.service_domain_name AS service_domain, e.subdomain_name AS subdomain, e.squad_team AS squad)) AS row_json
FROM `{bq['gcp_project_table']}` AS p
JOIN `{bq['cmdb_table']}` AS e ON e.it_element_identifier = p.it_element
WHERE p.gcp_project_identifier IN UNNEST(@projects)"""
    parameter = {"name": "projects", "parameterType": {"type": "ARRAY", "arrayType": {"type": "STRING"}}, "parameterValue": {"arrayValues": [{"value": name} for name in names]}}
    rows, _ = run_query(sql, [parameter], root)
    mapping = {}
    for record in _json_rows(rows):
        mapping.setdefault(record.get("project"), []).append(record)
    return mapping


def query_artifacts(search="", squad="", root=ROOT):
    _, bq = _read_config(root)
    table = bq["artifacts_table"]
    clauses = []
    parameters = []
    for index, (label, value, keys) in enumerate((("search", search, ["artifact", "artefacto", "image", "package", "name"]), ("squad", squad, ["squad", "team", "squad_team"]))):
        value = str(value or "").strip()
        if not value:
            continue
        parameter_name = f"value_{index}"
        clauses.append(f"REGEXP_CONTAINS(LOWER(TO_JSON_STRING(t)), @{parameter_name})")
        parameters.append(_parameter(parameter_name, _json_filter_pattern(keys, value)))
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    limit = bq["max_result_rows"]
    sql = f"SELECT TO_JSON_STRING(t) AS row_json FROM `{table}` AS t{where} LIMIT {limit}"
    rows, response = run_query(sql, parameters, root)
    records = []
    for row in rows:
        try:
            value = json.loads(row.get("row_json") or "{}")
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return {
        "schema": "latam-artifacts-live-v1",
        "available": True,
        "source": table,
        "queriedAt": datetime.now().astimezone().isoformat(),
        "rows": records,
        "returnedRows": len(records),
        "truncated": len(records) >= limit,
        "bytesProcessed": str(response.get("totalBytesProcessed") or ""),
    }
