"""Exploración paginada y filtrada de un CVE en SCC: totales exactos, facetas y páginas de 100 en 100."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

from gcp_collect import ROOT, atomic, read_json, run_gcloud
from scc_collect import GUATEMALA_TZ, SAFE_CVE, classify_resource, normalize_result, validate_scc_config

STATES = {"ACTIVE", "INACTIVE"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNSPECIFIED"}
MUTES = {"MUTED", "UNMUTED", "UNDEFINED"}
SAFE_TYPE = re.compile(r"^[A-Za-z0-9_.]{3,120}$")
SAFE_PROJECT = re.compile(r"^[A-Za-z0-9_.\- ]{1,100}$")
PAGE_SIZES = (50, 100, 200, 500)
FACETS = {"state": "state", "severity": "severity", "resourceType": "resource.type", "project": "resource.project_display_name"}


def build_filter(cve, filters=None):
    cve = str(cve or "").strip().upper()
    if not SAFE_CVE.fullmatch(cve):
        raise ValueError("Usa un identificador CVE válido, por ejemplo CVE-2026-12345")
    filters = filters or {}
    parts = [f'vulnerability.cve.id="{cve}"']
    if filters.get("state"):
        if filters["state"] not in STATES:
            raise ValueError("Estado no válido")
        parts.append(f'state="{filters["state"]}"')
    if filters.get("severity"):
        if filters["severity"] not in SEVERITIES:
            raise ValueError("Severidad no válida")
        parts.append(f'severity="{filters["severity"]}"')
    if filters.get("mute"):
        if filters["mute"] not in MUTES:
            raise ValueError("Mute no válido")
        parts.append(f'mute="{filters["mute"]}"')
    if filters.get("resourceType"):
        if not SAFE_TYPE.fullmatch(str(filters["resourceType"])):
            raise ValueError("Tipo de recurso no válido")
        parts.append(f'resource.type="{filters["resourceType"]}"')
    if filters.get("project"):
        if not SAFE_PROJECT.fullmatch(str(filters["project"])):
            raise ValueError("Proyecto no válido")
        parts.append(f'resource.project_display_name="{filters["project"]}"')
    return " AND ".join(parts), cve


def _context(root):
    config = read_json(Path(root) / "configuracion.json")
    scc = validate_scc_config(config)
    organization = str(config.get("organization_id", ""))
    if not organization.isdigit():
        raise ValueError("organization_id debe ser numérico")
    token = run_gcloud(config, ["auth", "print-access-token"], timeout=60).strip()
    if not token or any(c.isspace() for c in token):
        raise RuntimeError("gcloud no pudo entregar un access token válido")
    base = f"https://securitycenter.googleapis.com/v2/organizations/{organization}/sources/-/locations/{scc['location']}/findings"
    return config, scc, organization, token, base


def _call(method, url, token, scc, body=None):
    raw = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=raw, method=method, headers={
        "Authorization": "Bearer " + token, "X-Goog-User-Project": scc["billing_project"],
        "Accept": "application/json", "Content-Type": "application/json", "User-Agent": "Tools-LatamGCP-local/1.0"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=min(scc.get("request_timeout_seconds", 1800), 300)) as response:
                value = json.loads(response.read().decode("utf-8"))
            if not isinstance(value, dict):
                raise RuntimeError("SCC devolvió una respuesta con formato inesperado")
            return value
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[-1500:]
            if error.code == 401:
                raise RuntimeError("La sesión gcloud expiró. Ejecuta gcloud auth login.") from error
            if error.code not in (429, 500, 502, 503, 504) or attempt == 3:
                raise RuntimeError(f"SCC respondió HTTP {error.code}: {detail}") from error
        except (TimeoutError, urllib.error.URLError) as error:
            if attempt == 3:
                raise RuntimeError(f"SCC no respondió: {error}. No se interpreta como cero hallazgos.") from error
        time.sleep(2 ** attempt)
    raise RuntimeError("SCC no pudo completar la solicitud")


def _log(root, cve, entry):
    directory = Path(root) / "evidence" / "consultas-paginadas"
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / f"{cve}-{datetime.now(GUATEMALA_TZ):%Y%m%d}.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"at": datetime.now(GUATEMALA_TZ).isoformat(), **entry}, ensure_ascii=False) + "\n")


def facets(cve, filters=None, root=ROOT):
    """Conteos exactos por faceta. Cada faceta se calcula sin su propio filtro, para poder cambiar de valor sin limpiar."""
    from concurrent.futures import ThreadPoolExecutor
    started = time.time()
    filters = {k: v for k, v in (filters or {}).items() if v}
    build_filter(cve, filters)
    _, scc, _, token, base = _context(root)
    cve = str(cve).strip().upper()

    def one(item):
        name, prop = item
        scoped = {k: v for k, v in filters.items() if k != name}
        scc_filter, _ = build_filter(cve, scoped)
        try:
            response = _call("POST", base + ":group", token, scc, {"groupBy": prop, "filter": scc_filter, "pageSize": 1000})
            groups = []
            for entry in response.get("groupByResults") or []:
                props = entry.get("properties") or {}
                value = next(iter(props.values()), "") if props else ""
                groups.append({"value": value if not isinstance(value, dict) else json.dumps(value), "count": int(entry.get("count") or 0)})
            groups.sort(key=lambda g: -g["count"])
            return name, {"groups": groups[:300], "distinct": len(groups), "complete": not response.get("nextPageToken")}, None
        except Exception as error:
            return name, None, str(error)[-400:]

    result, errors = {}, {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        for name, value, error in pool.map(one, FACETS.items()):
            if error:
                errors[name] = error
            else:
                result[name] = value
    total = sum(g["count"] for g in result["state"]["groups"]) if not filters and "state" in result else None
    out = {"cve": cve, "filters": filters, "total": total, "facets": result, "errors": errors, "seconds": round(time.time() - started, 2),
           "queriedAt": datetime.now(GUATEMALA_TZ).isoformat(), "source": "GCP Security Command Center (findings:group)"}
    _log(root, cve, {"kind": "facets", "filters": filters, "total": total, "errors": errors})
    return out


def page(cve, filters=None, page_token="", page_size=100, root=ROOT):
    started = time.time()
    scc_filter, cve = build_filter(cve, filters)
    if page_size not in PAGE_SIZES:
        raise ValueError("Tamaño de página no permitido")
    if page_token and not re.fullmatch(r"[A-Za-z0-9_\-+/=.]{1,2000}", page_token):
        raise ValueError("Token de página no válido")
    _, scc, _, token, base = _context(root)
    params = {"filter": scc_filter, "orderBy": "eventTime desc", "pageSize": str(page_size)}
    if page_token:
        params["pageToken"] = page_token
    response = _call("GET", base + "?" + urllib.parse.urlencode(params), token, scc)
    items = response.get("listFindingsResults") or []
    if not isinstance(items, list):
        raise RuntimeError("SCC devolvió una página con formato inesperado")
    findings = [normalize_result(item, []) for item in items]
    bad = [f for f in findings if f["cve"].upper() != cve]
    if bad:
        raise RuntimeError(f"SCC devolvió {len(bad)} filas que no corresponden a {cve}; página descartada")
    out = {"cve": cve, "filter": scc_filter, "findings": findings, "returned": len(findings), "pageSize": page_size,
           "totalSize": response.get("totalSize"), "nextPageToken": response.get("nextPageToken") or "",
           "seconds": round(time.time() - started, 2), "queriedAt": datetime.now(GUATEMALA_TZ).isoformat(),
           "source": "GCP Security Command Center"}
    _log(root, cve, {"kind": "page", "filter": scc_filter, "returned": len(findings), "totalSize": out["totalSize"], "hasNext": bool(out["nextPageToken"]), "seconds": out["seconds"]})
    return out


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def build_image_filter(digest, filters=None):
    digest = str(digest or "").strip().lower()
    if not DIGEST.fullmatch(digest):
        raise ValueError("Digest de imagen no válido (se esperaba sha256:...)")
    filters = filters or {}
    parts = [f'resource.name:"{digest}"', 'vulnerability.cve.id:"CVE-"']
    if filters.get("state"):
        if filters["state"] not in STATES:
            raise ValueError("Estado no válido")
        parts.append(f'state="{filters["state"]}"')
    if filters.get("severity"):
        if filters["severity"] not in SEVERITIES:
            raise ValueError("Severidad no válida")
        parts.append(f'severity="{filters["severity"]}"')
    return " AND ".join(parts), digest


def image_cves(digest, filters=None, page_token="", page_size=100, with_facets=False, root=ROOT):
    """CVE que contiene una imagen concreta (por digest), con totales exactos y paginación."""
    from concurrent.futures import ThreadPoolExecutor
    started = time.time()
    filters = {k: v for k, v in (filters or {}).items() if v}
    scc_filter, digest = build_image_filter(digest, filters)
    if page_size not in PAGE_SIZES:
        raise ValueError("Tamaño de página no permitido")
    if page_token and not re.fullmatch(r"[A-Za-z0-9_\-+/=.]{1,2000}", page_token):
        raise ValueError("Token de página no válido")
    _, scc, _, token, base = _context(root)
    params = {"filter": scc_filter, "orderBy": "severity desc", "pageSize": str(page_size)}
    if page_token:
        params["pageToken"] = page_token

    def facet(name):
        scoped, _ = build_image_filter(digest, {k: v for k, v in filters.items() if k != name})
        response = _call("POST", base + ":group", token, scc, {"groupBy": name, "filter": scoped, "pageSize": 50})
        groups = [{"value": next(iter((g.get("properties") or {}).values()), ""), "count": int(g.get("count") or 0)} for g in response.get("groupByResults") or []]
        return name, sorted(groups, key=lambda g: -g["count"])

    with ThreadPoolExecutor(max_workers=3) as pool:
        facet_jobs = [pool.submit(facet, name) for name in ("state", "severity")] if with_facets else []
        response = _call("GET", base + "?" + urllib.parse.urlencode(params), token, scc)
        facets = dict(job.result() for job in facet_jobs)
    items = response.get("listFindingsResults") or []
    findings = [normalize_result(item, []) for item in items]
    if any(digest not in (f.get("resource") or "").lower() for f in findings):
        raise RuntimeError("SCC devolvió hallazgos de otra imagen; página descartada")
    out = {"digest": digest, "filter": scc_filter, "findings": findings, "returned": len(findings), "pageSize": page_size,
           "totalSize": response.get("totalSize"), "nextPageToken": response.get("nextPageToken") or "", "facets": facets,
           "seconds": round(time.time() - started, 2), "queriedAt": datetime.now(GUATEMALA_TZ).isoformat(), "source": "GCP Security Command Center"}
    _log(root, digest[7:19], {"kind": "image-cves", "filter": scc_filter, "returned": len(findings), "totalSize": out["totalSize"]})
    return out
