"""Pestaña Squad Beta: por squad, artefactos con proyecto, namespace, despliegue y última imagen, todo en vivo desde GCP.

La lista semilla (semilla/squads_artefactos.csv) solo aporta nombres (artefacto -> squad). Dónde corre cada uno
(Cloud Asset Inventory), el último tag (Artifact Registry) y los squads de CMDB (BigQuery) se consultan en vivo.
"""

from __future__ import annotations

import csv
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from artifact_lookup import POD_NAME, REPO_ENV, TAG_FORMAT, _environment, _images_in
from bigquery_live import query_project_squads
from gcp_collect import ROOT
from scc_browse import _call, _context
from scc_collect import GUATEMALA_TZ

KEY = re.compile(r"^[a-z0-9][a-z0-9._\-/]{1,159}$")
PROJECT = re.compile(r"^[a-z][a-z0-9-]{3,62}$")
GENERIC = {"api", "web", "app", "bff", "front", "frontend", "backend"}
REGISTRY_TTL = 900
MAX_PACKAGE_PAGES = 30
MAX_VERSION_PAGES = 10
MAX_POD_PAGES = 6
_registry_cache = {"at": 0.0, "data": None, "warnings": [], "lock": threading.Lock()}


def _norm(value):
    return str(value or "").strip().lower().replace("_", "-")


def _matches(query, path_norm):
    """query ya normalizado; path_norm es la ruta de imagen/paquete normalizada."""
    if "/" in query:
        return path_norm == query or path_norm.endswith("/" + query)
    return path_norm.rsplit("/", 1)[-1] == query


def seed_rows(root=ROOT):
    root = Path(root)
    for path in (root / "semilla" / "squads_artefactos.csv", root / "Catalogo.csv"):
        if not path.exists():
            continue
        with path.open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        out = []
        for row in rows:
            artifact = (row.get("Artefacto") or "").strip()
            query = (row.get("Buscar como") or artifact).strip()
            if artifact and query:
                out.append({"artifact": artifact, "squad": (row.get("Squad") or "").strip() or "Por validar",
                            "itElement": (row.get("IT element") or "").strip(), "query": query})
        return out, path.name
    return [], ""


def squads(root=ROOT):
    rows, source = seed_rows(root)
    grouped = {}
    for row in rows:
        item = grouped.setdefault(row["squad"], {"squad": row["squad"], "artifacts": 0, "itElements": set()})
        item["artifacts"] += 1
        if row["itElement"] and row["itElement"] != "Por validar":
            item["itElements"].add(row["itElement"])
    items = [{**v, "itElements": sorted(v["itElements"])} for v in grouped.values()]
    items.sort(key=lambda v: (v["squad"] == "Por validar", -v["artifacts"], v["squad"]))
    return {"squads": items, "totalArtifacts": len(rows), "seed": source}


def _list_packages(token, scc, project, location, repository):
    url = f"https://artifactregistry.googleapis.com/v1/projects/{project}/locations/{location}/repositories/{repository}/packages"
    names, page_token = [], ""
    for _ in range(MAX_PACKAGE_PAGES):
        params = {"pageSize": "1000"}
        if page_token:
            params["pageToken"] = page_token
        page = _call("GET", url + "?" + urllib.parse.urlencode(params), token, scc)
        names.extend(urllib.parse.unquote(p["name"].rsplit("/packages/", 1)[1]) for p in page.get("packages") or [])
        page_token = page.get("nextPageToken") or ""
        if not page_token:
            return names, False
    return names, True


def _package_index(token, scc, config):
    """Nombres de paquetes (no imágenes) por repositorio, en memoria. Los repos tienen decenas de miles de imágenes pero solo unos miles de paquetes."""
    with _registry_cache["lock"]:
        if _registry_cache["data"] is not None and time.time() - _registry_cache["at"] < REGISTRY_TTL:
            return _registry_cache["data"], list(_registry_cache["warnings"])
        project = config.get("artifact_project", "")
        targets = [(item.get("location", "us") or "us", item.get("name")) for item in config.get("repositories") or [] if item.get("name")]
        warnings, index = [], {}

        def fetch(target):
            try:
                return target, _list_packages(token, scc, project, target[0], target[1]), None
            except Exception as error:
                return target, None, str(error)[-300:]

        with ThreadPoolExecutor(max_workers=6) as pool:
            for (location, repository), result, error in pool.map(fetch, targets):
                if error:
                    warnings.append(f"Artifact Registry {repository}: {error}")
                    continue
                names, truncated = result
                if truncated:
                    warnings.append(f"Artifact Registry {repository}: lista de paquetes truncada a {MAX_PACKAGE_PAGES * 1000}")
                for name in names:
                    index.setdefault(_norm(name).rsplit("/", 1)[-1], []).append({"location": location, "repo": repository, "package": name})
        if warnings and not index:
            raise RuntimeError("No se pudo leer ningún repositorio de Artifact Registry: " + "; ".join(warnings))
        _registry_cache.update({"at": time.time(), "data": index, "warnings": warnings})
        return index, list(warnings)


def _latest_entry(token, scc, project, candidate):
    """Versión más reciente con tag de un paquete (Artifact Registry ordena por createTime desc)."""
    package = urllib.parse.quote(candidate["package"], safe="")
    url = (f"https://artifactregistry.googleapis.com/v1/projects/{project}/locations/{candidate['location']}/repositories/{candidate['repo']}"
           f"/packages/{package}/versions")
    page = _call("GET", url + "?" + urllib.parse.urlencode({"pageSize": "20", "orderBy": "createTime desc", "view": "FULL"}), token, scc)
    fallback = None
    for version in page.get("versions") or []:
        tags = [(t.get("name") or "").rsplit("/", 1)[-1] for t in version.get("relatedTags") or []]
        parsed = [(int(m["version"]), t) for t in tags if (m := TAG_FORMAT.match(t))]
        entry = None
        if parsed:
            number, tag = max(parsed)
            entry = {"tag": tag, "version": number}
        elif tags and fallback is None:
            fallback = {"tag": sorted(tags)[0], "version": None, "_raw": version}
        if entry:
            return {**candidate, **entry, "digest": (version.get("name") or "").rsplit("/", 1)[-1], "created": version.get("createTime") or ""}
    if fallback:
        raw = fallback.pop("_raw")
        return {**candidate, **fallback, "digest": (raw.get("name") or "").rsplit("/", 1)[-1], "created": raw.get("createTime") or ""}
    return None


def _pods_for(token, scc, organization, text):
    base = f"https://cloudasset.googleapis.com/v1/organizations/{organization}:searchAllResources"
    pods, page_token = [], ""
    for _ in range(MAX_POD_PAGES):
        params = {"query": text, "assetTypes": "k8s.io/Pod", "pageSize": "500", "readMask": "name,labels,createTime,versionedResources"}
        if page_token:
            params["pageToken"] = page_token
        page = _call("GET", base + "?" + urllib.parse.urlencode(params), token, scc)
        pods.extend(page.get("results") or [])
        page_token = page.get("nextPageToken") or ""
        if not page_token:
            return pods, False
    return pods, True


def _latest(entries):
    return max(entries, key=lambda e: e["created"]) if entries else None


def collect(squad, root=ROOT):
    started = time.time()
    seeds, source = seed_rows(root)
    if not seeds:
        raise ValueError("No hay lista semilla (semilla/squads_artefactos.csv). Es solo una lista de nombres artefacto -> squad.")
    squad = str(squad or "").strip()
    selected = seeds if squad in ("", "*") else [row for row in seeds if row["squad"] == squad]
    if not selected:
        raise ValueError("Ese squad no existe en la lista semilla")
    warnings = []
    keys, skipped = {}, {}
    for row in selected:
        key = _norm(row["query"])
        if not KEY.fullmatch(key):
            skipped[key] = "nombre de búsqueda no válido"
        elif key.endswith("-") or key in GENERIC:
            skipped[key] = "nombre genérico o prefijo: no se busca para evitar falsos positivos"
        else:
            keys.setdefault(key, []).append(row)
    config, scc, organization, token, _ = _context(root)
    package_index, extra = _package_index(token, scc, config)
    warnings += extra
    artifact_project = config.get("artifact_project", "")
    candidates = {}
    for key in keys:
        candidates[key] = [c for c in package_index.get(key.rsplit("/", 1)[-1], []) if _matches(key, _norm(c["package"]))]
    unique = {(c["repo"], c["package"]): c for found_ in candidates.values() for c in found_}

    def latest(candidate):
        try:
            return (candidate["repo"], candidate["package"]), _latest_entry(token, scc, artifact_project, candidate), None
        except Exception as error:
            return (candidate["repo"], candidate["package"]), None, str(error)[-200:]

    latest_by_package = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for ident, entry, error in pool.map(latest, unique.values()):
            if error:
                warnings.append(f"Artifact Registry {ident[0]}/{ident[1]}: {error}")
            elif entry:
                latest_by_package[ident] = entry
    registry = {key: [latest_by_package[(c["repo"], c["package"])] for c in found_ if (c["repo"], c["package"]) in latest_by_package] for key, found_ in candidates.items()}

    def fetch(key):
        try:
            return key, _pods_for(token, scc, organization, key.rsplit("/", 1)[-1]), None
        except Exception as error:
            return key, None, str(error)[-300:]

    deployments, failed = {}, []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for key, result, error in pool.map(fetch, sorted(keys)):
            if error:
                failed.append(key)
                warnings.append(f"Cloud Asset {key}: {error}")
                continue
            assets, truncated = result
            if truncated:
                warnings.append(f"{key}: más de {MAX_POD_PAGES * 500} pods coincidentes, resultado acotado")
            for asset in assets:
                match = POD_NAME.search(asset.get("name", ""))
                if not match:
                    continue
                project, zone, cluster, namespace, pod = match.groups()
                for path, refs in _images_in(asset.get("versionedResources")).items():
                    if not _matches(key, _norm(path)):
                        continue
                    tag = sorted(refs["tags"])[0] if refs["tags"] else ""
                    digest = sorted(refs["digests"])[0] if refs["digests"] else ""
                    parts = path.split("/")
                    repo = parts[2] if parts[0].endswith("pkg.dev") and len(parts) > 3 else ""
                    row = deployments.setdefault(key, {}).setdefault((project, cluster, namespace, path, tag, digest), {
                        "project": project, "location": zone, "cluster": cluster, "namespace": namespace, "image": path, "repo": repo,
                        "deployedTag": tag, "deployedDigest": digest, "pods": 0, "lastCreated": ""})
                    row["pods"] += 1
                    row["lastCreated"] = max(row["lastCreated"], asset.get("createTime") or "")

    projects = sorted({d["project"] for per_key in deployments.values() for d in per_key.values() if PROJECT.fullmatch(d["project"])})
    cmdb = {}
    if projects:
        try:
            cmdb = query_project_squads(projects, root)
        except Exception as error:
            warnings.append(f"CMDB no disponible (los squads de CMDB quedan vacíos): {str(error)[-250:]}")

    rows, artifacts = [], []
    for seed in selected:
        key = _norm(seed["query"])
        base = {"squad": seed["squad"], "itElement": seed["itElement"], "artifact": seed["artifact"], "query": key}
        entries = registry.get(key, [])
        has_packages = bool(candidates.get(key))
        latest_any = _latest(entries)
        latest_fields = {"latestAnyTag": latest_any["tag"] if latest_any else "", "latestAnyRepo": latest_any["repo"] if latest_any else "",
                         "latestAnyCreated": latest_any["created"] if latest_any else ""}
        found = list(deployments.get(key, {}).values())
        if key in skipped:
            status = "ambiguo"
        elif key in failed:
            status = "error de consulta"
        elif found:
            status = "desplegado"
        elif entries or has_packages:
            status = "sin despliegue"
        else:
            status = "no encontrado"
        artifact = {**base, **latest_fields, "status": status, "note": skipped.get(key, ""), "deployments": len(found),
                    "registryEnvironments": sorted({REPO_ENV.get(e["repo"].split("-", 1)[-1], e["repo"]) for e in entries})}
        artifacts.append(artifact)
        if not found:
            rows.append({**base, **latest_fields, "status": status, "environment": "", "project": "", "cluster": "", "namespace": "", "pods": 0,
                         "deployedTag": "", "deployedVersion": None, "latestRepoTag": "", "latestRepoCreated": "", "outdated": None,
                         "cmdbSquads": "", "digest": "", "note": skipped.get(key, "")})
            continue
        for item in sorted(found, key=lambda d: (d["project"], d["namespace"], d["cluster"])):
            same = [e for e in entries if e["repo"] == item["repo"]]
            latest_repo = _latest(same)
            parsed = TAG_FORMAT.match(item["deployedTag"]) if item["deployedTag"] else None
            outdated = None
            if latest_repo:
                outdated = not (item["deployedDigest"] == latest_repo["digest"] or (item["deployedTag"] and item["deployedTag"] == latest_repo["tag"]))
            cm = cmdb.get(item["project"], [])
            rows.append({**base, **latest_fields, "status": "desplegado", "environment": _environment(item["cluster"], item["namespace"], item["project"]) or next((c.get("environment") for c in cm if c.get("environment")), "") or REPO_ENV.get(item["repo"].split("-", 1)[-1], ""),
                         "project": item["project"], "cluster": item["cluster"], "namespace": item["namespace"], "pods": item["pods"],
                         "deployedTag": item["deployedTag"], "deployedVersion": int(parsed["version"]) if parsed else None,
                         "latestRepoTag": latest_repo["tag"] if latest_repo else "", "latestRepoCreated": latest_repo["created"] if latest_repo else "",
                         "outdated": outdated, "cmdbSquads": ", ".join(sorted({c["squad"] for c in cm if c.get("squad")})),
                         "digest": item["deployedDigest"], "note": ""})
    summary = {"artifacts": len(artifacts), "desplegado": sum(a["status"] == "desplegado" for a in artifacts),
               "sinDespliegue": sum(a["status"] == "sin despliegue" for a in artifacts), "noEncontrado": sum(a["status"] == "no encontrado" for a in artifacts),
               "ambiguo": sum(a["status"] == "ambiguo" for a in artifacts), "errores": sum(a["status"] == "error de consulta" for a in artifacts),
               "rows": len(rows), "projects": len({r["project"] for r in rows if r["project"]}), "namespaces": len({(r["project"], r["namespace"]) for r in rows if r["namespace"]}),
               "outdated": sum(r["outdated"] is True for r in rows)}
    return {"schema": "latam-squad-beta-v1", "squad": squad or "*", "label": "Todos los squads" if squad in ("", "*") else squad, "seed": source,
            "summary": summary, "rows": rows, "artifacts": artifacts, "warnings": warnings[:50],
            "source": "Cloud Asset Inventory (pods) + Artifact Registry (dockerImages) + CMDB techgov; la semilla solo aporta nombres",
            "queriedAt": datetime.now(GUATEMALA_TZ).isoformat(), "seconds": round(time.time() - started, 2)}


def versions(query, root=ROOT):
    """Todas las versiones con tag de un artefacto en todos los repositorios (master-220-<sha>, develop-223-<sha>, ...), en vivo."""
    started = time.time()
    key = _norm(query)
    if not KEY.fullmatch(key):
        raise ValueError("Nombre de artefacto no válido")
    config, scc, _, token, _ = _context(root)
    package_index, warnings = _package_index(token, scc, config)
    project = config.get("artifact_project", "")
    candidates = [c for c in package_index.get(key.rsplit("/", 1)[-1], []) if _matches(key, _norm(c["package"]))]

    def fetch(candidate):
        package = urllib.parse.quote(candidate["package"], safe="")
        url = (f"https://artifactregistry.googleapis.com/v1/projects/{project}/locations/{candidate['location']}/repositories/{candidate['repo']}"
               f"/packages/{package}/versions")
        out, page_token = [], ""
        for _ in range(MAX_VERSION_PAGES):
            params = {"pageSize": "1000", "orderBy": "createTime desc", "view": "FULL"}
            if page_token:
                params["pageToken"] = page_token
            page = _call("GET", url + "?" + urllib.parse.urlencode(params), token, scc)
            out.extend(page.get("versions") or [])
            page_token = page.get("nextPageToken") or ""
            if not page_token:
                return candidate, out, False, None
        return candidate, out, True, None

    rows, untagged, other_tags = [], 0, 0
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(fetch, c) for c in candidates]
        for future in futures:
            try:
                candidate, found, truncated, _ = future.result()
            except Exception as error:
                warnings.append(f"Artifact Registry: {str(error)[-250:]}")
                continue
            if truncated:
                warnings.append(f"{candidate['repo']}: más de {MAX_VERSION_PAGES * 1000} versiones, lista acotada")
            for version in found:
                tags = [(t.get("name") or "").rsplit("/", 1)[-1] for t in version.get("relatedTags") or []]
                if not tags:
                    untagged += 1
                for tag in tags:
                    parsed = TAG_FORMAT.match(tag)
                    if not parsed:
                        other_tags += 1
                        continue
                    rows.append({"repo": candidate["repo"], "environment": REPO_ENV.get(candidate["repo"].split("-", 1)[-1], candidate["repo"]),
                                 "package": candidate["package"], "tag": tag, "branch": parsed["branch"] if parsed else "",
                                 "version": int(parsed["version"]) if parsed else None, "commit": parsed["sha"] if parsed else "",
                                 "digest": (version.get("name") or "").rsplit("/", 1)[-1], "created": version.get("createTime") or ""})
    rows.sort(key=lambda r: r["created"], reverse=True)
    per_repo = {}
    for row in rows:
        if row["version"] is not None:
            item = per_repo.setdefault(row["repo"], {"repo": row["repo"], "tags": 0, "minVersion": row["version"], "maxVersion": row["version"]})
            item["tags"] += 1
            item["minVersion"], item["maxVersion"] = min(item["minVersion"], row["version"]), max(item["maxVersion"], row["version"])
    if not candidates:
        warnings.append("No existe un paquete con ese nombre en los repositorios configurados.")
    return {"schema": "latam-squad-beta-versions-v1", "query": key, "rows": rows, "perRepo": sorted(per_repo.values(), key=lambda r: r["repo"]),
            "untaggedVersions": untagged, "otherTags": other_tags, "warnings": warnings[:30], "source": "Artifact Registry (versions)",
            "queriedAt": datetime.now(GUATEMALA_TZ).isoformat(), "seconds": round(time.time() - started, 2)}
