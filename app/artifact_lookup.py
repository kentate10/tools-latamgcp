"""Búsqueda en vivo de una imagen: dónde corre (Cloud Asset Inventory), qué tags existen (Artifact Registry) y de quién es (CMDB)."""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from bigquery_live import query_project_squads
from gcp_collect import ROOT
from scc_browse import _call, _context
from scc_collect import GUATEMALA_TZ

SAFE_QUERY = re.compile(r"^[A-Za-z0-9_.\-]{3,120}$")
POD_NAME = re.compile(r"/projects/([^/]+)/(?:zones|locations)/([^/]+)/clusters/([^/]+)/k8s/namespaces/([^/]+)/pods/([^/]+)$")
IMAGE_REF = re.compile(r"((?:[a-z0-9-]+\.)?(?:pkg\.dev|gcr\.io)/[A-Za-z0-9_./-]+?)(?::([A-Za-z0-9_.-]{1,128})|@(sha256:[0-9a-f]{64}))(?![A-Za-z0-9_.-])")
TAG_FORMAT = re.compile(r"^(?P<branch>[A-Za-z]+)-(?P<version>\d+)-(?P<sha>[0-9a-f]{7,40})$")
ENV_WORDS = (("prod", "prod"), ("intg", "intg"), ("cert", "cert"), ("stg", "stg"), ("dev", "dev"))
MAX_PODS = 3000
REPO_ENV = {"develop": "dev", "master": "master (intg/prod)", "intg": "intg", "cert": "cert", "feature": "feature", "stg": "stg"}


def _environment(*names):
    for name in names:
        for word, label in ENV_WORDS:
            if re.search(rf"(?:^|[-_]){word}(?:$|[-_])", str(name or "").lower()):
                return label
    return ""


def _images_in(value):
    """Referencias de imagen (tag y digest) dentro del spec/estado de un pod."""
    found = {}
    for path, tag, digest in IMAGE_REF.findall(json.dumps(value)):
        entry = found.setdefault(path, {"tags": set(), "digests": set()})
        if tag:
            entry["tags"].add(tag)
        if digest:
            entry["digests"].add(digest)
    return found


def _cloud_asset_pods(token, scc, organization, normalized):
    base = f"https://cloudasset.googleapis.com/v1/organizations/{organization}:searchAllResources"
    pods, token_page, warnings = [], "", []
    while len(pods) < MAX_PODS:
        params = {"query": normalized, "assetTypes": "k8s.io/Pod", "pageSize": "500", "readMask": "*"}
        if token_page:
            params["pageToken"] = token_page
        page = _call("GET", base + "?" + urllib.parse.urlencode(params), token, scc)
        pods.extend(page.get("results") or [])
        token_page = page.get("nextPageToken") or ""
        if not token_page:
            break
    else:
        warnings.append(f"Resultado acotado a {MAX_PODS} pods; escribe un nombre más específico.")
    return pods, warnings


def _registry_versions(token, scc, location, project, repository, package):
    package_path = urllib.parse.quote(package, safe="")
    url = (f"https://artifactregistry.googleapis.com/v1/projects/{project}/locations/{location}/repositories/{repository}"
           f"/packages/{package_path}/versions")
    out, page_token = [], ""
    for _ in range(10):
        params = {"pageSize": "1000", "view": "FULL"}
        if page_token:
            params["pageToken"] = page_token
        try:
            page = _call("GET", url + "?" + urllib.parse.urlencode(params), token, scc)
        except RuntimeError as error:
            if "HTTP 404" in str(error):
                return None
            raise
        out.extend(page.get("versions") or [])
        page_token = page.get("nextPageToken") or ""
        if not page_token:
            break
    return out


def lookup(query, root=ROOT):
    started = time.time()
    query = str(query or "").strip()
    if not SAFE_QUERY.fullmatch(query):
        raise ValueError("Escribe el nombre de la imagen (3 a 120 caracteres: letras, números, guion o guion bajo)")
    normalized = query.lower().replace("_", "-")
    config, scc, organization, token, _ = _context(root)
    warnings = []
    pods, extra = _cloud_asset_pods(token, scc, organization, normalized)
    warnings += extra

    groups, registry_targets = {}, set()
    for asset in pods:
        match = POD_NAME.search(asset.get("name", ""))
        if not match:
            continue
        project, zone, cluster, namespace, pod = match.groups()
        labels = asset.get("labels") or {}
        for path, refs in _images_in(asset.get("versionedResources")).items():
            if normalized not in path.lower().replace("_", "-").rsplit("/", 1)[-1]:
                continue
            tag = sorted(refs["tags"])[0] if refs["tags"] else ""
            digest = sorted(refs["digests"])[0] if refs["digests"] else ""
            host, _, rest = path.partition("/")
            parts = rest.split("/")
            if host.endswith("pkg.dev") and len(parts) >= 3:
                registry_targets.add((host.split("-docker")[0] if "-docker" in host else host, parts[0], parts[1], "/".join(parts[2:])))
            key = (project, cluster, namespace, path, tag, digest)
            row = groups.setdefault(key, {"project": project, "location": zone, "cluster": cluster, "namespace": namespace, "image": path, "tag": tag,
                                           "digest": digest, "pods": 0, "podNames": [], "lastCreated": "", "gitCommits": set(), "buildIds": set(),
                                           "environment": _environment(cluster, namespace, project)})
            row["pods"] += 1
            if len(row["podNames"]) < 5:
                row["podNames"].append(pod)
            row["lastCreated"] = max(row["lastCreated"], asset.get("createTime") or "")
            if labels.get("git_commit"):
                row["gitCommits"].add(labels["git_commit"])
            if labels.get("build_id"):
                row["buildIds"].add(labels["build_id"])
    # Si no corre en ningún clúster, se intenta el nombre exacto en los repositorios configurados.
    if not registry_targets:
        for item in config.get("repositories") or []:
            registry_targets.add((item.get("location", "us"), config.get("artifact_project", ""), item.get("name"), query))
    registry_targets = {t for t in registry_targets if t[1] and t[2] and t[3]}
    # Mismo paquete en los demás repositorios configurados (master, develop, intg, ...)
    packages = {t[3] for t in registry_targets}
    for item in config.get("repositories") or []:
        for package in packages:
            registry_targets.add((item.get("location", "us"), config.get("artifact_project", ""), item.get("name"), package))

    def fetch(target):
        location, project, repository, package = target
        location = location or "us"
        try:
            return target, _registry_versions(token, scc, location, project, repository, package), None
        except Exception as error:
            return target, None, str(error)[-300:]

    registry, untagged = [], 0
    with ThreadPoolExecutor(max_workers=6) as pool:
        for target, versions, error in pool.map(fetch, sorted(registry_targets)):
            if error:
                warnings.append(f"Artifact Registry {target[2]}: {error}")
                continue
            for version in versions or []:
                digest = (version.get("name") or "").rsplit("/", 1)[-1]
                tags = [(t.get("name") or "").rsplit("/", 1)[-1] for t in version.get("relatedTags") or []]
                if not tags:
                    untagged += 1
                for tag in tags:
                    parsed = TAG_FORMAT.match(tag)
                    registry.append({"repository": f"{target[1]}/{target[2]}", "package": target[3], "tag": tag, "branch": parsed["branch"] if parsed else "",
                                     "version": int(parsed["version"]) if parsed else None, "commit": parsed["sha"] if parsed else "", "digest": digest,
                                     "created": version.get("createTime") or "", "environment": REPO_ENV.get(target[2].split("-", 1)[-1], target[2])})
    registry.sort(key=lambda r: r["created"], reverse=True)

    projects = {row["project"] for row in groups.values()}
    cmdb = {}
    try:
        cmdb = query_project_squads(projects, root)
    except Exception as error:
        warnings.append(f"CMDB no disponible: {str(error)[-250:]}")
    workloads = []
    for row in groups.values():
        parsed = TAG_FORMAT.match(row["tag"])
        items = cmdb.get(row["project"], [])
        row.update({"version": int(parsed["version"]) if parsed else None, "gitCommits": sorted(row["gitCommits"]), "buildIds": sorted(row["buildIds"]),
                    "cmdb": items, "squads": sorted({i["squad"] for i in items if i.get("squad")}),
                    "cmdbEnvironment": next((i.get("environment") for i in items if i.get("environment")), "")})
        row["environment"] = row["environment"] or row["cmdbEnvironment"]
        workloads.append(row)
    workloads.sort(key=lambda w: (w["environment"], w["cluster"], w["namespace"], -(w["version"] or 0)))
    summary = {"pods": sum(w["pods"] for w in workloads), "deployments": len(workloads), "clusters": len({w["cluster"] for w in workloads}),
               "namespaces": len({w["namespace"] for w in workloads}), "projects": len(projects), "registryTags": len(registry),
               "repositories": len({r["repository"] for r in registry})}
    if not workloads and not registry:
        warnings.append("No se encontró la imagen en pods desplegados ni como nombre exacto en Artifact Registry. Prueba con otra parte del nombre.")
    return {"schema": "latam-image-lookup-v1", "query": query, "normalized": normalized, "summary": summary, "workloads": workloads,
            "registry": registry[:1000], "registryTruncated": len(registry) > 1000, "untaggedDigests": untagged, "warnings": warnings,
            "source": "Cloud Asset Inventory (pods) + Artifact Registry + CMDB", "queriedAt": datetime.now(GUATEMALA_TZ).isoformat(),
            "seconds": round(time.time() - started, 2)}
