"""Recolector local read-only para Artifact Registry mediante la sesión de gcloud."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from image_rules import base_versions


ROOT = Path(__file__).resolve().parent
SAFE_ID = re.compile(r"^[a-z][a-z0-9-]{3,62}$")
SAFE_REPOSITORY = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")
SAFE_LOCATION = re.compile(r"^[a-z0-9-]{1,40}$")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def atomic(path: Path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def configured_gcloud(config):
    configured = Path(config.get("gcloud_path", ""))
    if configured.is_file():
        return str(configured)
    discovered = shutil.which("gcloud") or shutil.which("gcloud.cmd")
    if discovered:
        return discovered
    raise RuntimeError("Google Cloud CLI no está disponible. Revisa gcloud_path en configuracion.json.")


def run_gcloud_result(config, arguments, timeout=1800):
    executable = configured_gcloud(config)
    command = [executable, *arguments]
    use_shell = False
    shell_executable = None
    if os.name == "nt" and executable.lower().endswith((".cmd", ".bat")):
        command = subprocess.list2cmdline(command)
        use_shell = True
        shell_executable = os.environ.get("COMSPEC", "cmd.exe")
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        shell=use_shell,
        executable=shell_executable,
    )


def run_gcloud(config, arguments, timeout=1800):
    process = run_gcloud_result(config, arguments, timeout=timeout)
    if process.returncode:
        message = (process.stderr or process.stdout or "gcloud terminó con error").strip()
        raise RuntimeError(message[-4000:])
    return process.stdout


def active_gcloud_account(config):
    """Devuelve únicamente la cuenta activa; nunca solicita ni expone tokens."""
    value = run_gcloud(
        config,
        ["auth", "list", "--filter=status:ACTIVE", "--format=value(account)"],
        timeout=60,
    ).strip()
    accounts = [line.strip() for line in value.splitlines() if line.strip()]
    if len(accounts) != 1:
        raise RuntimeError("gcloud debe tener exactamente una cuenta activa")
    return accounts[0]


def validate_config(config):
    project = config.get("artifact_project", "")
    if not SAFE_ID.fullmatch(project):
        raise ValueError("artifact_project no es un project ID válido")
    organization = str(config.get("organization_id", ""))
    if not organization.isdigit():
        raise ValueError("organization_id debe ser numérico")
    repositories = config.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("Configura al menos un repositorio")
    for repository in repositories:
        if not SAFE_REPOSITORY.fullmatch(repository.get("name", "")):
            raise ValueError("Nombre de repositorio no válido")
        if not SAFE_LOCATION.fullmatch(repository.get("location", "")):
            raise ValueError("Location de repositorio no válida")
    limit = config.get("max_images_per_repository")
    if limit is not None and (type(limit) is not int or not 1 <= limit <= 100000):
        raise ValueError("max_images_per_repository debe ser null o un entero positivo")


def split_package(package):
    host, remainder = package.split("/", 1)
    return host, remainder


def digest_value(value):
    return str(value or "").rsplit("@", 1)[-1]


def previous_base_version_map(previous):
    exact = {}
    by_digest = {}
    for image in previous.get("images", []):
        bases = base_versions(image)
        if not bases:
            continue
        digest = digest_value(image.get("Digest") or image.get("Id"))
        exact[(image.get("Registry", ""), image.get("Repository", ""), image.get("Tag", ""), digest)] = bases
        by_digest[(image.get("Registry", ""), image.get("Repository", ""), digest)] = bases
    return exact, by_digest


def collect_repository(config, repository, exact_bases, digest_bases):
    project = config["artifact_project"]
    location = repository["location"]
    name = repository["name"]
    target = f"{location}-docker.pkg.dev/{project}/{name}"
    arguments = [
        "artifacts", "docker", "images", "list", target,
        "--include-tags", "--format=json", f"--project={project}",
    ]
    limit = config.get("max_images_per_repository")
    if limit is not None:
        arguments.append(f"--limit={limit}")
    payload = json.loads(run_gcloud(config, arguments))
    images = []
    for item in payload:
        package = item.get("package", "")
        version = item.get("version", "")
        if not package or not version or "/" not in package:
            continue
        registry, repository_path = split_package(package)
        tags = item.get("tags") or ([""] if not config.get("tagged_only", True) else [])
        for tag in tags:
            bases = exact_bases.get((registry, repository_path, tag, version))
            if bases is None:
                bases = digest_bases.get((registry, repository_path, version), [])
            metadata = item.get("metadata") or {}
            images.append({
                "Registry": registry,
                "Repository": repository_path,
                "Tag": tag,
                "Id": version,
                "Digest": f"{package}@{version}",
                "Namespaces": [],
                "Clusters": [],
                "Filas fuente": 1,
                "base_versions": bases,
                "createTime": item.get("createTime"),
                "updateTime": item.get("updateTime"),
                "buildTime": metadata.get("buildTime"),
                "mediaType": metadata.get("mediaType"),
                "source": "GCP Artifact Registry",
            })
    return target, images, bool(limit is not None and len(payload) >= limit)


def collect_inventory(root=ROOT):
    root = Path(root)
    config = read_json(root / "configuracion.json")
    validate_config(config)
    inventory_path = root / "inventario.json"
    previous = read_json(inventory_path) if inventory_path.exists() else {"images": []}
    exact_bases, digest_bases = previous_base_version_map(previous)
    started = time.time()
    collected = []
    repositories_status = []
    errors = []
    partial = False
    for repository in config["repositories"]:
        target = f"{repository['location']}-docker.pkg.dev/{config['artifact_project']}/{repository['name']}"
        print(f"Consultando {target}...", flush=True)
        try:
            target, images, truncated = collect_repository(config, repository, exact_bases, digest_bases)
            collected.extend(images)
            partial = partial or truncated
            status = "partial" if truncated else "ok"
            repositories_status.append({"repository": target, "status": status, "images": len(images), "limitReached": truncated})
            print(f"  {len(images)} tags recuperados ({status}).", flush=True)
        except Exception as error:
            message = str(error)
            errors.append({"repository": target, "error": message})
            repositories_status.append({"repository": target, "status": "error", "message": message})
            partial = True
            print(f"  Error: {message[-500:]}", flush=True)
    if not collected:
        raise RuntimeError("Ningún repositorio pudo entregar imágenes. " + (errors[0]["error"] if errors else ""))
    unique = {}
    for image in collected:
        key = tuple(image.get(field, "") for field in ("Registry", "Repository", "Tag", "Id", "Digest"))
        unique[key] = image
    collected = list(unique.values())
    current_keys = set(unique)
    historical = []
    for image in previous.get("images", []):
        key = tuple(image.get(field, "") for field in ("Registry", "Repository", "Tag", "Id", "Digest"))
        if key in current_keys:
            continue
        old = dict(image)
        if partial and config.get("preserve_unseen_on_partial", True):
            old["missing"] = False
            old["stale"] = True
            old["source"] = old.get("source") or "Inventario inicial conservado"
            old.setdefault("lastSeenSource", previous.get("source", "Inventario anterior"))
        else:
            old["missing"] = True
            old.setdefault("lastSeenSource", previous.get("source", "Inventario anterior"))
            old.setdefault("missingSinceSource", "GCP Artifact Registry")
        historical.append(old)
    if len(collected) + len(historical) > 100000:
        raise RuntimeError("El inventario combinado excede 100,000 imágenes; hay que ajustar el alcance.")
    finished = datetime.now(timezone.utc)
    result = {
        "schema": "latam-gcp-images-v1",
        "source": "GCP Artifact Registry",
        "source_modified": finished.timestamp(),
        "collected_at": finished.isoformat(),
        "rows": len(collected),
        "source_images": len(collected),
        "missing_images": sum(bool(image.get("missing")) for image in historical),
        "stale_images": sum(bool(image.get("stale")) for image in historical),
        "images": collected + historical,
        "seconds": round(time.time() - started, 2),
        "repositories": repositories_status,
    }
    if inventory_path.exists():
        shutil.copy2(inventory_path, root / "inventario.anterior.json")
    atomic(inventory_path, result)
    status = {
        "schema": "latam-gcp-status-v1",
        "updatedAt": finished.isoformat(),
        "organization": config["organization_id"],
        "quotaProject": config.get("quota_project"),
        "artifactProject": config["artifact_project"],
        "artifactRegistry": {"status": "partial" if partial else "ok", "repositories": repositories_status},
        "artifactAnalysis": {
            "status": "blocked",
            "message": "Falta containeranalysis.occurrences.list en pipeline-corporativo."
        },
        "securityCommandCenter": {
            "status": "available",
            "message": "La cuenta puede consultar SCC usando pipeline-corporativo como proyecto de cuota; falta cerrar el filtro/alcance de fuentes."
        },
        "errors": errors,
    }
    atomic(root / "gcp_status.json", status)
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-repository", help="Nombre de un repositorio configurado")
    parser.add_argument("--limit", type=int, default=20)
    arguments = parser.parse_args()
    if arguments.sample_repository:
        config = read_json(ROOT / "configuracion.json")
        repository = next((item for item in config["repositories"] if item["name"] == arguments.sample_repository), None)
        if repository is None:
            raise SystemExit("El repositorio no está configurado")
        config["max_images_per_repository"] = arguments.limit
        previous = read_json(ROOT / "inventario.json")
        exact, by_digest = previous_base_version_map(previous)
        target, images, truncated = collect_repository(config, repository, exact, by_digest)
        print(json.dumps({"repository": target, "images": len(images), "limitReached": truncated, "sample": images[:2]}, ensure_ascii=False, indent=2))
    else:
        summary = collect_inventory()
        print(json.dumps({
            "images": summary["source_images"],
            "missing": summary["missing_images"],
            "stale": summary["stale_images"],
            "repositories": summary["repositories"],
            "seconds": summary["seconds"],
        }, ensure_ascii=False, indent=2))
