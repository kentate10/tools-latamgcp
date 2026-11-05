"""Reglas compartidas para interpretar versiones de imágenes sin inferir evidencia."""

import json
import re


def interpreted_version(tag):
    value = str(tag or "").strip()
    if re.fullmatch(r"\d{1,4}", value):
        return int(value)
    match = re.match(
        r"^(?:master|develop|dev|stg|intg|prod|qa|release|main|test|uat|feature|plygrd)-(\d{3})(?:-|$)",
        value,
        re.I,
    )
    return int(match.group(1)) if match else None


def base_versions(image):
    """Lee solo labels base_version explícitos; nunca usa números genéricos."""
    found = set()

    def visit(value, direct=False):
        if isinstance(value, dict):
            key = str(value.get("key", value.get("name", ""))).lower().replace("-", "_")
            if key == "base_version":
                visit(value.get("value"), True)
            for current_key, current_value in value.items():
                normalized = str(current_key).lower().replace("-", "_").replace(" ", "_")
                if normalized == "base_version":
                    visit(current_value, True)
        elif isinstance(value, list):
            for current in value:
                visit(current, direct)
        elif isinstance(value, (str, int)) and not isinstance(value, bool):
            raw = str(value).strip()
            if direct and re.fullmatch(r"\d{1,4}", raw):
                found.add(int(raw))
            elif not direct:
                try:
                    parsed = json.loads(raw)
                except (ValueError, TypeError):
                    parsed = None
                if isinstance(parsed, (dict, list)):
                    visit(parsed)
                else:
                    pattern = r'(?:^|[\s,;{])"?base[_ -]version"?\s*[:=]\s*"?(\d{1,4})(?=["\s,;}\]]|$)'
                    found.update(int(number) for number in re.findall(pattern, raw, re.I))

    for current_key, current_value in image.items():
        normalized = current_key.lower().replace("-", "_").replace(" ", "_")
        if normalized in ("base_version", "base_versions"):
            visit(current_value, True)
        elif normalized in ("labels", "custom_labels", "image_labels"):
            visit(current_value)
    return sorted(found)
