#!/usr/bin/env python3
"""Sanitize n8n workflow exports before committing them.

Strips pinned execution data (pinData), the instance id, literal auth header
values, Splunk HEC tokens, ServiceNow instance names and password hashes.

Usage:
    python3 scripts/sanitize_n8n_export.py path/to/workflow.json [...]
    python3 scripts/sanitize_n8n_export.py --check path/...   # exit 1 if dirty
"""
import json
import re
import sys

SECRET_HEADER_NAMES = {"authorization", "x-apikey", "x-api-key", "apikey", "api-key", "x-splunk-request-channel"}

TEXT_RULES = [
    # "Authorization: Splunk <uuid>" anywhere (sticky notes, curl examples)
    (re.compile(r"Splunk [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "Splunk <HEC_TOKEN>"),
    # header objects: {"name": "Authorization", "value": "..."}
    (re.compile(r'("name"\s*:\s*"(?:Authorization|X-Api-?Key|apikey|api-key)"\s*,\s*"value"\s*:\s*")[^"]*(")', re.I),
     r"\1<SET_VIA_N8N_CREDENTIAL>\2"),
    (re.compile(r"\bdev\d+\.service-now\.com"), "<your-instance>.service-now.com"),
    (re.compile(r'("user_password"\s*:\s*")[^"]*(")'), r"\1<REDACTED>\2"),
]


def sanitize_text(text: str) -> str:
    for pattern, repl in TEXT_RULES:
        text = pattern.sub(repl, text)
    return text


def sanitize_workflow(data: dict) -> dict:
    if "pinData" in data:
        data["pinData"] = {}
    meta = data.get("meta")
    if isinstance(meta, dict):
        meta.pop("instanceId", None)
    for node in data.get("nodes", []):
        params = node.get("parameters", {})
        for key in ("headerParameters", "queryParameters"):
            block = params.get(key)
            if isinstance(block, dict):
                for item in block.get("parameters", []):
                    if str(item.get("name", "")).lower() in SECRET_HEADER_NAMES and item.get("value"):
                        item["value"] = "<SET_VIA_N8N_CREDENTIAL>"
    return data


def sanitize_bytes(raw: bytes) -> bytes:
    """Sanitize any blob; JSON workflows get structural cleaning first."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw  # binary (screenshots etc.)
    try:
        data = json.loads(text)
        if isinstance(data, dict) and "nodes" in data:
            text = json.dumps(sanitize_workflow(data), indent=2, ensure_ascii=False) + "\n"
    except ValueError:
        pass
    return sanitize_text(text).encode("utf-8")


def main(argv):
    check = "--check" in argv
    paths = [a for a in argv if a != "--check"]
    dirty = False
    for path in paths:
        raw = open(path, "rb").read()
        clean = sanitize_bytes(raw)
        if clean != raw:
            dirty = True
            if check:
                print(f"NEEDS SANITIZING: {path}")
            else:
                open(path, "wb").write(clean)
                print(f"sanitized: {path}")
    return 1 if (check and dirty) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
