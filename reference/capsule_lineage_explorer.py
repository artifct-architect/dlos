#!/usr/bin/env python3
"""
capsule_lineage_explorer.py

Static archive generator for capsule.v0 collections.

Outputs:
- index.html                  archive landing page
- lineage.html                graph / timeline explorer
- lineage.json                graph export
- data/index.json             archive metadata export
- artifacts/<capsule_id>.html individual artifact pages

Usage:
    python reference/capsule_lineage_explorer.py examples
    python reference/capsule_lineage_explorer.py examples --output-dir examples/archive
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print(
        "Missing dependency: cryptography. Install with: python -m pip install cryptography",
        file=sys.stderr,
    )
    sys.exit(1)


# ============================================================
# Core capsule helpers
# ============================================================

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"), validate=True)


def canonical_message(fields: Dict[str, Any]) -> bytes:
    return json.dumps(
        fields,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_capsule_id(
    payload_sha: str,
    created_at: str,
    author: str,
    parent_id: Optional[str],
) -> str:
    base = {
        "payload_sha256": payload_sha,
        "created_at": created_at,
        "author": author,
        "parent_id": parent_id or "",
        "schema": "capsule.v0",
    }
    return sha256_bytes(canonical_message(base))


def load_capsule(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_public_key_from_pem(pem_bytes: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Public key is not Ed25519.")
    return key


def verify_capsule(cap: Dict[str, Any]) -> Tuple[bool, str]:
    try:
        if cap.get("schema") != "capsule.v0":
            return False, "Unsupported schema"

        required = [
            "capsule_id",
            "created_at",
            "author",
            "payload_sha256",
            "payload_b64",
            "public_key_pem",
            "signature_b64",
            "signature_over",
        ]
        for k in required:
            if k not in cap:
                return False, f"Missing field: {k}"

        payload = b64d(cap["payload_b64"])
        recomputed_payload_sha = sha256_bytes(payload)
        if recomputed_payload_sha != cap["payload_sha256"]:
            return False, "Payload hash mismatch"

        parent_id = cap.get("parent_id") or None
        recomputed_capsule_id = compute_capsule_id(
            cap["payload_sha256"],
            cap["created_at"],
            cap["author"],
            parent_id,
        )
        if recomputed_capsule_id != cap["capsule_id"]:
            return False, "Capsule ID mismatch"

        sign_fields = cap["signature_over"]
        expected_sign_fields = {
            "schema": "capsule.v0",
            "capsule_id": cap["capsule_id"],
            "payload_sha256": cap["payload_sha256"],
            "created_at": cap["created_at"],
            "author": cap["author"],
            "parent_id": cap.get("parent_id") or "",
        }
        if sign_fields != expected_sign_fields:
            return False, "signature_over mismatch"

        pub = load_public_key_from_pem(cap["public_key_pem"].encode("utf-8"))
        sig = b64d(cap["signature_b64"])
        pub.verify(sig, canonical_message(sign_fields))
        return True, "VALID"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def key_fingerprint_from_pem(pem: str) -> str:
    der = serialization.load_pem_public_key(
        pem.encode("utf-8")
    ).public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


def detect_payload_type(payload_b64: str) -> str:
    try:
        payload = b64d(payload_b64)
    except Exception:
        return "unknown"

    sigs = [
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
    ]
    for prefix, kind in sigs:
        if payload.startswith(prefix):
            return kind

    if payload.startswith(b"RIFF") and b"WEBP" in payload[:16]:
        return "image/webp"

    try:
        payload.decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "application/octet-stream"


def payload_extension(payload_type: str) -> str:
    mapping = {
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "image/webp": ".webp",
        "text/plain": ".txt",
        "application/json": ".json",
        "application/octet-stream": ".bin",
        "unknown": ".bin",
    }
    return mapping.get(payload_type, ".bin")


def safe_text_preview(payload_b64: str, max_chars: int = 1800) -> Optional[str]:
    try:
        payload = b64d(payload_b64)
    except Exception:
        return None

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None

    if len(text) > max_chars:
        return text[:max_chars] + "\n\n...[truncated]..."
    return text


def safe_thumbnail_data_url(payload_b64: str, max_bytes: int = 500_000) -> Optional[str]:
    try:
        payload = b64d(payload_b64)
    except Exception:
        return None

    kind = detect_payload_type(payload_b64)
    if not kind.startswith("image/"):
        return None

    if len(payload) > max_bytes:
        return None

    return f"data:{kind};base64,{payload_b64}"


def safe_payload_data_url(payload_b64: str, payload_type: str, max_bytes: int = 2_000_000) -> Optional[str]:
    try:
        payload = b64d(payload_b64)
    except Exception:
        return None
    if len(payload) > max_bytes:
        return None
    return f"data:{payload_type};base64,{payload_b64}"


def find_capsules(root: Path) -> List[Path]:
    return sorted([p for p in root.rglob("*.cap") if p.is_file()])


def parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None


# ============================================================
# Graph and archive model
# ============================================================

def build_archive_model(root: Path, artifact_dir_name: str = "artifacts") -> Dict[str, Any]:
    paths = find_capsules(root)
    nodes: List[Dict[str, Any]] = []
    by_id: Dict[str, Dict[str, Any]] = {}

    for path in paths:
        try:
            cap = load_capsule(path)
            valid, verify_detail = verify_capsule(cap)
            cid = cap.get("capsule_id")
            if not cid:
                continue

            payload_b64 = cap.get("payload_b64", "")
            payload_type = detect_payload_type(payload_b64)
            preview = safe_text_preview(payload_b64)
            thumb = safe_thumbnail_data_url(payload_b64)
            payload_url = safe_payload_data_url(payload_b64, payload_type)
            created = cap.get("created_at")
            artifact_href = f"{artifact_dir_name}/{cid}.html"

            item = {
                "id": cid,
                "author": cap.get("author"),
                "created_at": created,
                "created_sort": created or "",
                "parent_id": cap.get("parent_id"),
                "path": str(path),
                "filename": path.name,
                "schema": cap.get("schema"),
                "payload_sha256": cap.get("payload_sha256"),
                "payload_type": payload_type,
                "payload_ext": payload_extension(payload_type),
                "valid": valid,
                "verify_detail": verify_detail,
                "key_fingerprint": key_fingerprint_from_pem(cap["public_key_pem"]),
                "preview": preview,
                "thumbnail": thumb,
                "payload_url": payload_url,
                "signature_over": cap.get("signature_over"),
                "artifact_href": artifact_href,
                "raw_capsule": cap,
            }
            nodes.append(item)
            by_id[cid] = item
        except Exception as e:
            nodes.append({
                "id": str(path),
                "author": None,
                "created_at": None,
                "created_sort": "",
                "parent_id": None,
                "path": str(path),
                "filename": path.name,
                "schema": None,
                "payload_sha256": None,
                "payload_type": "unknown",
                "payload_ext": ".bin",
                "valid": False,
                "verify_detail": f"Failed to load: {e}",
                "key_fingerprint": None,
                "preview": None,
                "thumbnail": None,
                "payload_url": None,
                "signature_over": None,
                "artifact_href": None,
                "raw_capsule": None,
                "error_node": True,
            })

    edges: List[Dict[str, str]] = []
    children_map: Dict[str, List[str]] = {n["id"]: [] for n in nodes}

    for node in nodes:
        pid = node.get("parent_id")
        cid = node["id"]
        if pid and pid in by_id:
            edges.append({"from": pid, "to": cid})
            children_map[pid].append(cid)

    for node in nodes:
        node["children"] = sorted(children_map.get(node["id"], []))
        node["child_count"] = len(node["children"])

    roots, orphans, invalid = [], [], []
    for node in nodes:
        pid = node.get("parent_id")
        if not node.get("valid"):
            invalid.append(node["id"])
        if not pid:
            roots.append(node["id"])
        elif pid not in by_id:
            orphans.append(node["id"])

    depth_cache: Dict[str, int] = {}

    def depth_of(node_id: str, seen: Optional[set] = None) -> int:
        if node_id in depth_cache:
            return depth_cache[node_id]
        if seen is None:
            seen = set()
        if node_id in seen:
            return 0
        seen.add(node_id)
        node = by_id.get(node_id)
        if not node:
            return 0
        pid = node.get("parent_id")
        if not pid or pid not in by_id:
            depth_cache[node_id] = 0
            return 0
        d = 1 + depth_of(pid, seen)
        depth_cache[node_id] = d
        return d

    for node in nodes:
        node["depth"] = depth_of(node["id"])

    authors = defaultdict(list)
    for node in nodes:
        authors[node.get("author") or "(unknown)"].append(node["id"])

    latest_nodes = sorted(
        nodes,
        key=lambda n: (n.get("created_sort") or "", n["id"]),
        reverse=True,
    )[:12]

    summary = {
        "capsule_count": len(nodes),
        "valid_count": sum(1 for n in nodes if n.get("valid")),
        "invalid_count": sum(1 for n in nodes if not n.get("valid")),
        "root_count": len(roots),
        "orphan_count": len(orphans),
        "author_count": len(authors),
        "edge_count": len(edges),
    }

    return {
        "root": str(root),
        "nodes": nodes,
        "edges": edges,
        "by_id": by_id,
        "roots": sorted(roots),
        "orphans": sorted(orphans),
        "invalid": sorted(invalid),
        "authors": {k: sorted(v) for k, v in authors.items()},
        "latest_nodes": latest_nodes,
        "summary": summary,
    }


# ============================================================
# Artifact page generation
# ============================================================

ARTIFACT_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Artifact Viewer</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {{
      --bg: #0c111c;
      --panel: #121a2b;
      --text: #e8edf7;
      --muted: #9cabc5;
      --border: #26344f;
      --ok: #3ec97a;
      --bad: #e56767;
      --link: #8ebcff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
      background: linear-gradient(180deg, var(--bg), #08101b 65%);
      color: var(--text);
    }}
    .page {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 28px 20px 40px;
    }}
    .nav {{
      display: flex;
      gap: 14px;
      flex-wrap: wrap;
      margin-bottom: 16px;
    }}
    .nav a {{
      color: var(--link);
      text-decoration: none;
      font-weight: 600;
    }}
    .actions {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 14px;
    }}
    .action {{
      display: inline-block;
      color: var(--link);
      text-decoration: none;
      font-weight: 600;
      border: 1px solid var(--border);
      padding: 10px 12px;
      border-radius: 12px;
      background: rgba(255,255,255,0.02);
    }}
    .panel {{
      background: rgba(255,255,255,0.025);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 18px;
      margin-top: 18px;
    }}
    .hero {{
      display: grid;
      grid-template-columns: 1.2fr 0.8fr;
      gap: 18px;
    }}
    h1 {{ margin: 0; font-size: 2rem; }}
    h2 {{ margin: 0 0 12px; font-size: 1rem; }}
    .eyebrow {{
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-size: 0.78rem;
      margin-bottom: 10px;
    }}
    .sub {{
      color: var(--muted);
      margin-top: 10px;
      line-height: 1.5;
    }}
    .status {{
      display: inline-block;
      margin-top: 16px;
      padding: 8px 12px;
      border-radius: 999px;
      font-weight: 700;
      font-size: 0.9rem;
    }}
    .status.ok {{
      background: rgba(62,201,122,0.14);
      color: #9ef0bf;
      border: 1px solid rgba(62,201,122,0.25);
    }}
    .status.bad {{
      background: rgba(229,103,103,0.14);
      color: #ffb3b3;
      border: 1px solid rgba(229,103,103,0.25);
    }}
    .kv {{
      display: grid;
      grid-template-columns: 130px 1fr;
      gap: 10px 12px;
      font-size: 0.95rem;
    }}
    .k {{ color: var(--muted); }}
    .v code {{ word-break: break-all; }}
    .grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
    }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      background: rgba(255,255,255,0.03);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
      overflow: auto;
      margin: 0;
      font-size: 0.88rem;
      line-height: 1.45;
    }}
    img.preview {{
      display: block;
      max-width: 100%;
      max-height: 420px;
      margin: 0 auto;
      border-radius: 14px;
      border: 1px solid var(--border);
    }}
    details {{ margin-top: 12px; }}
    summary {{
      cursor: pointer;
      color: var(--link);
      font-weight: 600;
    }}
    .muted {{ color: var(--muted); }}
    ul {{
      margin: 0.5rem 0 0;
      padding-left: 1.2rem;
    }}
    a {{
      color: var(--link);
    }}
    @media (max-width: 900px) {{
      .hero, .grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <div class="nav">
      <a href="../index.html">← Archive index</a>
      <a href="../lineage.html">Lineage explorer</a>
      {parent_nav}
    </div>

    <section class="panel hero">
      <div>
        <div class="eyebrow">Digital Artifact</div>
        <h1>{title}</h1>
        <div class="sub">A self-verifying capsule artifact with embedded identity, integrity, and lineage reference.</div>
        <div class="status {status_class}">{status_text}</div>
        <div class="actions">
          {payload_link}
          {capsule_link}
        </div>
      </div>
      <div>
        <div class="kv">
          <div class="k">Capsule ID</div><div class="v"><code>{capsule_id}</code></div>
          <div class="k">Author</div><div class="v">{author}</div>
          <div class="k">Created</div><div class="v">{created_at}</div>
          <div class="k">Parent</div><div class="v">{parent_display}</div>
          <div class="k">Depth</div><div class="v">{depth}</div>
          <div class="k">Children</div><div class="v">{child_count}</div>
          <div class="k">Schema</div><div class="v">{schema}</div>
          <div class="k">Payload Type</div><div class="v">{payload_type}</div>
          <div class="k">Payload Size</div><div class="v">{payload_size}</div>
          <div class="k">Key FP</div><div class="v"><code>{key_fp}</code></div>
        </div>
      </div>
    </section>

    <div class="grid">
      <section class="panel">
        <h2>Artifact Preview</h2>
        {preview_block}
      </section>

      <section class="panel">
        <h2>Verification</h2>
        <div class="kv" style="margin-bottom:14px;">
          <div class="k">Result</div><div class="v">{verify_detail}</div>
          <div class="k">Payload SHA256</div><div class="v"><code>{payload_sha}</code></div>
        </div>
        <details open>
          <summary>Signed Fields</summary>
          <pre>{signature_over}</pre>
        </details>
        <details>
          <summary>Raw Capsule JSON</summary>
          <pre>{raw_json}</pre>
        </details>
      </section>
    </div>

    <section class="panel">
      <h2>Related Capsules</h2>
      <div class="grid">
        <div>
          <div class="muted">Parent</div>
          {parent_section}
        </div>
        <div>
          <div class="muted">Children</div>
          {children_section}
        </div>
      </div>
    </section>
  </div>
</body>
</html>
"""


def render_artifact_page(
    node: Dict[str, Any],
    by_id: Dict[str, Dict[str, Any]],
    out_path: Path,
) -> None:
    cap = node["raw_capsule"]
    if not cap:
        return

    payload = b64d(cap["payload_b64"])
    payload_type = detect_payload_type(cap["payload_b64"])
    payload_size = f"{len(payload)} bytes"

    title = node.get("author") or Path(node["path"]).stem
    status_text = "VALID CAPSULE" if node.get("valid") else "INVALID CAPSULE"
    status_class = "ok" if node.get("valid") else "bad"

    if payload_type.startswith("image/"):
        data_url = f"data:{payload_type};base64,{cap['payload_b64']}"
        preview_block = f'<img class="preview" src="{data_url}" alt="Artifact preview">'
    else:
        preview = node.get("preview")
        if preview:
            preview_block = f"<pre>{html.escape(preview)}</pre>"
        else:
            preview_block = '<div class="muted">No native preview available for this payload type.</div>'

    parent_id = node.get("parent_id")
    parent_node = by_id.get(parent_id) if parent_id else None
    if parent_node:
        parent_display = f'<a href="{html.escape(parent_node["id"])}.html">{html.escape(parent_node["id"])}</a>'
        parent_nav = f'<a href="{html.escape(parent_node["id"])}.html">Parent artifact</a>'
        parent_section = (
            f'<p><a href="{html.escape(parent_node["id"])}.html">{html.escape(parent_node["id"])}</a><br>'
            f'<span class="muted">{html.escape(str(parent_node.get("author") or "(unknown)"))}</span></p>'
        )
    elif parent_id:
        parent_display = f"<code>{html.escape(parent_id)}</code>"
        parent_nav = ""
        parent_section = f"<p><code>{html.escape(parent_id)}</code> <span class='muted'>(not present in archive)</span></p>"
    else:
        parent_display = "(none)"
        parent_nav = ""
        parent_section = "<p class='muted'>None</p>"

    children_ids = node.get("children", [])
    if children_ids:
        items = []
        for cid in children_ids:
            child = by_id.get(cid)
            if child:
                items.append(
                    f'<li><a href="{html.escape(cid)}.html">{html.escape(cid)}</a> '
                    f'<span class="muted">— {html.escape(str(child.get("author") or "(unknown)"))}</span></li>'
                )
            else:
                items.append(f"<li><code>{html.escape(cid)}</code></li>")
        children_section = "<ul>" + "".join(items) + "</ul>"
    else:
        children_section = "<p class='muted'>None</p>"

    payload_filename = f"{node['id']}{node.get('payload_ext', '.bin')}"
    payload_link = (
        f'<a class="action" href="{html.escape(node["payload_url"])}" download="{html.escape(payload_filename)}">Download payload</a>'
        if node.get("payload_url")
        else '<span class="action" style="opacity:.55;cursor:default;">Payload too large to embed</span>'
    )

    capsule_json_data = "data:application/json;base64," + base64.b64encode(
        json.dumps(cap, indent=2, ensure_ascii=False).encode("utf-8")
    ).decode("ascii")
    capsule_link = (
        f'<a class="action" href="{capsule_json_data}" download="{html.escape(node["id"])}.cap.json">Download capsule JSON</a>'
    )

    page = ARTIFACT_TEMPLATE.format(
        title=html.escape(str(title)),
        status_text=html.escape(status_text),
        status_class=status_class,
        capsule_id=html.escape(str(node.get("id", ""))),
        author=html.escape(str(node.get("author", "(unknown)"))),
        created_at=html.escape(str(node.get("created_at", "(unknown)"))),
        parent_display=parent_display,
        depth=html.escape(str(node.get("depth", 0))),
        child_count=html.escape(str(node.get("child_count", 0))),
        schema=html.escape(str(node.get("schema", ""))),
        payload_type=html.escape(payload_type),
        payload_size=html.escape(payload_size),
        key_fp=html.escape(str(node.get("key_fingerprint", ""))),
        verify_detail=html.escape(str(node.get("verify_detail", ""))),
        payload_sha=html.escape(str(node.get("payload_sha256", ""))),
        signature_over=html.escape(json.dumps(cap.get("signature_over", {}), indent=2, ensure_ascii=False)),
        raw_json=html.escape(json.dumps(cap, indent=2, ensure_ascii=False)),
        preview_block=preview_block,
        parent_nav=parent_nav,
        parent_section=parent_section,
        children_section=children_section,
        payload_link=payload_link,
        capsule_link=capsule_link,
    )
    out_path.write_text(page, encoding="utf-8")


# ============================================================
# Index page
# ============================================================

INDEX_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Capsule Archive</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {{
      --bg: #0c111c;
      --panel: #121a2b;
      --text: #e8edf7;
      --muted: #9cabc5;
      --border: #26344f;
      --link: #8ebcff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
      background: linear-gradient(180deg, var(--bg), #08101b 65%);
      color: var(--text);
    }}
    .page {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 28px 20px 40px;
    }}
    .hero {{
      background: rgba(255,255,255,0.025);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 22px;
    }}
    h1 {{ margin: 0; font-size: 2rem; }}
    .sub {{
      margin-top: 10px;
      color: var(--muted);
      line-height: 1.5;
      max-width: 70ch;
    }}
    .nav {{
      margin-top: 16px;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
    }}
    .nav a {{
      color: var(--link);
      text-decoration: none;
      font-weight: 600;
    }}
    .grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-top: 20px;
    }}
    .panel {{
      background: rgba(255,255,255,0.025);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 18px;
    }}
    h2 {{
      margin: 0 0 12px;
      font-size: 1rem;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0,1fr));
      gap: 12px;
    }}
    .stat {{
      background: rgba(255,255,255,0.03);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px;
    }}
    .stat .n {{
      font-size: 1.5rem;
      font-weight: 800;
    }}
    .stat .l {{
      color: var(--muted);
      margin-top: 4px;
      font-size: 0.9rem;
    }}
    ul {{
      margin: 0;
      padding-left: 1.2rem;
    }}
    li {{
      margin: 0.45rem 0;
    }}
    a {{
      color: var(--link);
    }}
    .muted {{
      color: var(--muted);
    }}
    @media (max-width: 900px) {{
      .grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <section class="hero">
      <h1>Capsule Archive</h1>
      <div class="sub">
        A static archive of self-verifying capsule artifacts with lineage, provenance, linked artifact pages, and downloadable payloads.
      </div>
      <div class="nav">
        <a href="lineage.html">Open lineage explorer</a>
        <a href="lineage.json">Graph JSON</a>
        <a href="data/index.json">Archive metadata JSON</a>
      </div>
    </section>

    <div class="grid">
      <section class="panel">
        <h2>Archive Summary</h2>
        <div class="stats">
          <div class="stat"><div class="n">{capsule_count}</div><div class="l">Capsules</div></div>
          <div class="stat"><div class="n">{valid_count}</div><div class="l">Valid</div></div>
          <div class="stat"><div class="n">{invalid_count}</div><div class="l">Invalid</div></div>
          <div class="stat"><div class="n">{root_count}</div><div class="l">Roots</div></div>
          <div class="stat"><div class="n">{orphan_count}</div><div class="l">Orphans</div></div>
          <div class="stat"><div class="n">{author_count}</div><div class="l">Authors</div></div>
        </div>
      </section>

      <section class="panel">
        <h2>Latest Artifacts</h2>
        {latest_list}
      </section>

      <section class="panel">
        <h2>Root Artifacts</h2>
        {root_list}
      </section>

      <section class="panel">
        <h2>Invalid / Orphaned</h2>
        {problem_list}
      </section>
    </div>
  </div>
</body>
</html>
"""


def render_index_page(model: Dict[str, Any], out_path: Path) -> None:
    by_id = model["by_id"]
    summary = model["summary"]

    def make_list(items: List[str], empty: str) -> str:
        if not items:
            return f"<p class='muted'>{html.escape(empty)}</p>"
        parts = []
        for cid in items:
            node = by_id.get(cid)
            if not node:
                continue
            parts.append(
                f"<li><a href='artifacts/{html.escape(cid)}.html'>{html.escape(cid)}</a> "
                f"<span class='muted'>— {html.escape(str(node.get('author') or '(unknown)'))}</span></li>"
            )
        return "<ul>" + "".join(parts) + "</ul>" if parts else f"<p class='muted'>{html.escape(empty)}</p>"

    latest_ids = [n["id"] for n in model["latest_nodes"]]
    root_ids = model["roots"][:16]
    problem_ids = (model["invalid"] + model["orphans"])[:16]

    page = INDEX_TEMPLATE.format(
        capsule_count=summary["capsule_count"],
        valid_count=summary["valid_count"],
        invalid_count=summary["invalid_count"],
        root_count=summary["root_count"],
        orphan_count=summary["orphan_count"],
        author_count=summary["author_count"],
        latest_list=make_list(latest_ids, "No artifacts found."),
        root_list=make_list(root_ids, "No root artifacts."),
        problem_list=make_list(problem_ids, "No invalid or orphaned artifacts."),
    )
    out_path.write_text(page, encoding="utf-8")


# ============================================================
# Lineage explorer
# ============================================================

LINEAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Capsule Lineage Explorer</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {{
      --bg: #0b1020;
      --panel: #121931;
      --panel-2: #0f1528;
      --text: #e8ecf4;
      --muted: #a6b0c3;
      --edge: #42506e;
      --accent: #6ea8ff;
      --border: #26314d;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    .layout {{
      display: grid;
      grid-template-columns: 1fr 390px;
      height: 100vh;
    }}
    .canvas-wrap {{
      position: relative;
      overflow: hidden;
      background:
        radial-gradient(circle at center, rgba(255,255,255,0.03) 1px, transparent 1px);
      background-size: 24px 24px;
    }}
    svg {{
      width: 100%;
      height: 100%;
      display: block;
      cursor: grab;
      user-select: none;
    }}
    .sidebar {{
      border-left: 1px solid var(--border);
      background: linear-gradient(180deg, var(--panel), var(--panel-2));
      padding: 1rem;
      overflow: auto;
    }}
    h1 {{
      font-size: 1.1rem;
      margin: 0 0 0.4rem 0;
    }}
    .muted {{
      color: var(--muted);
      font-size: 0.92rem;
    }}
    .card {{
      background: rgba(255,255,255,0.02);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 0.85rem;
      margin-top: 0.9rem;
    }}
    .kv {{
      display: grid;
      grid-template-columns: 110px 1fr;
      gap: 0.45rem 0.6rem;
      font-size: 0.92rem;
      margin-top: 0.8rem;
    }}
    .kv .k {{ color: var(--muted); }}
    code, pre {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      background: rgba(255,255,255,0.03);
      border-radius: 10px;
      padding: 0.75rem;
      font-size: 0.84rem;
      overflow: auto;
    }}
    .pill {{
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 700;
      letter-spacing: 0.02em;
    }}
    .ok {{ background: rgba(54,194,117,0.18); color: #8ef0b8; }}
    .bad {{ background: rgba(224,93,93,0.18); color: #ffadad; }}
    .toolbar {{
      position: absolute;
      top: 12px;
      left: 12px;
      right: 12px;
      z-index: 10;
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }}
    button, input, select {{
      background: rgba(18,25,49,0.95);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.5rem 0.7rem;
    }}
    input {{
      min-width: 220px;
    }}
    button {{
      cursor: pointer;
    }}
    .node-label {{
      font-size: 12px;
      fill: #dfe7f7;
      pointer-events: none;
    }}
    .edge {{
      stroke: var(--edge);
      stroke-width: 1.6;
      opacity: 0.9;
    }}
    .node {{
      stroke: #0d1325;
      stroke-width: 2;
      cursor: pointer;
      transition: opacity 120ms ease;
    }}
    .node.selected {{ stroke: #fff; stroke-width: 3; }}
    .node.dimmed {{ opacity: 0.15; }}
    .edge.dimmed {{ opacity: 0.08; }}
    .thumb {{
      max-width: 100%;
      max-height: 220px;
      display: block;
      margin-top: 0.75rem;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.03);
    }}
    .legend-row {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 4px 0;
      font-size: 0.85rem;
    }}
    .swatch {{
      width: 14px;
      height: 14px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,0.25);
      flex: 0 0 auto;
    }}
    .open-link {{
      display: inline-block;
      margin-top: 0.9rem;
      color: #8ebcff;
      text-decoration: none;
      font-weight: 600;
    }}
    .navlinks {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 8px;
    }}
    .navlinks a {{
      color: #8ebcff;
      text-decoration: none;
      font-weight: 600;
      font-size: 0.92rem;
    }}
  </style>
</head>
<body>
  <div class="layout">
    <div class="canvas-wrap">
      <div class="toolbar">
        <button id="fitBtn">Fit</button>
        <button id="resetBtn">Reset</button>
        <select id="modeSelect">
          <option value="graph">Graph mode</option>
          <option value="timeline">Timeline mode</option>
        </select>
        <select id="filterSelect">
          <option value="all">All capsules</option>
          <option value="roots">Roots only</option>
          <option value="orphans">Orphans only</option>
          <option value="invalid">Invalid only</option>
        </select>
        <input id="searchInput" type="text" placeholder="Search author, capsule ID, filename">
        <button id="clearSearchBtn">Clear</button>
      </div>
      <svg id="graph" viewBox="0 0 1800 1100" aria-label="Capsule lineage graph">
        <g id="viewport">
          <g id="edges"></g>
          <g id="nodes"></g>
          <g id="labels"></g>
        </g>
      </svg>
    </div>

    <aside class="sidebar">
      <h1>Capsule Lineage Explorer</h1>
      <div class="muted">Directory: <code>{root}</code></div>
      <div class="muted">Capsules: {count}</div>
      <div class="navlinks">
        <a href="index.html">Archive index</a>
        <a href="lineage.json">Graph JSON</a>
        <a href="data/index.json">Archive metadata</a>
      </div>

      <div class="card">
        <strong>Author Groups</strong>
        <div id="legend" class="muted"></div>
      </div>

      <div class="card">
        <strong>Selected Capsule</strong>
        <div id="details" class="muted">Click a node to inspect its capsule. Double-click a node to open its artifact page.</div>
      </div>
    </aside>
  </div>

<script>
const DATA = {data_json};

const svg = document.getElementById("graph");
const viewport = document.getElementById("viewport");
const edgesG = document.getElementById("edges");
const nodesG = document.getElementById("nodes");
const labelsG = document.getElementById("labels");
const details = document.getElementById("details");
const legend = document.getElementById("legend");
const fitBtn = document.getElementById("fitBtn");
const resetBtn = document.getElementById("resetBtn");
const modeSelect = document.getElementById("modeSelect");
const filterSelect = document.getElementById("filterSelect");
const searchInput = document.getElementById("searchInput");
const clearSearchBtn = document.getElementById("clearSearchBtn");

let selectedId = null;
let panX = 0;
let panY = 0;
let scale = 1;
let layoutMode = "graph";
let searchTerm = "";
let filterMode = "all";

const palette = [
  "#6ea8ff", "#ffb86b", "#8be28b", "#d58cff", "#ffd866",
  "#61dafb", "#ff7b72", "#7ee787", "#f2cc60", "#c678dd",
  "#56b6c2", "#e06c75"
];

function esc(s) {{
  return String(s ?? "").replace(/[&<>"]/g, c => ({{"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;"}}[c]));
}}

function truncate(s, n=12) {{
  s = String(s ?? "");
  return s.length <= n ? s : s.slice(0, n) + "…";
}}

function normalize(s) {{
  return String(s ?? "").toLowerCase();
}}

function makeAuthorColors(nodes) {{
  const authors = [...new Set(nodes.map(n => n.author || "(unknown)"))].sort();
  const map = new Map();
  authors.forEach((a, i) => map.set(a, palette[i % palette.length]));
  return map;
}}

const authorColors = makeAuthorColors(DATA.nodes);

function buildLevels(nodes, edges) {{
  const incoming = new Map(nodes.map(n => [n.id, 0]));
  const children = new Map(nodes.map(n => [n.id, []]));

  for (const e of edges) {{
    if (incoming.has(e.to)) incoming.set(e.to, incoming.get(e.to) + 1);
    if (children.has(e.from)) children.get(e.from).push(e.to);
  }}

  const roots = nodes.filter(n => incoming.get(n.id) === 0);
  const queue = roots.map(r => [r.id, 0]);
  const level = new Map();

  while (queue.length) {{
    const [id, depth] = queue.shift();
    if (level.has(id) && level.get(id) <= depth) continue;
    level.set(id, depth);
    for (const child of children.get(id) || []) queue.push([child, depth + 1]);
  }}

  for (const n of nodes) if (!level.has(n.id)) level.set(n.id, 0);
  return level;
}}

function assignGraphPositions(nodes) {{
  const level = buildLevels(nodes, DATA.edges);
  const groups = new Map();

  for (const n of nodes) {{
    const l = level.get(n.id) || 0;
    if (!groups.has(l)) groups.set(l, []);
    groups.get(l).push(n);
  }}

  const sortedLevels = [...groups.keys()].sort((a, b) => a - b);
  const positions = new Map();
  const xGap = 300;
  const yGap = 130;
  const startX = 140;
  const centerY = 550;

  for (const l of sortedLevels) {{
    const group = groups.get(l).sort((a, b) => {
      const ad = a.created_at || "";
      const bd = b.created_at || "";
      return ad.localeCompare(bd) || String(a.id).localeCompare(String(b.id));
    });

    const totalHeight = (group.length - 1) * yGap;
    const baseY = centerY - totalHeight / 2;

    group.forEach((n, i) => {{
      positions.set(n.id, {{
        x: startX + l * xGap,
        y: baseY + i * yGap
      }});
    }});
  }}

  return positions;
}}

function assignTimelinePositions(nodes) {{
  const positions = new Map();
  const sorted = [...nodes].sort((a, b) => {
    const ad = a.created_at || "";
    const bd = b.created_at || "";
    return ad.localeCompare(bd) || String(a.id).localeCompare(String(b.id));
  });

  const xStart = 140;
  const xGap = 190;
  const laneGap = 120;
  const authors = [...new Set(sorted.map(n => n.author || "(unknown)"))].sort();
  const authorLane = new Map(authors.map((a, i) => [a, i]));

  sorted.forEach((n, i) => {{
    const lane = authorLane.get(n.author || "(unknown)") || 0;
    positions.set(n.id, {{
      x: xStart + i * xGap,
      y: 140 + lane * laneGap
    }});
  }});

  return positions;
}}

function matchesSearch(n) {{
  if (!searchTerm.trim()) return true;
  const q = normalize(searchTerm);
  return (
    normalize(n.author).includes(q) ||
    normalize(n.id).includes(q) ||
    normalize(n.filename).includes(q) ||
    normalize(n.path).includes(q)
  );
}}

function matchesFilter(n) {{
  if (filterMode === "all") return true;
  if (filterMode === "roots") return !n.parent_id;
  if (filterMode === "orphans") return !!n.parent_id && !DATA.by_id[n.parent_id];
  if (filterMode === "invalid") return !n.valid;
  return true;
}}

function visibleNode(n) {{
  return matchesSearch(n) && matchesFilter(n);
}}

function renderLegend() {{
  legend.innerHTML = "";
  const authors = [...authorColors.keys()].sort();
  for (const author of authors) {{
    const row = document.createElement("div");
    row.className = "legend-row";
    row.innerHTML = `<span class="swatch" style="background:${authorColors.get(author)}"></span><span>${esc(author)}</span>`;
    legend.appendChild(row);
  }}
}}

function render() {{
  edgesG.innerHTML = "";
  nodesG.innerHTML = "";
  labelsG.innerHTML = "";

  const positions = layoutMode === "timeline"
    ? assignTimelinePositions(DATA.nodes)
    : assignGraphPositions(DATA.nodes);

  for (const e of DATA.edges) {{
    const a = positions.get(e.from);
    const b = positions.get(e.to);
    if (!a || !b) continue;

    const fromNode = DATA.by_id[e.from];
    const toNode = DATA.by_id[e.to];
    const visible = visibleNode(fromNode) || visibleNode(toNode);

    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    let d;
    if (layoutMode === "timeline") {{
      d = `M ${a.x} ${a.y} C ${a.x + 80} ${a.y}, ${b.x - 80} ${b.y}, ${b.x} ${b.y}`;
    }} else {{
      const mx = (a.x + b.x) / 2;
      d = `M ${a.x} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x} ${b.y}`;
    }}
    path.setAttribute("d", d);
    path.setAttribute("class", `edge ${visible ? "" : "dimmed"}`);
    edgesG.appendChild(path);
  }}

  for (const n of DATA.nodes) {{
    const p = positions.get(n.id);
    if (!p) continue;

    const color = n.valid ? (authorColors.get(n.author || "(unknown)") || "#6ea8ff") : "#d96767";
    const visible = visibleNode(n);

    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", p.x);
    circle.setAttribute("cy", p.y);
    circle.setAttribute("r", 18);
    circle.setAttribute("fill", color);
    circle.setAttribute("class", `node ${selectedId === n.id ? "selected" : ""} ${visible ? "" : "dimmed"}`);
    circle.addEventListener("click", (ev) => {{
      ev.stopPropagation();
      selectedId = n.id;
      render();
      showDetails(n);
    }});
    circle.addEventListener("dblclick", (ev) => {{
      ev.stopPropagation();
      if (n.artifact_href) window.open(n.artifact_href, "_blank");
    }});
    nodesG.appendChild(circle);

    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", p.x + 28);
    label.setAttribute("y", p.y + 4);
    label.setAttribute("class", "node-label");
    label.style.opacity = visible ? "1" : "0.2";
    label.textContent = n.author ? `${n.author} · ${truncate(n.id, 10)}` : truncate(n.id, 16);
    labelsG.appendChild(label);
  }}

  applyTransform();
}}

function showDetails(n) {{
  const status = n.valid
    ? `<span class="pill ok">VALID</span>`
    : `<span class="pill bad">INVALID</span>`;

  const children = (n.children || []).length
    ? `<ul>${n.children.map(c => `<li><code>${esc(c)}</code></li>`).join("")}</ul>`
    : `<div class="muted">none</div>`;

  const preview = n.preview
    ? `<pre>${esc(n.preview)}</pre>`
    : `<div class="muted">No text preview available.</div>`;

  const thumb = n.thumbnail
    ? `<img class="thumb" src="${n.thumbnail}" alt="Capsule payload thumbnail">`
    : "";

  const sig = n.signature_over
    ? `<pre>${esc(JSON.stringify(n.signature_over, null, 2))}</pre>`
    : `<div class="muted">none</div>`;

  const openLink = n.artifact_href
    ? `<a class="open-link" href="${n.artifact_href}" target="_blank" rel="noopener">Open artifact page →</a>`
    : "";

  details.innerHTML = `
    <div style="margin-top:.7rem;">${status}</div>
    <div class="kv">
      <div class="k">Capsule ID</div><div><code>${esc(n.id)}</code></div>
      <div class="k">Author</div><div>${esc(n.author || "(unknown)")}</div>
      <div class="k">Created</div><div>${esc(n.created_at || "(unknown)")}</div>
      <div class="k">Parent</div><div><code>${esc(n.parent_id || "(none)")}</code></div>
      <div class="k">Depth</div><div>${esc(n.depth)}</div>
      <div class="k">Children</div><div>${esc(n.child_count)}</div>
      <div class="k">Path</div><div><code>${esc(n.path || "")}</code></div>
      <div class="k">Filename</div><div>${esc(n.filename || "")}</div>
      <div class="k">Schema</div><div>${esc(n.schema || "(unknown)")}</div>
      <div class="k">Payload Type</div><div>${esc(n.payload_type || "(unknown)")}</div>
      <div class="k">Payload SHA</div><div><code>${esc(n.payload_sha256 || "")}</code></div>
      <div class="k">Key FP</div><div><code>${esc(n.key_fingerprint || "")}</code></div>
      <div class="k">Verify</div><div>${esc(n.verify_detail || "")}</div>
    </div>

    ${thumb}
    ${openLink}

    <div class="card">
      <strong>Children</strong>
      ${children}
    </div>

    <div class="card">
      <strong>Payload Preview</strong>
      ${preview}
    </div>

    <div class="card">
      <strong>Signed Fields</strong>
      ${sig}
    </div>
  `;
}}

function applyTransform() {{
  viewport.setAttribute("transform", `translate(${panX},${panY}) scale(${scale})`);
}}

function fitGraph() {{
  panX = 40;
  panY = 40;
  scale = 1;
  applyTransform();
}}

fitBtn.addEventListener("click", fitGraph);
resetBtn.addEventListener("click", fitGraph);

modeSelect.addEventListener("change", () => {{
  layoutMode = modeSelect.value;
  render();
}});

filterSelect.addEventListener("change", () => {{
  filterMode = filterSelect.value;
  render();
}});

searchInput.addEventListener("input", () => {{
  searchTerm = searchInput.value;
  render();
}});

clearSearchBtn.addEventListener("click", () => {{
  searchInput.value = "";
  searchTerm = "";
  filterMode = "all";
  filterSelect.value = "all";
  render();
}});

let dragging = false;
let lastX = 0;
let lastY = 0;

svg.addEventListener("mousedown", (e) => {{
  dragging = true;
  lastX = e.clientX;
  lastY = e.clientY;
  svg.style.cursor = "grabbing";
}});

window.addEventListener("mousemove", (e) => {{
  if (!dragging) return;
  panX += e.clientX - lastX;
  panY += e.clientY - lastY;
  lastX = e.clientX;
  lastY = e.clientY;
  applyTransform();
}});

window.addEventListener("mouseup", () => {{
  dragging = false;
  svg.style.cursor = "grab";
}});

svg.addEventListener("click", () => {{
  selectedId = null;
  render();
  details.innerHTML = 'Click a node to inspect its capsule. Double-click a node to open its artifact page.';
}});

renderLegend();
render();
if (DATA.nodes.length > 0) {{
  showDetails(DATA.nodes[0]);
}}
</script>
</body>
</html>
"""


def render_lineage_page(model: Dict[str, Any], out_path: Path) -> None:
    data = {
        "root": model["root"],
        "count": model["summary"]["capsule_count"],
        "nodes": [
            {k: v for k, v in n.items() if k != "raw_capsule"}
            for n in model["nodes"]
        ],
        "edges": model["edges"],
        "by_id": {
            k: {kk: vv for kk, vv in v.items() if kk != "raw_capsule"}
            for k, v in model["by_id"].items()
        },
    }
    page = LINEAGE_TEMPLATE.format(
        root=html.escape(model["root"]),
        count=model["summary"]["capsule_count"],
        data_json=json.dumps(data, ensure_ascii=False),
    )
    out_path.write_text(page, encoding="utf-8")


# ============================================================
# JSON exports
# ============================================================

def write_graph_json(model: Dict[str, Any], out_path: Path) -> None:
    data = {
        "root": model["root"],
        "summary": model["summary"],
        "nodes": [
            {k: v for k, v in n.items() if k != "raw_capsule"}
            for n in model["nodes"]
        ],
        "edges": model["edges"],
    }
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_index_json(model: Dict[str, Any], out_path: Path) -> None:
    data = {
        "root": model["root"],
        "summary": model["summary"],
        "roots": model["roots"],
        "orphans": model["orphans"],
        "invalid": model["invalid"],
        "authors": model["authors"],
        "latest_nodes": [
            {k: v for k, v in n.items() if k not in ("raw_capsule", "thumbnail", "preview")}
            for n in model["latest_nodes"]
        ],
    }
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


# ============================================================
# Main
# ============================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="capsule-lineage-explorer",
        description="Generate a static capsule archive with lineage explorer and artifact pages",
    )
    parser.add_argument("directory", help="Directory containing .cap files")
    parser.add_argument(
        "--output-dir",
        help="Output archive directory (default: <directory>/archive)",
    )
    args = parser.parse_args()

    source_root = Path(args.directory)
    if not source_root.exists() or not source_root.is_dir():
        print(f"Directory not found: {source_root}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output_dir) if args.output_dir else source_root / "archive"
    artifact_dir = output_dir / "artifacts"
    data_dir = output_dir / "data"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    model = build_archive_model(source_root, artifact_dir_name="artifacts")

    render_index_page(model, output_dir / "index.html")
    render_lineage_page(model, output_dir / "lineage.html")
    write_graph_json(model, output_dir / "lineage.json")
    write_index_json(model, data_dir / "index.json")

    for node in model["nodes"]:
        if node.get("raw_capsule") and node.get("id") in model["by_id"]:
            render_artifact_page(node, model["by_id"], artifact_dir / f"{node['id']}.html")

    print(f"Wrote archive index   -> {output_dir / 'index.html'}")
    print(f"Wrote lineage page    -> {output_dir / 'lineage.html'}")
    print(f"Wrote graph JSON      -> {output_dir / 'lineage.json'}")
    print(f"Wrote index JSON      -> {data_dir / 'index.json'}")
    print(f"Wrote artifact pages  -> {artifact_dir}")
    print(f"Capsules indexed      -> {model['summary']['capsule_count']}")


if __name__ == "__main__":
    main()