#!/usr/bin/env python3
"""
capsule_viewer.py

A lightweight viewer for capsule.v0 files.

Features:
- Loads and verifies a capsule offline
- Prints a clean human-readable summary
- Shows key fingerprint
- Previews text payloads when possible
- Can generate a standalone HTML viewer page
- Can scan a directory of capsules and show simple lineage relationships

Designed for the current capsule.v0 format used by capsule.py.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import mimetypes
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print(
        "Missing dependency: cryptography. Install with: python -m pip install cryptography",
        file=sys.stderr,
    )
    sys.exit(1)


# ----------------------------
# Core helpers
# ----------------------------

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
    """
    Returns (is_valid, message).
    """
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
    except Exception as e:  # pragma: no cover
        return False, f"{type(e).__name__}: {e}"


# ----------------------------
# Presentation helpers
# ----------------------------

def key_fingerprint_from_pem(pem: str) -> str:
    der = serialization.load_pem_public_key(
        pem.encode("utf-8")
    ).public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).hexdigest()
    return f"sha256:{digest}"


def guess_payload_kind(payload: bytes, source_name: str = "") -> str:
    """
    Best-effort payload classification.
    """
    mime, _ = mimetypes.guess_type(source_name)
    if mime:
        return mime

    try:
        payload.decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "application/octet-stream"


def text_preview(payload: bytes, max_chars: int = 2000) -> Optional[str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None

    if len(text) > max_chars:
        return text[:max_chars] + "\n\n...[truncated]..."
    return text


def payload_summary(payload: bytes, source_name: str = "") -> Dict[str, Any]:
    kind = guess_payload_kind(payload, source_name)
    preview = text_preview(payload)

    return {
        "size_bytes": len(payload),
        "kind": kind,
        "is_text": preview is not None,
        "preview": preview,
    }


def find_capsules_in_dir(root: Path) -> List[Path]:
    return sorted([p for p in root.rglob("*.cap") if p.is_file()])


def build_lineage_index(paths: Iterable[Path]) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for path in paths:
        try:
            cap = load_capsule(path)
            cid = cap.get("capsule_id")
            if cid:
                index[cid] = {
                    "path": path,
                    "capsule": cap,
                }
        except Exception:
            continue
    return index


def children_of(capsule_id: str, index: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    children = []
    for item in index.values():
        cap = item["capsule"]
        if cap.get("parent_id") == capsule_id:
            children.append(item)
    return sorted(children, key=lambda x: x["path"].name.lower())


# ----------------------------
# CLI / HTML output
# ----------------------------

def print_summary(path: Path, scan_dir: Optional[Path] = None) -> int:
    cap = load_capsule(path)
    valid, msg = verify_capsule(cap)
    payload = b64d(cap["payload_b64"])
    ps = payload_summary(payload, path.name)
    fp = key_fingerprint_from_pem(cap["public_key_pem"])

    print("=" * 72)
    print("CAPSULE VIEWER")
    print("=" * 72)
    print(f"File:           {path}")
    print(f"Schema:         {cap.get('schema')}")
    print(f"Status:         {'VALID ✅' if valid else 'INVALID ❌'}")
    print(f"Verify detail:  {msg}")
    print()
    print(f"Capsule ID:     {cap.get('capsule_id')}")
    print(f"Author:         {cap.get('author')}")
    print(f"Created At:     {cap.get('created_at')}")
    print(f"Parent ID:      {cap.get('parent_id') or '(none)'}")
    print(f"Payload SHA256: {cap.get('payload_sha256')}")
    print(f"Key Fingerprint:{fp}")
    print()
    print("Payload")
    print("-" * 72)
    print(f"Type:           {ps['kind']}")
    print(f"Size:           {ps['size_bytes']} bytes")
    print(f"Text Preview:   {'yes' if ps['is_text'] else 'no'}")

    if ps["preview"]:
        print()
        print("Preview")
        print("-" * 72)
        print(ps["preview"])

    if scan_dir:
        print()
        print("Lineage")
        print("-" * 72)
        index = build_lineage_index(find_capsules_in_dir(scan_dir))

        parent_id = cap.get("parent_id")
        if parent_id:
            parent = index.get(parent_id)
            if parent:
                print(f"Parent:         {parent_id}  ({parent['path'].name})")
            else:
                print(f"Parent:         {parent_id}  (not found in scan dir)")
        else:
            print("Parent:         (none)")

        kids = children_of(cap["capsule_id"], index)
        if not kids:
            print("Children:       (none)")
        else:
            for child in kids:
                print(
                    f"Child:          {child['capsule'].get('capsule_id')}  "
                    f"({child['path'].name})"
                )

    return 0 if valid else 1


def render_html(path: Path, out_path: Path, scan_dir: Optional[Path] = None) -> int:
    cap = load_capsule(path)
    valid, msg = verify_capsule(cap)
    payload = b64d(cap["payload_b64"])
    ps = payload_summary(payload, path.name)
    fp = key_fingerprint_from_pem(cap["public_key_pem"])

    parent_html = ""
    children_html = ""

    if scan_dir:
        index = build_lineage_index(find_capsules_in_dir(scan_dir))
        parent_id = cap.get("parent_id")
        if parent_id:
            parent = index.get(parent_id)
            if parent:
                parent_html = (
                    f"<p><strong>Parent:</strong> {html.escape(parent_id)} "
                    f"({html.escape(parent['path'].name)})</p>"
                )
            else:
                parent_html = f"<p><strong>Parent:</strong> {html.escape(parent_id)} (not found)</p>"
        else:
            parent_html = "<p><strong>Parent:</strong> none</p>"

        kids = children_of(cap["capsule_id"], index)
        if kids:
            child_items = "".join(
                f"<li>{html.escape(k['capsule'].get('capsule_id', ''))} "
                f"({html.escape(k['path'].name)})</li>"
                for k in kids
            )
            children_html = f"<p><strong>Children:</strong></p><ul>{child_items}</ul>"
        else:
            children_html = "<p><strong>Children:</strong> none</p>"

    preview_html = (
        f"<pre>{html.escape(ps['preview'])}</pre>" if ps["preview"] else "<p>No text preview available.</p>"
    )

    status_text = "VALID ✅" if valid else "INVALID ❌"

    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Capsule Viewer</title>
  <style>
    body {{
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
      max-width: 1000px;
      margin: 2rem auto;
      padding: 0 1rem;
      color: #111;
      background: #fafafa;
    }}
    h1, h2 {{
      margin-bottom: 0.5rem;
    }}
    .card {{
      background: white;
      border: 1px solid #ddd;
      border-radius: 14px;
      padding: 1rem 1.25rem;
      margin: 1rem 0;
      box-shadow: 0 1px 4px rgba(0,0,0,0.04);
    }}
    pre {{
      background: #f5f5f5;
      border-radius: 10px;
      padding: 1rem;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .ok {{
      color: #0a7a2f;
      font-weight: 700;
    }}
    .bad {{
      color: #a11;
      font-weight: 700;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
    }}
    td {{
      border-top: 1px solid #eee;
      padding: 0.55rem 0.4rem;
      vertical-align: top;
    }}
    td:first-child {{
      width: 220px;
      font-weight: 600;
      color: #333;
    }}
  </style>
</head>
<body>
  <h1>Capsule Viewer</h1>

  <div class="card">
    <h2>Summary</h2>
    <table>
      <tr><td>File</td><td>{html.escape(str(path))}</td></tr>
      <tr><td>Status</td><td><span class="{'ok' if valid else 'bad'}">{html.escape(status_text)}</span></td></tr>
      <tr><td>Verify Detail</td><td>{html.escape(msg)}</td></tr>
      <tr><td>Schema</td><td>{html.escape(str(cap.get('schema')))}</td></tr>
      <tr><td>Capsule ID</td><td>{html.escape(str(cap.get('capsule_id')))}</td></tr>
      <tr><td>Author</td><td>{html.escape(str(cap.get('author')))}</td></tr>
      <tr><td>Created At</td><td>{html.escape(str(cap.get('created_at')))}</td></tr>
      <tr><td>Parent ID</td><td>{html.escape(str(cap.get('parent_id') or '(none)'))}</td></tr>
      <tr><td>Payload SHA256</td><td>{html.escape(str(cap.get('payload_sha256')))}</td></tr>
      <tr><td>Key Fingerprint</td><td>{html.escape(fp)}</td></tr>
      <tr><td>Payload Type</td><td>{html.escape(ps['kind'])}</td></tr>
      <tr><td>Payload Size</td><td>{ps['size_bytes']} bytes</td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Payload Preview</h2>
    {preview_html}
  </div>

  <div class="card">
    <h2>Lineage</h2>
    {parent_html or "<p>No lineage scan requested.</p>"}
    {children_html}
  </div>

  <div class="card">
    <h2>Signed Fields</h2>
    <pre>{html.escape(json.dumps(cap.get("signature_over", {}), indent=2, ensure_ascii=False))}</pre>
  </div>

  <div class="card">
    <h2>Raw Capsule JSON</h2>
    <pre>{html.escape(json.dumps(cap, indent=2, ensure_ascii=False))}</pre>
  </div>
</body>
</html>
"""
    out_path.write_text(page, encoding="utf-8")
    print(f"Wrote HTML viewer -> {out_path}")
    return 0 if valid else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="capsule-viewer",
        description="View and verify capsule.v0 files",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("show", help="Print a human-readable capsule summary")
    s1.add_argument("capsule", help="Path to .cap file")
    s1.add_argument(
        "--scan-dir",
        help="Optional directory to scan for parent/child capsules",
    )

    s2 = sub.add_parser("html", help="Generate a standalone HTML viewer page")
    s2.add_argument("capsule", help="Path to .cap file")
    s2.add_argument(
        "--output",
        help="Output HTML file path (default: <capsule>.html)",
    )
    s2.add_argument(
        "--scan-dir",
        help="Optional directory to scan for parent/child capsules",
    )

    args = parser.parse_args()

    if args.cmd == "show":
        path = Path(args.capsule)
        scan_dir = Path(args.scan_dir) if args.scan_dir else None
        sys.exit(print_summary(path, scan_dir))

    if args.cmd == "html":
        path = Path(args.capsule)
        scan_dir = Path(args.scan_dir) if args.scan_dir else None
        out = Path(args.output) if args.output else path.with_suffix(path.suffix + ".html")
        sys.exit(render_html(path, out, scan_dir))


if __name__ == "__main__":
    main()