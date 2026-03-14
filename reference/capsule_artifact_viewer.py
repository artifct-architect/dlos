#!/usr/bin/env python3
"""
capsule_artifact_viewer.py

Generate a standalone museum-style HTML viewer for a single capsule.v0 file.

Usage:
    python reference/capsule_artifact_viewer.py examples/hello.cap
    python reference/capsule_artifact_viewer.py examples/hello.cap --output examples/hello.artifact.html
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print(
        "Missing dependency: cryptography. Install with: python -m pip install cryptography",
        file=sys.stderr,
    )
    sys.exit(1)


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


def detect_payload_type(payload: bytes) -> str:
    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if payload.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if payload.startswith(b"GIF87a") or payload.startswith(b"GIF89a"):
        return "image/gif"
    if payload.startswith(b"RIFF") and b"WEBP" in payload[:16]:
        return "image/webp"
    try:
        payload.decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "application/octet-stream"


def safe_text_preview(payload: bytes, max_chars: int = 3000) -> Optional[str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) > max_chars:
        return text[:max_chars] + "\n\n...[truncated]..."
    return text


HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Artifact Viewer</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {{
      --bg: #0c111c;
      --panel: #121a2b;
      --panel-2: #0f1626;
      --text: #e8edf7;
      --muted: #9cabc5;
      --border: #26344f;
      --accent: #7db2ff;
      --ok: #3ec97a;
      --bad: #e56767;
      --shadow: 0 10px 30px rgba(0,0,0,0.25);
    }}

    * {{ box-sizing: border-box; }}

    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
      background:
        radial-gradient(circle at top, rgba(125,178,255,0.08), transparent 30%),
        linear-gradient(180deg, var(--bg), #08101b 65%);
      color: var(--text);
    }}

    .page {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 28px 20px 40px;
    }}

    .hero {{
      display: grid;
      grid-template-columns: 1.2fr 0.8fr;
      gap: 20px;
      align-items: start;
    }}

    .panel {{
      background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.015));
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: var(--shadow);
    }}

    .hero-left {{
      padding: 22px;
    }}

    .eyebrow {{
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-size: 0.78rem;
      margin-bottom: 10px;
    }}

    h1 {{
      margin: 0;
      font-size: 2rem;
      line-height: 1.1;
    }}

    .sub {{
      margin-top: 10px;
      color: var(--muted);
      line-height: 1.55;
      max-width: 62ch;
    }}

    .status {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-top: 16px;
      padding: 8px 12px;
      border-radius: 999px;
      font-size: 0.9rem;
      font-weight: 700;
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

    .meta {{
      padding: 18px 18px 8px;
    }}

    .meta h2, .section h2 {{
      margin: 0 0 12px;
      font-size: 1rem;
    }}

    .kv {{
      display: grid;
      grid-template-columns: 130px 1fr;
      gap: 10px 12px;
      font-size: 0.95rem;
    }}

    .k {{
      color: var(--muted);
    }}

    .v code {{
      word-break: break-all;
    }}

    .grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-top: 20px;
    }}

    .section {{
      padding: 18px;
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
      color: #dfe8f8;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
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
      background: rgba(255,255,255,0.02);
    }}

    .muted {{
      color: var(--muted);
    }}

    details {{
      margin-top: 12px;
    }}

    summary {{
      cursor: pointer;
      color: var(--accent);
      font-weight: 600;
    }}

    .footer {{
      margin-top: 24px;
      color: var(--muted);
      font-size: 0.88rem;
    }}

    @media (max-width: 900px) {{
      .hero {{
        grid-template-columns: 1fr;
      }}
      .grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <div class="hero">
      <section class="panel hero-left">
        <div class="eyebrow">Digital Artifact</div>
        <h1>{title}</h1>
        <div class="sub">
          A self-verifying capsule artifact with embedded identity, integrity, and lineage reference.
        </div>
        <div class="status {status_class}">
          {status_text}
        </div>
      </section>

      <aside class="panel meta">
        <h2>Artifact Identity</h2>
        <div class="kv">
          <div class="k">Capsule ID</div><div class="v"><code>{capsule_id}</code></div>
          <div class="k">Author</div><div class="v">{author}</div>
          <div class="k">Created</div><div class="v">{created_at}</div>
          <div class="k">Parent</div><div class="v"><code>{parent_id}</code></div>
          <div class="k">Schema</div><div class="v">{schema}</div>
          <div class="k">Payload Type</div><div class="v">{payload_type}</div>
          <div class="k">Payload Size</div><div class="v">{payload_size}</div>
          <div class="k">Key FP</div><div class="v"><code>{key_fp}</code></div>
        </div>
      </aside>
    </div>

    <div class="grid">
      <section class="panel section">
        <h2>Artifact Preview</h2>
        {preview_block}
      </section>

      <section class="panel section">
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

    <div class="footer">
      Generated by <code>reference/capsule_artifact_viewer.py</code>
    </div>
  </div>
</body>
</html>
"""


def render_html(cap: Dict[str, Any], source_path: Path, out_path: Path) -> int:
    valid, verify_detail = verify_capsule(cap)

    payload = b64d(cap["payload_b64"])
    payload_type = detect_payload_type(payload)
    payload_size = f"{len(payload)} bytes"
    key_fp = key_fingerprint_from_pem(cap["public_key_pem"])

    title = cap.get("author") or source_path.stem
    status_text = "VALID CAPSULE" if valid else "INVALID CAPSULE"
    status_class = "ok" if valid else "bad"

    preview_block: str
    if payload_type.startswith("image/"):
        data_url = f"data:{payload_type};base64,{cap['payload_b64']}"
        preview_block = f'<img class="preview" src="{data_url}" alt="Artifact preview">'
    else:
        preview = safe_text_preview(payload)
        if preview:
            preview_block = f"<pre>{html.escape(preview)}</pre>"
        else:
            preview_block = '<div class="muted">No native preview available for this payload type.</div>'

    page = HTML_TEMPLATE.format(
        title=html.escape(title),
        status_text=html.escape(status_text),
        status_class=status_class,
        capsule_id=html.escape(str(cap.get("capsule_id", ""))),
        author=html.escape(str(cap.get("author", "(unknown)"))),
        created_at=html.escape(str(cap.get("created_at", "(unknown)"))),
        parent_id=html.escape(str(cap.get("parent_id") or "(none)")),
        schema=html.escape(str(cap.get("schema", ""))),
        payload_type=html.escape(payload_type),
        payload_size=html.escape(payload_size),
        key_fp=html.escape(key_fp),
        verify_detail=html.escape(verify_detail),
        payload_sha=html.escape(str(cap.get("payload_sha256", ""))),
        signature_over=html.escape(json.dumps(cap.get("signature_over", {}), indent=2, ensure_ascii=False)),
        raw_json=html.escape(json.dumps(cap, indent=2, ensure_ascii=False)),
        preview_block=preview_block,
    )

    out_path.write_text(page, encoding="utf-8")
    print(f"Wrote artifact viewer -> {out_path}")
    return 0 if valid else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="capsule-artifact-viewer",
        description="Generate a museum-style HTML viewer for a single capsule",
    )
    parser.add_argument("capsule", help="Path to .cap file")
    parser.add_argument(
        "--output",
        help="Output HTML file path (default: <capsule>.artifact.html)",
    )
    args = parser.parse_args()

    source_path = Path(args.capsule)
    if not source_path.exists():
        print(f"Capsule not found: {source_path}", file=sys.stderr)
        sys.exit(1)

    out_path = (
        Path(args.output)
        if args.output
        else source_path.with_suffix(source_path.suffix + ".artifact.html")
    )

    cap = load_capsule(source_path)
    sys.exit(render_html(cap, source_path, out_path))


if __name__ == "__main__":
    main()