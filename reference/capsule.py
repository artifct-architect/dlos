#!/usr/bin/env python3
"""
capsule.py

Reference CLI for capsule.v0 objects.

Commands:
  keygen   Generate an Ed25519 keypair
  seal     Create a capsule from a payload file
  verify   Verify a capsule
  show     Show capsule metadata
  extract  Extract a capsule payload
  branch   Create a derivative capsule from an existing capsule

Examples:
  python reference/capsule.py keygen --out-dir keys
  python reference/capsule.py seal payload.txt --author "Christopher Jamar Prater" --private-key keys/private.pem --public-key keys/public.pem
  python reference/capsule.py verify payload.txt.cap
  python reference/capsule.py show payload.txt.cap
  python reference/capsule.py extract payload.txt.cap --output restored.txt
  python reference/capsule.py branch parent.cap new_payload.txt --author "Christopher Jamar Prater" --private-key keys/private.pem --public-key keys/public.pem
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


SCHEMA = "capsule.v0"


# ============================================================
# Helpers
# ============================================================

def canonical_json_bytes(obj: Dict[str, Any]) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"), validate=True)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def write_bytes(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(read_text(path))


def iso_utc_now() -> str:
    from datetime import datetime, timezone
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def compute_capsule_id(
    payload_sha256: str,
    created_at: str,
    author: str,
    parent_id: Optional[str],
) -> str:
    seed = {
        "payload_sha256": payload_sha256,
        "created_at": created_at,
        "author": author,
        "parent_id": parent_id or "",
        "schema": SCHEMA,
    }
    return sha256_bytes(canonical_json_bytes(seed))


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(read_bytes(path), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Private key is not Ed25519.")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(read_bytes(path))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Public key is not Ed25519.")
    return key


def key_fingerprint_from_public_pem(public_pem: str) -> str:
    pub = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + sha256_bytes(der)


def detect_payload_extension(payload: bytes) -> str:
    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if payload.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if payload.startswith(b"GIF87a") or payload.startswith(b"GIF89a"):
        return ".gif"
    if payload.startswith(b"RIFF") and b"WEBP" in payload[:16]:
        return ".webp"
    try:
        payload.decode("utf-8")
        return ".txt"
    except UnicodeDecodeError:
        return ".bin"


def text_preview(payload: bytes, max_chars: int = 500) -> Optional[str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text[:max_chars] + ("...[truncated]" if len(text) > max_chars else "")


# ============================================================
# Capsule operations
# ============================================================

def build_capsule(
    payload: bytes,
    author: str,
    private_key: Ed25519PrivateKey,
    public_key_pem: str,
    parent_id: Optional[str] = None,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    created_at = created_at or iso_utc_now()
    payload_sha256 = sha256_bytes(payload)
    capsule_id = compute_capsule_id(payload_sha256, created_at, author, parent_id)

    signature_over = {
        "schema": SCHEMA,
        "capsule_id": capsule_id,
        "payload_sha256": payload_sha256,
        "created_at": created_at,
        "author": author,
        "parent_id": parent_id or "",
    }

    signature = private_key.sign(canonical_json_bytes(signature_over))

    return {
        "schema": SCHEMA,
        "capsule_id": capsule_id,
        "created_at": created_at,
        "author": author,
        "parent_id": parent_id,
        "payload_sha256": payload_sha256,
        "payload_b64": b64e(payload),
        "public_key_pem": public_key_pem,
        "signature_b64": b64e(signature),
        "signature_over": signature_over,
    }


def verify_capsule(capsule: Dict[str, Any]) -> Tuple[bool, str]:
    try:
        if capsule.get("schema") != SCHEMA:
            return False, f"Unsupported schema: {capsule.get('schema')}"

        required = [
            "schema",
            "capsule_id",
            "created_at",
            "author",
            "payload_sha256",
            "payload_b64",
            "public_key_pem",
            "signature_b64",
            "signature_over",
        ]
        for field in required:
            if field not in capsule:
                return False, f"Missing field: {field}"

        payload = b64d(capsule["payload_b64"])
        actual_payload_sha = sha256_bytes(payload)
        if actual_payload_sha != capsule["payload_sha256"]:
            return False, "Payload hash mismatch"

        recomputed_id = compute_capsule_id(
            payload_sha256=capsule["payload_sha256"],
            created_at=capsule["created_at"],
            author=capsule["author"],
            parent_id=capsule.get("parent_id"),
        )
        if recomputed_id != capsule["capsule_id"]:
            return False, "Capsule ID mismatch"

        expected_signature_over = {
            "schema": SCHEMA,
            "capsule_id": capsule["capsule_id"],
            "payload_sha256": capsule["payload_sha256"],
            "created_at": capsule["created_at"],
            "author": capsule["author"],
            "parent_id": capsule.get("parent_id") or "",
        }
        if capsule["signature_over"] != expected_signature_over:
            return False, "Signed field set mismatch"

        public_key = serialization.load_pem_public_key(
            capsule["public_key_pem"].encode("utf-8")
        )
        if not isinstance(public_key, Ed25519PublicKey):
            return False, "Embedded public key is not Ed25519"

        signature = b64d(capsule["signature_b64"])
        public_key.verify(signature, canonical_json_bytes(expected_signature_over))
        return True, "VALID"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


# ============================================================
# Command handlers
# ============================================================

def cmd_keygen(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path = out_dir / args.private_name
    public_path = out_dir / args.public_name

    write_bytes(private_path, private_pem)
    write_bytes(public_path, public_pem)

    print(f"Private key: {private_path}")
    print(f"Public key:  {public_path}")
    return 0


def cmd_seal(args: argparse.Namespace) -> int:
    payload_path = Path(args.payload)
    private_key_path = Path(args.private_key)
    public_key_path = Path(args.public_key)

    payload = read_bytes(payload_path)
    private_key = load_private_key(private_key_path)
    public_key_pem = read_text(public_key_path)

    capsule = build_capsule(
        payload=payload,
        author=args.author,
        private_key=private_key,
        public_key_pem=public_key_pem,
        parent_id=args.parent_id,
        created_at=args.created_at,
    )

    out_path = Path(args.output) if args.output else payload_path.with_suffix(payload_path.suffix + ".cap")
    write_text(out_path, json.dumps(capsule, indent=2, ensure_ascii=False))

    print(f"Capsule written: {out_path}")
    print(f"Capsule ID:      {capsule['capsule_id']}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    cap_path = Path(args.capsule)
    capsule = load_json(cap_path)
    ok, detail = verify_capsule(capsule)

    print(f"Capsule: {cap_path}")
    print(f"Status:  {'VALID' if ok else 'INVALID'}")
    print(f"Detail:  {detail}")
    return 0 if ok else 1


def cmd_show(args: argparse.Namespace) -> int:
    cap_path = Path(args.capsule)
    capsule = load_json(cap_path)
    ok, detail = verify_capsule(capsule)
    payload = b64d(capsule["payload_b64"])
    preview = text_preview(payload)

    print("=" * 72)
    print("CAPSULE SUMMARY")
    print("=" * 72)
    print(f"File:            {cap_path}")
    print(f"Schema:          {capsule.get('schema')}")
    print(f"Status:          {'VALID' if ok else 'INVALID'}")
    print(f"Verify detail:   {detail}")
    print(f"Capsule ID:      {capsule.get('capsule_id')}")
    print(f"Author:          {capsule.get('author')}")
    print(f"Created At:      {capsule.get('created_at')}")
    print(f"Parent ID:       {capsule.get('parent_id') or '(none)'}")
    print(f"Payload SHA256:  {capsule.get('payload_sha256')}")
    print(f"Payload Size:    {len(payload)} bytes")
    print(f"Key Fingerprint: {key_fingerprint_from_public_pem(capsule['public_key_pem'])}")

    if preview:
        print("\nPreview")
        print("-" * 72)
        print(preview)

    if args.raw:
        print("\nRaw Capsule")
        print("-" * 72)
        print(json.dumps(capsule, indent=2, ensure_ascii=False))

    return 0 if ok else 1


def cmd_extract(args: argparse.Namespace) -> int:
    cap_path = Path(args.capsule)
    capsule = load_json(cap_path)

    if args.verify_first:
        ok, detail = verify_capsule(capsule)
        if not ok:
            print(f"Refusing to extract invalid capsule: {detail}", file=sys.stderr)
            return 1

    payload = b64d(capsule["payload_b64"])

    if args.output:
        out_path = Path(args.output)
    else:
        ext = detect_payload_extension(payload)
        stem = Path(args.capsule).stem
        out_path = Path(f"{stem}.extracted{ext}")

    write_bytes(out_path, payload)
    print(f"Extracted payload: {out_path}")
    return 0


def cmd_branch(args: argparse.Namespace) -> int:
    parent_path = Path(args.parent_capsule)
    new_payload_path = Path(args.payload)
    private_key_path = Path(args.private_key)
    public_key_path = Path(args.public_key)

    parent_capsule = load_json(parent_path)
    ok, detail = verify_capsule(parent_capsule)
    if not ok:
        print(f"Parent capsule is invalid: {detail}", file=sys.stderr)
        return 1

    payload = read_bytes(new_payload_path)
    private_key = load_private_key(private_key_path)
    public_key_pem = read_text(public_key_path)

    capsule = build_capsule(
        payload=payload,
        author=args.author,
        private_key=private_key,
        public_key_pem=public_key_pem,
        parent_id=parent_capsule["capsule_id"],
        created_at=args.created_at,
    )

    out_path = Path(args.output) if args.output else new_payload_path.with_suffix(new_payload_path.suffix + ".cap")
    write_text(out_path, json.dumps(capsule, indent=2, ensure_ascii=False))

    print(f"Branched capsule written: {out_path}")
    print(f"Parent capsule ID:        {parent_capsule['capsule_id']}")
    print(f"New capsule ID:           {capsule['capsule_id']}")
    return 0


# ============================================================
# CLI parser
# ============================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capsule",
        description="Reference CLI for capsule.v0 objects",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # keygen
    p = sub.add_parser("keygen", help="Generate an Ed25519 keypair")
    p.add_argument("--out-dir", default="keys", help="Directory to write keys into")
    p.add_argument("--private-name", default="private.pem", help="Private key filename")
    p.add_argument("--public-name", default="public.pem", help="Public key filename")
    p.set_defaults(func=cmd_keygen)

    # seal
    p = sub.add_parser("seal", help="Seal a payload file into a capsule")
    p.add_argument("payload", help="Payload file to seal")
    p.add_argument("--author", required=True, help="Author string")
    p.add_argument("--private-key", required=True, help="Path to Ed25519 private key PEM")
    p.add_argument("--public-key", required=True, help="Path to Ed25519 public key PEM")
    p.add_argument("--parent-id", help="Optional parent capsule ID")
    p.add_argument("--created-at", help="Optional explicit UTC timestamp")
    p.add_argument("--output", help="Output capsule path")
    p.set_defaults(func=cmd_seal)

    # verify
    p = sub.add_parser("verify", help="Verify a capsule")
    p.add_argument("capsule", help="Path to capsule file")
    p.set_defaults(func=cmd_verify)

    # show
    p = sub.add_parser("show", help="Show capsule metadata")
    p.add_argument("capsule", help="Path to capsule file")
    p.add_argument("--raw", action="store_true", help="Also print raw capsule JSON")
    p.set_defaults(func=cmd_show)

    # extract
    p = sub.add_parser("extract", help="Extract payload from a capsule")
    p.add_argument("capsule", help="Path to capsule file")
    p.add_argument("--output", help="Output payload path")
    p.add_argument(
        "--verify-first",
        action="store_true",
        help="Verify capsule before extraction",
    )
    p.set_defaults(func=cmd_extract)

    # branch
    p = sub.add_parser("branch", help="Create a derivative capsule from a parent capsule")
    p.add_argument("parent_capsule", help="Path to parent capsule")
    p.add_argument("payload", help="New payload file")
    p.add_argument("--author", required=True, help="Author string")
    p.add_argument("--private-key", required=True, help="Path to Ed25519 private key PEM")
    p.add_argument("--public-key", required=True, help="Path to Ed25519 public key PEM")
    p.add_argument("--created-at", help="Optional explicit UTC timestamp")
    p.add_argument("--output", help="Output capsule path")
    p.set_defaults(func=cmd_branch)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
