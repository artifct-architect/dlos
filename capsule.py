#!/usr/bin/env python3
import argparse
import base64
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# --- Crypto (Ed25519) ---
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Missing dependency: cryptography. Install with: python -m pip install cryptography", file=sys.stderr)
    sys.exit(1)

APP_DIR = Path.home() / ".capsule"
KEY_DIR = APP_DIR / "keys"
DEFAULT_PRIV = KEY_DIR / "ed25519_private.pem"
DEFAULT_PUB = KEY_DIR / "ed25519_public.pem"

def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"), validate=True)

def ensure_keys(priv_path: Path = DEFAULT_PRIV, pub_path: Path = DEFAULT_PUB) -> None:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if priv_path.exists() and pub_path.exists():
        return

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_bytes)
    pub_path.write_bytes(pub_bytes)

def load_private_key(priv_path: Path = DEFAULT_PRIV) -> Ed25519PrivateKey:
    ensure_keys(priv_path=priv_path, pub_path=DEFAULT_PUB)
    return serialization.load_pem_private_key(priv_path.read_bytes(), password=None)

def load_public_key_from_pem(pem_bytes: bytes) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(pem_bytes)

def load_public_key(pub_path: Path = DEFAULT_PUB) -> Ed25519PublicKey:
    ensure_keys(priv_path=DEFAULT_PRIV, pub_path=pub_path)
    return serialization.load_pem_public_key(pub_path.read_bytes())

def canonical_message(fields: Dict[str, Any]) -> bytes:
    """
    We sign a canonical JSON serialization of a subset of fields.
    This avoids ambiguity and makes signature reproducible.
    """
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return canonical.encode("utf-8")

def compute_capsule_id(payload_sha: str, created_at: str, author: str, parent_id: Optional[str]) -> str:
    # The capsule_id is derived from immutable identity fields (not signature itself).
    base = {
        "payload_sha256": payload_sha,
        "created_at": created_at,
        "author": author,
        "parent_id": parent_id or "",
        "schema": "capsule.v0",
    }
    return sha256_bytes(canonical_message(base))

def seal_file(input_path: Path, out_path: Optional[Path], author: str, parent_id: Optional[str]) -> Path:
    data = input_path.read_bytes()
    payload_sha = sha256_bytes(data)
    created_at = utc_now_iso()

    capsule_id = compute_capsule_id(payload_sha, created_at, author, parent_id)

    priv = load_private_key()
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Sign canonical identity message (not the raw payload)
    sign_fields = {
        "schema": "capsule.v0",
        "capsule_id": capsule_id,
        "payload_sha256": payload_sha,
        "created_at": created_at,
        "author": author,
        "parent_id": parent_id or "",
    }
    sig = priv.sign(canonical_message(sign_fields))

    capsule = {
        "schema": "capsule.v0",
        "capsule_id": capsule_id,
        "created_at": created_at,
        "author": author,
        "parent_id": parent_id,
        "payload_sha256": payload_sha,
        "payload_b64": b64e(data),
        "public_key_pem": pub_pem.decode("utf-8"),
        "signature_b64": b64e(sig),
        "signature_over": sign_fields,  # helpful for debugging / transparency
    }

    if out_path is None:
        out_path = input_path.with_suffix(".cap")
    out_path.write_text(json.dumps(capsule, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path

def load_capsule(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def verify_capsule(path: Path) -> bool:
    cap = load_capsule(path)

    # Basic schema checks
    if cap.get("schema") != "capsule.v0":
        raise ValueError("Unsupported schema.")
    required = ["capsule_id", "created_at", "author", "payload_sha256", "payload_b64", "public_key_pem", "signature_b64", "signature_over"]
    for k in required:
        if k not in cap:
            raise ValueError(f"Missing field: {k}")

    payload = b64d(cap["payload_b64"])
    recomputed_payload_sha = sha256_bytes(payload)
    if recomputed_payload_sha != cap["payload_sha256"]:
        raise ValueError("Payload hash mismatch: capsule payload was altered or corrupted.")

    # Recompute capsule_id deterministically
    parent_id = cap.get("parent_id") or None
    recomputed_capsule_id = compute_capsule_id(
        cap["payload_sha256"],
        cap["created_at"],
        cap["author"],
        parent_id
    )
    if recomputed_capsule_id != cap["capsule_id"]:
        raise ValueError("Capsule ID mismatch: identity fields altered.")

    # Verify signature
    pub = load_public_key_from_pem(cap["public_key_pem"].encode("utf-8"))
    sig = b64d(cap["signature_b64"])

    sign_fields = cap["signature_over"]
    # Ensure the signature_over matches expected canonical identity fields
    expected_sign_fields = {
        "schema": "capsule.v0",
        "capsule_id": cap["capsule_id"],
        "payload_sha256": cap["payload_sha256"],
        "created_at": cap["created_at"],
        "author": cap["author"],
        "parent_id": cap.get("parent_id") or "",
    }
    if sign_fields != expected_sign_fields:
        raise ValueError("signature_over fields mismatch: capsule metadata was altered.")

    pub.verify(sig, canonical_message(sign_fields))
    return True

def inspect_capsule(path: Path) -> None:
    cap = load_capsule(path)
    print(f"schema:       {cap.get('schema')}")
    print(f"capsule_id:   {cap.get('capsule_id')}")
    print(f"author:       {cap.get('author')}")
    print(f"created_at:   {cap.get('created_at')}")
    print(f"parent_id:    {cap.get('parent_id')}")
    print(f"payload_sha:  {cap.get('payload_sha256')}")
    payload_len = len(b64d(cap.get("payload_b64", ""))) if cap.get("payload_b64") else 0
    print(f"payload_size: {payload_len} bytes")

def cmd_seal(args: argparse.Namespace) -> None:
    out = seal_file(Path(args.input), Path(args.output) if args.output else None, args.author, args.parent_id)
    print(f"Sealed -> {out}")

def cmd_verify(args: argparse.Namespace) -> None:
    try:
        verify_capsule(Path(args.capsule))
        print("VALID ✅")
    except Exception as e:
        print("INVALID ❌")
        print(f"Reason: {e}")
        sys.exit(1)

def cmd_fingerprint(args: argparse.Namespace) -> None:
    cap = load_capsule(Path(args.capsule))
    cid = cap.get("capsule_id")
    if not cid:
        print("Missing capsule_id", file=sys.stderr)
        sys.exit(1)
    print(cid)

def cmd_extract(args: argparse.Namespace) -> None:
    cap_path = Path(args.capsule)

    try:
        cap = load_capsule(cap_path)

        # Verify first unless --no-verify
        if not args.no_verify:
            verify_capsule(cap_path)

        payload = b64d(cap["payload_b64"])

        out_path = Path(args.output) if args.output else None
        if out_path is None:
            out_path = cap_path.with_suffix(cap_path.suffix + ".payload")

        out_path.write_bytes(payload)
        print(f"Extracted -> {out_path}")

    except Exception as e:
        print("INVALID ❌")
        print(f"Reason: {e}")
        sys.exit(1)

def cmd_key_export(args: argparse.Namespace) -> None:
    ensure_keys()
    dest = Path(args.dir) if args.dir else Path.cwd()
    dest.mkdir(parents=True, exist_ok=True)

    pub_src = DEFAULT_PUB
    priv_src = DEFAULT_PRIV

    pub_dst = dest / "ed25519_public.pem"
    priv_dst = dest / "ed25519_private.pem"

    pub_dst.write_bytes(pub_src.read_bytes())
    print(f"Exported public key -> {pub_dst}")

    if args.include_private:
        priv_dst.write_bytes(priv_src.read_bytes())
        print(f"Exported PRIVATE key -> {priv_dst}")
        print("WARNING: Keep this private key secret. Anyone with it can sign as you.", file=sys.stderr)

def cmd_key_import(args: argparse.Namespace) -> None:
    src_priv = Path(args.private_key)
    if not src_priv.exists():
        print(f"Private key not found: {src_priv}", file=sys.stderr)
        sys.exit(1)

    # Load + validate it’s a real Ed25519 private key
    priv = serialization.load_pem_private_key(src_priv.read_bytes(), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        print("That private key is not an Ed25519 key.", file=sys.stderr)
        sys.exit(1)

    pub = priv.public_key()

    KEY_DIR.mkdir(parents=True, exist_ok=True)

    # Write private
    DEFAULT_PRIV.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    # Write public
    DEFAULT_PUB.write_bytes(
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    print(f"Imported PRIVATE key -> {DEFAULT_PRIV}")
    print(f"Derived & wrote public key -> {DEFAULT_PUB}")
    print("WARNING: Anyone with your private key can sign as you. Store it securely.", file=sys.stderr)

def cmd_inspect(args: argparse.Namespace) -> None:
    inspect_capsule(Path(args.capsule))

def cmd_branch(args: argparse.Namespace) -> None:
    parent = load_capsule(Path(args.parent_capsule))
    parent_id = parent.get("capsule_id")
    if not parent_id:
        raise ValueError("Parent capsule missing capsule_id.")
    out = seal_file(Path(args.new_file), Path(args.output) if args.output else None, args.author, parent_id)
    print(f"Branched from {parent_id}\nNew -> {out}")

def main() -> None:
    p = argparse.ArgumentParser(prog="capsule", description="Capsule MVP CLI (authenticity + integrity + lineage)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("seal", help="Seal a file into a capsule")
    s1.add_argument("input", help="Path to input file")
    s1.add_argument("--author", required=True, help="Author name/handle (e.g., Chris)")
    s1.add_argument("--output", help="Output capsule path (default: <input>.cap)")
    s1.add_argument("--parent-id", help="Optional parent capsule_id for lineage")
    s1.set_defaults(func=cmd_seal)

    s2 = sub.add_parser("verify", help="Verify a capsule offline")
    s2.add_argument("capsule", help="Path to .cap file")
    s2.set_defaults(func=cmd_verify)

    s3 = sub.add_parser("inspect", help="Print capsule metadata")
    s3.add_argument("capsule", help="Path to .cap file")
    s3.set_defaults(func=cmd_inspect)

    s4 = sub.add_parser("branch", help="Create a new capsule referencing a parent capsule")
    s4.add_argument("parent_capsule", help="Path to parent .cap file")
    s4.add_argument("new_file", help="Path to new file content for the child capsule")
    s4.add_argument("--author", required=True, help="Author name/handle (e.g., Chris)")
    s4.add_argument("--output", help="Output capsule path (default: <new_file>.cap)")
    s4.set_defaults(func=cmd_branch)

    s_fp = sub.add_parser("fingerprint", help="Print capsule_id only")
    s_fp.add_argument("capsule", help="Path to .cap file")
    s_fp.set_defaults(func=cmd_fingerprint)

    s_ex = sub.add_parser("extract", help="Extract payload from a capsule")
    s_ex.add_argument("capsule", help="Path to .cap file")
    s_ex.add_argument("--output", help="Output file path (default: <capsule>.payload)")
    s_ex.add_argument("--no-verify", action="store_true", help="Skip verification before extracting")
    s_ex.set_defaults(func=cmd_extract)

    s_key = sub.add_parser("key", help="Key management (import/export)")
    key_sub = s_key.add_subparsers(dest="keycmd", required=True)

    s_kexp = key_sub.add_parser("export", help="Export public key (and optionally private key)")
    s_kexp.add_argument("--dir", help="Destination directory (default: current directory)")
    s_kexp.add_argument("--include-private", action="store_true", help="Also export private key (DANGEROUS)")
    s_kexp.set_defaults(func=cmd_key_export)

    s_kimp = key_sub.add_parser("import", help="Import an Ed25519 private key PEM (overwrites local keypair)")
    s_kimp.add_argument("private_key", help="Path to ed25519_private.pem")
    s_kimp.set_defaults(func=cmd_key_import)

    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
