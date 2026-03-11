# DLOS Core Specification v0

A DLOS Object is a structured container that binds digital content to cryptographic identity and lineage.

## Object Fields

- schema
- object_id
- created_at
- author
- parent_id
- payload_sha256
- payload
- public_key
- signature

## Verification Rules

1. payload hash must match payload_sha256
2. object_id must be deterministically derived from identity fields
3. signature must verify using the provided public key
4. parent_id references the object lineage chain
