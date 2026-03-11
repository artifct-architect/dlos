## Status

Experimental reference implementation  
Specification draft

DLOS defines a self-verifying digital artifact container that preserves
identity, integrity, and lineage independent of platforms or registries.

## Design Principles

1. Artifacts should be self-verifiable.
2. Identity should not depend on platforms.
3. Lineage should remain portable across systems.
4. Objects should retain meaning across time.

DLOS objects are self-verifying digital artifacts that carry their own identity, integrity proof, and lineage reference independent of any platform or blockchain.

# DLOS — Digital Lineage Object Standard

Author: Christopher J. Prater  
Year: 2026

DLOS defines a self-verifying digital object that embeds authorship, integrity, and lineage directly within the artifact itself.

The goal of DLOS is to provide durable digital artifacts that can be verified independently of centralized platforms or distributed ledger consensus.

---

## Core Concepts

A DLOS object contains:

- payload
- payload hash
- author identity
- timestamp
- parent reference (lineage)
- public key
- signature

These elements allow any artifact to verify:

- authenticity
- integrity
- authorship
- lineage

offline and without trusted intermediaries.

---

## Repository Contents

/spec
    protocol specification

/reference
    reference implementation

/examples
    sample objects

/docs
    diagrams and concept papers
