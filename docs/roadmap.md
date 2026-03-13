# DLOS Protocol Roadmap

This roadmap outlines the expected areas of development for the
Digital Lineage Object Standard (DLOS).

The roadmap focuses on evolution of the protocol and reference
tooling rather than any specific application implementation.

---

## Phase 0 — Foundational Object Model (Current)

- DLOS object container
- Self-authenticating artifact structure
- Payload hashing
- Signature verification
- Parent lineage reference
- Reference implementation (`capsule.py`)

This phase establishes the core object architecture and
verification model.

---

## Phase 1 — Developer Tooling

Improving the usability of the protocol for developers.

Planned areas of exploration include:

- CLI tooling improvements
- Object inspection utilities
- Object verification commands
- Language SDK exploration
- Example integration patterns

---

## Phase 2 — Identity Layer (Exploratory)

Optional identity objects that may reference signing keys
without altering artifact self-verifiability.

The goal of this layer is to allow identity continuity across
multiple objects while preserving the independence of each
artifact.

Identity mechanisms are not required for basic protocol
operation.

---

## Phase 3 — Continuity Profiles

Profiles that apply the core object model to specific domains
where long-term artifact continuity is important.

Examples include:

- archival preservation
- research artifacts
- family continuity trees
- institutional records

These profiles extend the protocol through usage conventions
rather than changes to the core architecture.

---

## Phase 4 — Implementation Ecosystem

Independent tools and systems may emerge that implement
or build upon the DLOS protocol.

Examples of potential implementation areas include:

- artifact creation tools
- verification utilities
- artifact registries
- archive systems
- lineage exploration interfaces

These systems are not part of the protocol itself and may
evolve independently.
