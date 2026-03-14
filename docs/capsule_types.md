# Capsule Types

The DLOS protocol defines a general-purpose container format for
self-verifying digital artifacts.

All capsules share the same core object structure and verification
mechanism. Differences between capsules arise only from the **purpose
of the payload**.

Within the protocol, three conceptual capsule roles naturally emerge:

- Identity Capsules
- Artifact Capsules
- Attestation Capsules

These roles are conventions built on the core object model rather than
separate object formats.

---

# 1. Identity Capsules

Identity capsules establish a **persistent identity anchor** within the
DLOS ecosystem.

An identity capsule declares the association between a public key and an
identity statement.

Example identity payload fields may include:

- name
- description
- creation timestamp
- public key fingerprint
- identity metadata

The identity capsule is signed using the corresponding private key,
making it self-verifiable.

Other capsules may reference an identity capsule through an
`identity_id` field.

This creates a stable identity reference across multiple artifacts.

Example relationship:

identity capsule
↓
artifact capsules signed by that identity


Identity capsules may also reference successor identity capsules to
support key rotation and long-term identity continuity.

---

# 2. Artifact Capsules

Artifact capsules represent the **primary purpose of the protocol**:
durable digital artifacts.

An artifact capsule binds digital content to:

- a cryptographic identity
- a payload hash
- a creation timestamp
- an optional lineage reference

These capsules may contain any form of digital payload including:

- documents
- images
- research artifacts
- cultural records
- software artifacts
- archival materials

Artifacts may reference a parent capsule through the `parent_id`
field, forming verifiable lineage chains.

Example lineage:

artifact_v1
↓
artifact_v2
↓
artifact_v3


This allows artifacts to evolve without losing their historical
continuity.

---

# 3. Attestation Capsules

Attestation capsules provide a mechanism for **third-party verification
or endorsement**.

An attestation capsule is a signed statement referencing another
capsule.

Examples include:

- institutional verification
- archival certification
- peer review confirmation
- authorship recognition
- provenance validation

Example relationship:

artifact capsule
↓
attestation capsule signed by institution


Attestations do not alter the original artifact. They simply add
additional layers of trust or recognition.

Multiple attestations may reference the same artifact.

---

# Relationship Between Capsule Types

All capsules share the same verification model.

Identity Capsules
↓
sign Artifact Capsules
↓
Attestation Capsules may reference either


This creates a flexible artifact graph:


This creates a flexible artifact graph:

identity
↓
artifact
↓
derivative artifact
↓
attestation

Because each capsule remains independently verifiable, the system does
not require centralized registries or issuing authorities.

---

# Summary

The DLOS protocol supports a flexible artifact ecosystem built from
three simple capsule roles:

- identity capsules anchor authorship
- artifact capsules preserve digital materials
- attestation capsules provide external verification

Together these roles allow digital artifacts to maintain identity,
integrity, and lineage across systems and time without requiring
centralized infrastructure.
