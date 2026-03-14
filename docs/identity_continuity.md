# Identity Continuity

Digital identities must remain stable across long periods of time.
Cryptographic keys may be rotated, algorithms may evolve, and systems
that reference identities may change.

The DLOS identity model addresses this challenge by treating identity
records as capsules that can evolve while preserving historical
continuity.

This section describes how identity capsules can remain durable across
decades or generations.

---

# Identity as an Artifact

In the DLOS protocol, identity is represented as an artifact rather than
as an account or registry entry.

An **identity capsule** contains a declaration linking a public key to an
identity statement.

Because the identity itself is stored as a capsule, it inherits the same
properties as all DLOS objects:

- self-verifiability
- cryptographic integrity
- portable storage
- platform independence

Identity therefore becomes a durable artifact rather than a record tied
to a specific system.

---

# Key Rotation

Cryptographic keys may need to be replaced over time.

Reasons include:

- key compromise
- key loss
- algorithm migration
- operational changes

Rather than modifying an existing identity capsule, a new identity
capsule may be created referencing the previous identity.

Example:

identity_v1
↓
identity_v2
↓
identity_v3


Each successor identity capsule may include a reference to the previous
identity capsule.

This creates a verifiable identity lineage.

Artifacts created with earlier keys remain valid because the identity
continuity chain can be followed.

---

# Identity Lineage

Identity capsules may form lineage chains similar to artifact lineage.

Example:

identity_root
↓
identity_update
↓
identity_rotation


Each capsule may contain fields such as:

- `current_key`
- `previous_keys`
- `previous_identity`
- `successor_identity`

These references allow identity transitions without breaking historical
verification.

---

# Algorithm Migration

Cryptographic algorithms evolve over time.

An identity capsule lineage allows migration to new algorithms without
invalidating historical artifacts.

Example transition:

Ed25519 identity capsule
↓
future algorithm identity capsule


Because each identity capsule references the previous identity, the
continuity of authorship remains intact.

---

# Identity Attestations

Institutions or collaborators may publish **attestation capsules**
referencing identity capsules.

Examples include:

- institutional affiliation confirmation
- archival verification
- research authorship confirmation
- curator authentication

These attestations strengthen trust in an identity without requiring a
central issuing authority.

---

# Long-Term Preservation

Identity capsules are designed to remain valid even when external
systems disappear.

Verification requires only:

- the capsule itself
- the embedded public key
- the signature verification algorithm

Identity therefore remains verifiable even if:

- websites disappear
- institutions change
- platforms shut down
- registries are lost

---

# Recommended Practices

For long-term identity durability, authors should consider:

- storing identity capsules in multiple archives
- publishing capsule identifiers in public records
- maintaining identity continuity through successor capsules
- preserving private keys in secure storage

These practices increase the likelihood that identity capsules remain
discoverable and verifiable over long periods.

---

# Summary

Identity continuity in DLOS is achieved through artifact lineage rather
than centralized identity authorities.

By representing identity as a series of linked capsules, the protocol
allows identities to evolve while preserving the historical authenticity
of artifacts created in the past.

This approach ensures that authorship remains durable across time,
systems, and generations.
