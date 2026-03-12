# Related Work

Digital Lineage Objects (DLOS) intersect with several areas of
computer science and digital preservation. While the architecture
combines elements from multiple traditions, it takes a distinct
approach by embedding identity, integrity, and lineage directly
within the artifact container itself.

The following systems and standards explore related concepts.

---

## Content-Addressed Storage

Systems such as Git and IPFS introduced the idea that digital
objects can be identified by cryptographic hashes derived from
their contents.

Examples include:

- Git — distributed version control using content-addressed objects
- IPFS — peer-to-peer storage network using content identifiers (CID)

These systems provide strong guarantees of data integrity and
deduplication.

Digital Lineage Objects build on similar cryptographic principles
but extend them by embedding artifact lineage and authorship
information directly inside the object container.

---

## Artifact Provenance and Supply Chain Integrity

Recent work in software supply-chain security has focused on
verifiable provenance for build artifacts.

Examples include:

- Sigstore
- in-toto
- SLSA (Supply-chain Levels for Software Artifacts)

These systems attach signatures and attestations to artifacts
to verify their origin and build process.

Digital Lineage Objects pursue a related goal but focus on
general digital artifacts rather than software builds. The
artifact itself carries lineage references that connect it to
its predecessors.

---

## Decentralized Identity Systems

Digital identity frameworks explore portable identity records
that can exist independently of centralized platforms.

Examples include:

- W3C Decentralized Identifiers (DID)
- Verifiable Credentials (VC)

These systems provide mechanisms for representing identities
and credentials.

Digital Lineage Objects may optionally reference identity
objects, but the core artifact model does not require identity
infrastructure in order to verify artifact authenticity.

---

## Archival Provenance Models

Libraries, archives, and museums maintain provenance records
for cultural artifacts. These systems track the origin and
custodial history of physical objects.

Archival science often relies on principles such as:

- provenance
- custodial lineage
- record groups
- context preservation

Digital Lineage Objects adapt these ideas to the digital
environment by allowing artifacts themselves to carry
their historical relationships.

---

## Distinguishing Characteristics

The key distinction of the DLOS model is that the artifact
itself becomes the primary carrier of authenticity and
lineage.

Instead of relying on external platforms or registries,
each object contains the information necessary to verify:

- its integrity
- its authorship
- its relationship to prior artifacts

This approach aims to create digital artifacts that retain
their meaning and authenticity across changing technological
environments.

---

## Related Concepts
Various systems have attempted to represent provenance and ownership
of digital artifacts. Some approaches rely on external ledgers or
token systems that reference digital files stored elsewhere.

While these systems may record claims about artifacts, the artifact
itself often remains separate from the mechanism that records those
claims.

Digital Lineage Objects take a different approach: the artifact
itself carries its identity, integrity proof, and lineage
information directly within the object container.

In this model, provenance and authenticity travel with the artifact
rather than being maintained by an external platform, ledger, or
registry. This allows artifacts to retain meaning and verifiability
across changing systems and technologies.
