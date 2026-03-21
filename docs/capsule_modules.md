# Capsule Modules

## Overview

Capsule Modules define how additional behavior, rules, and system
capabilities can be composed around the core Capsule object model.

They enable capsules to carry extended functionality while preserving
the neutrality and integrity of the underlying protocol.

Capsule Modules are modular, composable, and optional.

---

## Core Principle

Capsules define identity and integrity.

Modules define behavior.

Systems interpret behavior.

---

## Module Philosophy

The Capsule system is designed to remain minimal at its core.

All extended functionality is introduced through modules rather than
embedded directly into the protocol.

This ensures:

- protocol stability
- long-term adaptability
- composability
- system neutrality

---

## Module Layers

Capsule Modules exist across primary layers (only one is disclose at this time).

---

### Behavior Modules (Object Layer)

Behavior Modules are embedded directly inside a capsule.

They define how a capsule behaves when interpreted by a system.

If present, they are part of the capsule’s canonical data and must be
included in identity derivation and signature verification.

---

#### Characteristics

- embedded within the capsule
- self-verifiable
- signed as part of the object
- portable across systems
- immutable once sealed

---

#### Examples

- economics (value flow)
- access
- attestation data

---

#### Rule

If a module is inside a capsule, it must be verifiable.

---

## Module Independence

Modules are independent of one another.

- Capsules do not require modules to remain valid.
- Modules may be added or removed without breaking the core object.
- Systems may choose which modules to support.

---

## Optionality

All modules are optional.

A capsule without modules remains a valid capsule.

Modules enhance behavior but are not required for identity or integrity.

---

## Composition Model

Multiple modules may coexist within a single capsule.

Example:

```json
{
  "economics": { ... },
  "access": { ... },
  "attestation": { ... }
}
