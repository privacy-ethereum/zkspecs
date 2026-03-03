---
slug: 5
title: 5/ZK-HUMAN-VERIFICATION
name: ZK-based Human Verification for BBS
status: raw
category: Standards Track
tags: zero-knowledge, identity, privacy, anonymous-credentials, human-verification
editor: Nicole <cc03668@users.noreply.github.com>
contributors:
  - zkmopro <https://github.com/zkmopro>
---

# Change Process

This document is governed by the [1/COSS](https://github.com/privacy-ethereum/zkspecs/tree/main/specs/1) (COSS).

# Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

# Abstract

BBS Human Verification is a privacy-preserving protocol that allows a user to prove possession of a valid issuer-signed credential and obtain a one-time "verified human" status on a BBS platform without disclosing credential attributes.

The protocol prevents duplicate verification via a deterministic nullifier and supports two verifier deployments:
(1) off-chain verification by a BBS backend; and
(2) an on-chain registry variant that publicly records nullifier usage.

This version (v0.1) enforces one verification per credential instance. If the credential is periodically renewed and renewal modifies the credential contents, the user MAY be able to verify again (known limitation).

# Motivation

Online communities and BBS-style platforms often require human verification to reduce Sybil attacks and automated abuse. Traditional verification methods require revealing personal information to the platform.

This specification defines a primitive that separates eligibility verification (possession of a valid credential) from identity disclosure by using a zero-knowledge proof.

# Specification

## System Requirements

Implementations MUST provide:

### 1. Credential Model

A credential `S` is a structured message containing attributes `m` and an issuer signature `σ`.

The issuer public key `PK_I` MUST be available to verifiers via one of:
- hardcoded trust anchor(s),
- a platform-managed allowlist, or
- an on-chain key registry (see [On-Chain Registry Variant](#on-chain-registry-variant)).

The credential type MUST be representable as `cred_scope` and MUST be derivable from `m` via `Type(m)`.

### 2. Challenge (Anti-replay)

Verifiers MUST provide a 256-bit `challenge` value per verification attempt.

- Challenges MUST be unpredictable.
- Challenges MUST expire (implementation-defined).
- Verifiers MUST reject proofs bound to expired challenges.

### 3. Nullifier

The protocol MUST output a deterministic nullifier to prevent duplicate verification.

In v0.1, the nullifier is derived from credential contents:


nullifier := H( Encode(app_id) || Encode(cred_scope) || Encode(S) )


Where:
- `app_id` is a platform identifier (domain separator),
- `cred_scope` is a credential type identifier,
- `H` is a hash function defined in [Cryptographic Primitives](#cryptographic-primitives).

Each platform MUST use a unique `app_id`.

## Cryptographic Primitives

This specification defines:

- Hash function: `H = SHA-256`.
- Signature verification: `VerifySig(PK, msg, σ) -> {0,1}`.
- Encoding: `Encode()` is a deterministic canonical encoding function.

Concatenation MUST be length-prefixed (e.g., `len(x)||x||len(y)||y||...`) to avoid ambiguity.

## Protocol Flow

Implementations MUST:

1. Obtain `challenge`, `app_id`, and `cred_scope` from the verifier context.
2. Construct circuit inputs from the credential `S` and signature `σ`.
3. Generate a proof for the statement in [Circuit Design](#circuit-design).
4. Submit the proof and public inputs to the verifier.

## Circuit Design

### Private Inputs

- `S`: Credential message.
- `σ`: Issuer signature over `S`.
- `m`: Attributes parsed from `S` such that `Parse(S) = m`.

### Public Inputs

- `challenge: bytes32`
- `app_id: <encoded string>`
- `cred_scope: <encoded string>`
- `nullifier: bytes32`

### Circuit Operations

The circuit MUST enforce:

1. **Issuer signature verification**


isValid := VerifySig(PK_I, Encode(S), σ)
assert(isValid == 1)


2. **Credential parsing**


Parse(S) = m


3. **Credential type constraint**


assert(Type(m) == cred_scope)


4. **Nullifier derivation**


nullifier := SHA256( Encode(app_id) || Encode(cred_scope) || Encode(S) )


5. **Challenge binding**

The proof MUST bind to `challenge` as a public input.

### Outputs

- `nullifier: bytes32`

## Proof Output Format

Implementations MUST serialize proof outputs in a deterministic format.

A minimal proof object SHOULD include:

```text
{
  app_id: <string>,
  cred_scope: <string>,
  challenge: bytes32,
  nullifier: bytes32,
  proof: bytes
}
```

## Proof Verification

### Verifier MUST

- Validate the zero-knowledge proof against the public inputs.
- Validate challenge freshness (not expired).
- Enforce `app_id` and `cred_scope` match the expected policy for the verification endpoint.

### Verifier SHOULD

- Check whether the nullifier has already been used and reject duplicates.

### Verifier MAY

- Maintain a history of recently-valid challenges for resilience (implementation-defined), provided replay protection remains intact.

## Error Handling

Implementations MUST handle:

- Invalid proof
- Invalid or expired challenge

Implementations SHOULD handle:

- Duplicate nullifier

Error responses MUST include:

- Error code
- Error message
- Error details (when available)

## Interoperability Constraints

- Implementations MUST use the same `Encode()` canonicalization rules to ensure nullifier consistency across verifiers.
- Implementations MUST use the same `H` function (SHA-256) for nullifier derivation in v0.1.
- Implementations MUST agree on `cred_scope` values and how `Type(m)` is derived.

## Credential Renewal

In v0.1, the nullifier is derived from `Encode(S)`.

If the issuer renews/reissues credentials such that `S` changes, then the nullifier may change. Therefore a user MAY be able to verify again after renewal.

This is a known limitation of v0.1.

A future version MAY derive nullifiers from a renewal-stable holder secret:

```
nullifier := H( Encode(app_id) || holder_secret )
```

## On-Chain Registry Variant

In the on-chain verification mode, a smart contract MAY act as the verifier and registry.

A contract MUST maintain:

```
mapping(bytes32 => bool) nullifierUsed
```

A contract MAY additionally store `PK_I` (issuer public key) or a commitment to an issuer allowlist.

Verification procedure:

1. Verify the zero-knowledge proof.
2. Ensure `nullifierUsed[nullifier] == false`.
3. Set `nullifierUsed[nullifier] = true`.
4. Emit an event:

```
VerificationRegistered(nullifier, app_id)
```

No credential attributes MUST be stored on-chain.

# Security Considerations

## Privacy and Security Assumptions

The protocol assumes:

- The security of the proving system used (and its trusted setup requirements, if applicable).
- The unforgeability of the issuer signature scheme.
- Collision resistance of SHA-256.
- Correct and unique domain separation via `app_id`.
- Correct canonical encoding via `Encode()`.

## Privacy and Security Best Practices

- Proof generation SHOULD be performed on the user's device to reduce risk of credential exposure.
- Verifiers SHOULD minimize logging of public inputs, particularly nullifier, to reduce metadata retention.
- Deployments using the on-chain registry SHOULD use relayers or transaction sponsorship to reduce linkage between proof submissions and wallet addresses.

## Linkability

### Off-chain mode

In off-chain mode, the nullifier is only visible to the BBS platform verifier.

### On-chain mode

In on-chain mode:

- Nullifiers are publicly observable.
- Verification timing is public.
- Transaction sender addresses may be linkable.
- Domain separation via `app_id` is REQUIRED, but does not eliminate all metadata leakage.

## Known Limitations

**Renewal limitation (v0.1)**
If credential renewal changes `S`, a user MAY verify again.

**Credential sharing (v0.1)**
This version does not include device binding. Credential sharing across devices is not cryptographically prevented.

# Implementation Notes

A reference implementation MAY:

- generate proofs client-side (web or native app),
- verify proofs off-chain in a backend, and/or
- verify proofs in an EVM verifier contract for the on-chain registry variant.

Implementations SHOULD provide test vectors for:

- `Encode()` canonicalization,
- nullifier derivation,
- signature verification inputs.

# References

- [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt)
- [FIPS 180-4 (SHA-256)](https://csrc.nist.gov/publications/detail/fips/180/4/final)

# Glossary

## BBS Platform

A forum-like application that may maintain per-user status or badges.

## Credential

Issuer-signed message `S` containing attributes `m`.

## Nullifier

A deterministic value derived in zero-knowledge and used to prevent duplicate verification.

## Challenge

A verifier-provided nonce bound to the proof to prevent replay.
