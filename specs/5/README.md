---
slug: 5
title: 5/ZK-HUMAN-VERIFICATION
name: ZK-based Human Verification for Bulletin Board System (BBS)
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

Bulletin Board System (BBS) Human Verification is a privacy-preserving protocol that allows a user to prove possession of a valid issuer-signed credential and obtain a one-time "verified human" status on a BBS platform without disclosing credential attributes.

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

A credential `S` is a structured message containing a subject distinguished name (`subjectDN`), attributes `m`, and an RSA signature `σ` over the TBS (To-Be-Signed) certificate data.

The credential MUST be issued by a trusted Certificate Authority (CA). The issuer's public key `PK_I` MUST be verifiable through a certificate chain rooted in one of:
- hardcoded trusted CA root certificates (e.g., government root CA),
- a platform-managed CA allowlist, or
- an on-chain CA key registry (see [On-Chain Registry Variant](#on-chain-registry-variant)).

Implementations MUST validate that the end-entity certificate was signed by a trusted CA public key.

### 2. Revocation List

The protocol MUST support credential revocation via a **non-inclusion proof** against a revocation accumulator.

A revocation list is maintained as a **Sparse Merkle Tree (SMT)** where each leaf corresponds to a revoked credential identifier:

```
revoked_leaf := Poseidon( Encode(subjectDN) )
```

The SMT root (`revocation_root`) is published by the CA or a trusted updater. Provers demonstrate their credential has not been revoked by providing a non-inclusion witness against the current `revocation_root`.

Implementations MUST support at least one of:
- an off-chain revocation root distributed by the CA (e.g., derived from a CRL),
- an on-chain revocation root stored in a smart contract (see [On-Chain Registry Variant](#on-chain-registry-variant)).

### 3. Challenge (Anti-replay)

Verifiers MUST provide a 256-bit `challenge` value per verification attempt.

- Challenges MUST be unpredictable.
- Challenges MUST expire (implementation-defined).
- Verifiers MUST reject proofs bound to expired challenges.

### 4. Nullifier

The protocol MUST output a deterministic nullifier to prevent duplicate verification.

The nullifier is derived from the subject distinguished name:

```
nullifier := Poseidon( Encode(app_id || subjectDN) )
```

Where:
- `app_id` is a platform identifier (domain separator),
- `subjectDN` is the subject distinguished name extracted from the credential,
- `Poseidon` is the Poseidon hash function (see [Cryptographic Primitives](#cryptographic-primitives)).

Each platform MUST use a unique `app_id`.

## Cryptographic Primitives

This specification defines:

- Hash function (data integrity): `SHA-256` for certificate TBS data hashing.
- Hash function (nullifier): `Poseidon` hash, a ZK-friendly hash function optimized for arithmetic circuits (see [circomlib Poseidon](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom)).
- Signature verification: `RSA_Verify(PK, msg, σ) -> {0,1}` — RSA signature verification over SHA-256 hashed TBS data.
- Sparse Merkle Tree non-inclusion: `SMT_NonInclusion(root, leaf, proof) -> {0,1}` — verifies that `leaf` is **not** present in the SMT committed to by `root` (see [PSE: Revocation in zkID](https://pse.dev/blog/revocation-in-zkid-merkle-tree-based-approaches)).
- Encoding: `Encode()` is a deterministic canonical encoding function.

Concatenation MUST be length-prefixed (e.g., `len(x)||x||len(y)||y||...`) to avoid ambiguity.

## Protocol Flow

Implementations MUST:

1. Obtain `challenge`, `app_id`, and the current `revocation_root` from the verifier context.
2. Obtain a non-inclusion witness from the revocation SMT for the prover's credential identifier.
3. Construct circuit inputs from the credential `S`, RSA signature `σ`, trusted CA public keys, and the revocation witness.
4. Generate a proof for the statement in [Circuit Design](#circuit-design).
5. Submit the proof and public inputs to the verifier.

## Circuit Design

### Private Inputs

- `S`: Credential message (certificate data).
- `σ`: RSA signature over the TBS (To-Be-Signed) data.
- `subjectDN`: Subject distinguished name extracted from `S`.
- `PK_cert`: Public key extracted from the end-entity certificate.
- `revocation_witness`: SMT non-inclusion proof (sibling path and leaf preimage) for the prover's credential identifier.

### Public Inputs

- `challenge: bytes32`
- `app_id: <encoded string>`
- `nullifier: bytes32`
- `PK_CA`: Trusted CA public key(s) (root and/or intermediate CA).
- `revocation_root: bytes32`: Current root of the revocation Sparse Merkle Tree.

### Circuit Operations

The circuit MUST enforce:

1. **Certificate chain validation**

Confirm that the end-entity certificate was issued by a trusted CA:

```
isValid := RSA_Verify(PK_CA, TBS(S), σ)
assert(isValid == 1)
```

2. **Subject DN extraction**

```
subjectDN := ExtractSubjectDN(S)
```

3. **Nullifier derivation**

```
nullifier := Poseidon( Encode(app_id || subjectDN) )
```

4. **Challenge binding**

The proof MUST bind to `challenge` as a public input.

5. **Revocation non-inclusion**

Prove the credential has not been revoked:

```
revoked_id := Poseidon( Encode(subjectDN) )
assert( SMT_NonInclusion(revocation_root, revoked_id, revocation_witness) == 1 )
```

### Outputs

- `nullifier: bytes32`

## Proof Output Format

Implementations MUST serialize proof outputs in a deterministic format.

A minimal proof object SHOULD include:

```text
{
  app_id: <string>,
  challenge: bytes32,
  nullifier: bytes32,
  revocation_root: bytes32,
  proof: bytes
}
```

## Proof Verification

### Verifier MUST

- Validate the zero-knowledge proof against the public inputs.
- Validate challenge freshness (not expired).
- Enforce `app_id` matches the expected policy for the verification endpoint.
- Validate that `revocation_root` matches the latest known revocation tree root (from the CA's CRL or an on-chain registry).

### Verifier SHOULD

- Check whether the nullifier has already been used and reject duplicates.

### Verifier MAY

- Maintain a history of recently-valid challenges for resilience (implementation-defined), provided replay protection remains intact.

## Error Handling

Implementations MUST handle:

- Invalid proof
- Invalid or expired challenge
- Stale or unrecognized `revocation_root`

Implementations SHOULD handle:

- Duplicate nullifier

Error responses MUST include:

- Error code
- Error message
- Error details (when available)

## Interoperability Constraints

- Implementations MUST use the same `Encode()` canonicalization rules to ensure nullifier consistency across verifiers.
- Implementations MUST use the same Poseidon hash configuration for nullifier derivation.
- Implementations MUST use the same RSA verification parameters (key size, padding scheme) for certificate chain validation.
- Implementations MUST use the same SMT depth and hash configuration for revocation non-inclusion proofs.

## Credential Renewal

The nullifier is derived from `subjectDN`, which is stable across credential renewals as long as the subject identity remains the same.

If the issuer renews/reissues credentials such that `subjectDN` changes, then the nullifier will change. Therefore a user MAY be able to verify again after renewal with a different `subjectDN`.

A future version MAY derive nullifiers from a renewal-stable holder secret:

```
nullifier := Poseidon( Encode(app_id || holder_secret) )
```

## On-Chain Registry Variant

In the on-chain verification mode, a smart contract MAY act as the verifier and registry.

A contract MUST maintain:

```
mapping(bytes32 => bool) nullifierUsed
```

A contract MAY additionally store:
- `PK_I` (issuer public key) or a commitment to an issuer allowlist.
- `revocationRoot` (`bytes32`): the current root of the revocation SMT, updated by a trusted updater role when the CA publishes a new CRL.

Verification procedure:

1. Verify the zero-knowledge proof.
2. Ensure `nullifierUsed[nullifier] == false`.
3. Set `nullifierUsed[nullifier] = true`.
4. Emit an event:

```
VerificationRegistered(nullifier, app_id)
```

No credential attributes MUST be stored on-chain.

Implementations MUST NOT store proofs on-chain for later reuse. Each verification MUST generate a fresh proof bound to a new challenge.

# Security Considerations

## Privacy and Security Assumptions

The protocol assumes:

- The security of the proving system used (and its trusted setup requirements, if applicable).
- The unforgeability of the RSA signature scheme used for certificate signing.
- Collision resistance of SHA-256 (for TBS hashing) and Poseidon (for nullifier derivation and revocation leaf computation).
- Correct and unique domain separation via `app_id`.
- Correct canonical encoding via `Encode()`.
- Freshness of the revocation SMT root (i.e., the root reflects the latest CRL published by the CA).

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

## Revocation Freshness

There is an inherent delay between a CA revoking a credential (publishing a new CRL) and the revocation SMT root being updated. During this window, a revoked credential can still produce valid proofs.

- Verifiers SHOULD define a maximum acceptable `revocation_root` age.
- On-chain deployments SHOULD emit a `RevocationRootUpdated(bytes32 newRoot, uint256 timestamp)` event to allow verifiers to track freshness.
- Off-chain deployments SHOULD include the CRL publication timestamp alongside the `revocation_root`.

## Known Limitations

**Renewal limitation (v0.1)**
If credential renewal changes `subjectDN`, a user MAY verify again.

**Credential sharing (v0.1)**
This version does not include device binding. Credential sharing across devices is not cryptographically prevented.

**Revocation latency (v0.1)**
The revocation SMT root update is not real-time. The window between CRL publication and root update depends on the update mechanism (manual, automated, on-chain oracle). During this window, revoked credentials remain usable.

# Implementation Notes

A reference implementation MAY:

- generate proofs client-side (web or native app),
- verify proofs off-chain in a backend, and/or
- verify proofs in an EVM verifier contract for the on-chain registry variant.

Implementations SHOULD provide test vectors for:

- `Encode()` canonicalization,
- nullifier derivation,
- signature verification inputs,
- SMT non-inclusion proof generation and verification.

# References

- [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt)
- [FIPS 180-4 (SHA-256)](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [Poseidon Hash (circomlib)](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom)
- [ZK Circuit Specification for Human Verification (prior art)](https://github.com/zkmopro/ZK-based-Human-Verification/issues/3)
- [Revocation in zkID: Merkle Tree Based Approaches (PSE)](https://pse.dev/blog/revocation-in-zkid-merkle-tree-based-approaches)
- [MOICA Certificate Revocation List](https://moica.nat.gov.tw/del.html)

# Glossary

## BBS Platform

A forum-like application that may maintain per-user status or badges.

## Credential

A CA-signed certificate `S` containing a subject distinguished name (`subjectDN`), attributes `m`, and an RSA signature `σ`.

## Nullifier

A deterministic value derived in zero-knowledge and used to prevent duplicate verification.

## Challenge

A verifier-provided nonce bound to the proof to prevent replay.

## Revocation List

A set of credential identifiers that have been invalidated by the issuing CA, represented as a Sparse Merkle Tree for ZK-compatible non-inclusion proofs.

## Sparse Merkle Tree (SMT)

A binary Merkle trie where each element has a fixed position determined by its key. Supports efficient non-membership proofs by demonstrating that a given position is empty.
