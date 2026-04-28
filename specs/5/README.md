---
slug: 5
title: 5/ZK-HUMAN-VERIFICATION
name: ZK-based Human Verification for Online Forums
status: raw
category: Standards Track
tags: zero-knowledge, identity, privacy, anonymous-credentials, human-verification
editor: Nicole <nicole@ethereum.org>
contributors:
  - Moven <moven.tsai@ethereum.org>
  - Nicole <nicole@ethereum.org>
  - Vivian <vivian.jeng@ethereum.org>
---

# Change Process

This document is governed by the [1/COSS](https://github.com/privacy-ethereum/zkspecs/tree/main/specs/1) (COSS).

# Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

# Abstract

This specification defines a privacy-preserving protocol that allows a user to prove possession of a valid issuer-signed certificate and obtain a one-time "verified human" status on an online forum without disclosing certificate attributes.

The protocol prevents duplicate verification via a deterministic nullifier. Off-chain verification is the deployment mode for this version. On-chain verification was evaluated and is deferred (see [On-Chain Verification Status](#on-chain-verification-status)).

The proof generation pipeline builds on OpenAC ([paper](https://github.com/privacy-ethereum/zkID/blob/main/paper/zkID.pdf)), adopting a minimal profile: RSA certificate chain validation, nullifier-based duplicate prevention, and SMT-based revocation. Features such as unlinkability and device binding are not in scope for this version but MAY be incorporated in future revisions.

This version (v0.1) enforces one verification per certificate instance. If the certificate is periodically renewed and renewal modifies the certificate contents, the user MAY be able to verify again (known limitation).

# Motivation

Online forums often require human verification to reduce Sybil attacks and automated abuse. Traditional verification methods require revealing personal information to the platform.

This specification defines a primitive that separates eligibility verification (possession of a valid certificate) from identity disclosure by using a zero-knowledge proof.

# Specification

## System Requirements

Implementations MUST provide:

### 1. Certificate Model

A certificate `S` is a structured message containing a subject distinguished name (`subjectDN`), a subject number (`sn`), attributes `m`, and an RSA signature `σ` over the TBS (To-Be-Signed) certificate data.

- `subjectDN`: A secret unique identifier assigned by the issuing CA. Used for nullifier derivation.
- `sn` (subject number): A distinct field from `subjectDN`, used as the key for revocation lookups. The `sn` does not directly reveal the prover's identity.

The certificate MUST be issued by a trusted Certificate Authority (CA). The issuer's public key `PK_I` MUST be verifiable through a certificate chain rooted in one of:
- hardcoded trusted CA root certificates (e.g., government root CA), or
- a platform-managed CA allowlist.

The certificate chain consists of:
- `PK_CA`: The public key from the intermediate CA certificate, which signs the end-entity certificate.
- `PK_I`: The issuer (root CA) public key, which signs the intermediate CA certificate.

Implementations MUST validate that the end-entity certificate was signed by a trusted CA public key.

### 2. Revocation List

The protocol MUST support certificate revocation via a **non-inclusion proof** against a revocation accumulator.

A revocation list is maintained as a **Sparse Merkle Tree (SMT)** where each leaf corresponds to a revoked certificate identifier:

```
revoked_leaf := Poseidon( Encode(sn) )
```

A trusted party (e.g., the CA or a designated updater) MUST maintain and publish the full SMT, constructed from the CA's Certificate Revocation List (CRL) or an equivalent revocation feed. The published SMT state MUST be periodically rebuilt from the latest CRL. Only the SMT root (`revocation_root`) needs to be distributed for verification; the full tree state is distributed as a downloadable snapshot for client-side proof generation.

#### Witness Retrieval

To preserve privacy, the prover MUST generate the revocation non-inclusion witness locally. The prover MUST NOT send their `sn` to a remote service for witness retrieval.

The client-side witness retrieval flow is:

1. Download the compressed SMT snapshot to the local device.
2. Import the snapshot into a local disk-backed SMT (e.g., SQLite).
3. Generate the non-membership Merkle path (sibling hashes) for the prover's `sn` position locally.
4. Verify that the locally computed `revocation_root` matches the published reference root.
5. Use the locally generated Merkle path as the `revocation_witness` private input.
6. Clean up local SMT data after proof generation.

The `sn` MUST NOT leave the prover's device during this process.

Implementations MUST support an off-chain revocation root distributed by the CA or a trusted updater (e.g., derived from a CRL). The snapshot distribution mechanism is implementation-defined (e.g., CDN, IPFS, or a public repository).

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
- `subjectDN` is the subject distinguished name extracted from the certificate. The `subjectDN` contains a secret unique identifier assigned by the issuing CA and is not publicly available information,
- `Poseidon` is the Poseidon hash function (see [Cryptographic Primitives](#cryptographic-primitives)).

Each platform MUST use a unique `app_id`.

## Cryptographic Primitives

This specification defines:

- Hash function (data integrity): `SHA-256` for certificate TBS data hashing.
- Hash function (nullifier): `Poseidon` hash, a ZK-friendly hash function optimized for arithmetic circuits (see [circomlib Poseidon](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom)).
- Signature verification: `RSA_Verify(PK, msg, σ) -> {0,1}` — RSA signature verification over SHA-256 hashed TBS data.
- Sparse Merkle Tree non-inclusion: `SMT_NonInclusion(root, leaf, proof) -> {0,1}` — verifies that `leaf` is **not** present in the SMT committed to by `root` (see [PSE: Revocation in zkID](https://pse.dev/blog/revocation-in-zkid-merkle-tree-based-approaches)).
- Encoding: `Encode()` is a deterministic canonical encoding function using base64 encoding. All implementations MUST use the same base64 encoding variant (standard alphabet, with padding) to ensure consistent nullifier derivation across verifiers.

Concatenation MUST be length-prefixed (e.g., `len(x)||x||len(y)||y||...`) to avoid ambiguity.

## Recommended Parameters

### RSA

- Key size: RSA-2048
- Padding scheme: PKCS#1 v1.5
- Hash algorithm: SHA-256

### Poseidon Hash

- Implementation: [circomlib Poseidon](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom)
- Field: BN254 scalar field
- Implementations MUST use consistent round parameters (t, number of full/partial rounds) across all parties.

### Proving System

- Spartan2 with Hyrax polynomial commitment scheme. This is a transparent proving system (no trusted setup required).

On-chain verification is not supported in this version. See [On-Chain Verification Status](#on-chain-verification-status) for the research summary and rationale.

## Protocol Flow

Implementations MUST:

1. Obtain `challenge`, `app_id`, and the current `revocation_root` from the verifier context.
2. Download the SMT snapshot and generate the revocation non-inclusion witness locally (see [Witness Retrieval](#witness-retrieval)). Verify that the locally computed root matches the published `revocation_root`.
3. Construct circuit inputs from the certificate `S`, RSA signature `σ`, trusted CA public keys, and the locally generated revocation witness.
4. Generate a proof for the statement in [Circuit Design](#circuit-design).
5. Submit the proof and public inputs to the verifier.

## Circuit Design

### Private Inputs

- `S`: Certificate message (certificate data).
- `σ`: RSA signature over the TBS (To-Be-Signed) data.
- `subjectDN`: Subject distinguished name extracted from `S`.
- `sn`: Subject number extracted from `S`, used for revocation lookup.
- `PK_cert`: Public key extracted from the end-entity certificate, used to verify the certificate was issued by the intermediate CA (`PK_CA`).
- `revocation_witness`: SMT non-inclusion proof (Merkle path of sibling hashes) for the prover's `sn`, generated locally from a downloaded SMT snapshot (see [Witness Retrieval](#witness-retrieval)).

### Public Inputs

- `challenge: bytes32`
- `app_id: <encoded string>`
- `nullifier: bytes32`
- `PK_CA`: Trusted CA public key from intermediate CA.
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

Prove the certificate has not been revoked:

```
revoked_id := Poseidon( Encode(sn) )
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
  pk_ca: list<string>,
  proof: bytes
}
```

## Proof Verification

### Verifier MUST

- Validate the zero-knowledge proof against the public inputs.
- Validate challenge freshness (not expired).
- Enforce `app_id` matches the expected policy for the verification endpoint.
- Validate that `revocation_root` matches the latest known revocation tree root (from the CA's CRL or a trusted updater).
- Check whether the nullifier has already been used and reject duplicates.
- Persist nullifier state durably (i.e., nullifier rejection MUST survive verifier restarts).

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

- Implementations MUST use the same `Encode()` canonicalization rules (base64, standard alphabet, with padding) to ensure nullifier consistency across verifiers.
- Implementations MUST use the same Poseidon hash configuration (circomlib, BN254 scalar field) for nullifier derivation.
- Implementations MUST use the same RSA verification parameters (RSA-2048, PKCS#1 v1.5, SHA-256) for certificate chain validation.
- Implementations MUST use the same SMT depth and hash configuration for revocation non-inclusion proofs.

## Certificate Renewal

The nullifier is derived from `subjectDN`, which is stable across certificate renewals as long as the subject identity remains the same.

If the issuer renews/reissues certificates such that `subjectDN` changes, then the nullifier will change. Therefore a user MAY be able to verify again after renewal with a different `subjectDN`.

A future version MAY derive nullifiers from a renewal-stable holder secret:

```
nullifier := Poseidon( Encode(app_id || holder_secret) )
```

## On-Chain Verification Status

On-chain verification was a design goal for this protocol (trustless nullifier registry, public verifiability). Extensive research and implementation work was conducted to evaluate feasibility. This section documents the findings and the rationale for deferring on-chain verification in this version.

OpenAC has three core properties that MUST NOT be compromised:

1. **Rerandomizable proofs** — required for unlinkability across presentations.
2. **Transparent setup** — no trusted setup ceremony required.
3. **Zero knowledge** — no credential attributes disclosed.

The circuit size is ~2^20 constraints. The current design uses Spartan2 with Hyrax PCS over the T256 (secp256r1) curve. No EVM chain provides native T256 ecAdd/ecMul precompiles; RIP-7212 / EIP-7951 exposes only `ECDSA.verify(hash, r, s, x, y)`, which cannot be used for the arbitrary curve arithmetic that Hyrax and IPA require.

### Approaches Evaluated

**1. Native Rust Verifier.** A self-contained Spartan2 verifier was built in Rust, independent of any external proving infrastructure. This serves as the foundation for off-chain verification and was used to validate subsequent on-chain approaches.

**2. SP1 Wrapper.** The native verifier was wrapped inside SP1 to generate a succinct proof of verification. This direction was abandoned due to: (a) no T256 precompiles available in SP1, (b) prohibitive credit cost (~44 credits per proof), and (c) no provers accepting jobs at the required resource limits. Cost scales proportionally with complexity, making this economically unviable.

**3. L2 Landscape Investigation.** All major L2s were surveyed for P-256 curve arithmetic support:

| Chain | RIP-7212 (Sig Verify) | P-256 ecAdd/ecMul | Useful for Spartan2? |
| --- | --- | --- | --- |
| Arbitrum | Yes | No | Yes, via Stylus |
| Optimism/Base | Yes | No | No |
| zkSync Era | Yes | No | No |
| Polygon PoS | Yes | No | No |
| Scroll/Linea | Partial | No | No |

No L2 currently provides the general-purpose P-256 curve arithmetic required. The only viable path is Arbitrum Stylus, which runs a WASM VM alongside the EVM with ~10–100x cheaper compute for cryptographic operations.

**4. Groth16 with the same R1CS circuits.** Reuse existing circuits, add a per-circuit trusted setup. Cheapest on-chain cost (~$0.003), but breaks transparent setup.

**5. Spartan2 + SPARK (native Solidity verifier).** SPARK preprocessing eliminates matrix storage but barely reduces per-verification gas (~3.7% savings). Estimated cost: ~200M gas on Arbitrum (~$20) for 2^20 constraints. Prohibitively expensive because every T256 curve operation runs as Solidity bytecode.

**6. Spartan2 + SPARK + WHIR.** Replace Hyrax PCS with WHIR (hash-based PCS). Cheaper verification (~$0.03–$0.93 batched), but WHIR is not additively homomorphic — breaks rerandomizable proofs.

**7. Spartan2 → Groth16 wrapper.** Verify the Spartan proof inside a Groth16 circuit. Cheap on-chain verification, but reintroduces trusted setup and adds 30–120s prover overhead.

**8. Spartan2 + KZG.** Replace Hyrax with KZG (e.g., HyperKZG). Cheap on-chain verification (~$0.01–$0.05), preserves rerandomization and ZK, but requires trusted setup / universal SRS.

**9. Arbitrum Stylus Verifier (Rust → WASM).** A fully self-contained Spartan2 verifier was built targeting Stylus with custom T256 field and curve arithmetic, no external crypto dependencies, compiled to WASM, and deployed on Arbitrum Sepolia ([0xfcd5fc2da39f4dc822835f99b5a70d12e32b24fd](https://sepolia.arbiscan.io/address/0xfcd5fc2da39f4dc822835f99b5a70d12e32b24fd#code)). This preserves all three core properties. However, it is currently blocked: Stylus caps contracts at 24 KB brotli-compressed (current build is ~349 KB uncompressed), and RPC clients reject the ~100 KB calldata required for proof submission.

### Summary

| Option | Transparent Setup | Rerandomizable | ZK | On-Chain Cost | Status |
| --- | --- | --- | --- | --- | --- |
| Groth16 | No | Yes | Yes | ~$0.003 | Breaks transparent setup |
| Spartan2 + SPARK (Solidity) | Yes | Yes | Yes | ~$20 | Prohibitively expensive |
| Spartan2 + SPARK + WHIR | Yes | No | Yes | ~$0.03–$0.93 | Breaks rerandomization |
| Spartan2 → Groth16 wrapper | No | Yes | Yes | ~$0.003 | Breaks transparent setup |
| Spartan2 + KZG | No | Yes | Yes | ~$0.01–$0.05 | Breaks transparent setup |
| SP1 wrapper | Yes | Yes | Yes | N/A | Economically unviable |
| Arbitrum Stylus | Yes | Yes | Yes | TBD | Blocked (contract size + calldata) |

Only two options preserve all three core properties: Spartan2 + SPARK as a Solidity contract (prohibitively expensive) and Arbitrum Stylus (blocked on contract size and calldata limits). Every other option compromises at least one core property.

### Conclusion

On-chain verification is deferred for this version. Off-chain verification via Spartan2 with Hyrax PCS is the only conformance mode. A future version MAY revisit on-chain verification if the Stylus size blocker is resolved or if L2s add native P-256 curve arithmetic precompiles.

For the full research details, see [Exploring Spartan2 Proofs for On-Chain Verification](https://github.com/zkmopro/zkID/blob/main/wallet-unit-poc/onchain-research.md).

# Security Considerations

## Privacy and Security Assumptions

The protocol assumes:

- The security of Spartan2 with Hyrax polynomial commitment scheme (transparent setup — no trusted setup required).
- The unforgeability of the RSA signature scheme (RSA-2048, PKCS#1 v1.5) used for certificate signing.
- Collision resistance of SHA-256 (for TBS hashing) and Poseidon (for nullifier derivation and revocation leaf computation).
- Correct and unique domain separation via `app_id`.
- Correct canonical encoding via `Encode()` (base64, standard alphabet, with padding).
- Freshness of the revocation SMT snapshot (i.e., the snapshot reflects the latest CRL published by the CA). The prover downloads the snapshot locally and verifies the computed root against a published reference root. Freshness depends on the snapshot distribution frequency.
- The `subjectDN` contains a secret unique identifier not publicly available; if `subjectDN` were guessable, an adversary could compute nullifiers for targeted users.

## Privacy and Security Best Practices

- Proof generation SHOULD be performed on the user's device to reduce risk of certificate exposure.
- Revocation witness generation MUST be performed locally on the user's device (see [Witness Retrieval](#witness-retrieval)).
- Verifiers SHOULD minimize logging of public inputs, particularly nullifier, to reduce metadata retention.

## Linkability

The nullifier is only visible to the forum platform verifier. Domain separation via `app_id` is REQUIRED to prevent cross-platform nullifier correlation.

## Revocation Witness Privacy

Client-side witness generation (see [Witness Retrieval](#witness-retrieval)) ensures that the prover's `sn` never leaves the device. This eliminates the metadata leakage risk present in server-side witness retrieval models, where the server would learn which `sn` is being checked.

The prover downloads the full SMT snapshot, which is a public dataset derived from the CA's CRL. Downloading the snapshot does not reveal which certificate the prover holds.

## Revocation Freshness

There is an inherent delay between a CA revoking a certificate (publishing a new CRL), the SMT snapshot being rebuilt, and the prover downloading the updated snapshot. During this window, a revoked certificate can still produce valid proofs.

- Verifiers SHOULD define a maximum acceptable `revocation_root` age.
- Snapshot publishers SHOULD include the CRL publication timestamp alongside the `revocation_root`.
- Provers SHOULD download the latest available snapshot before each verification attempt.

## Known Limitations

**Renewal limitation (v0.1)**
If certificate renewal changes `subjectDN`, a user MAY verify again.

**Certificate sharing (v0.1)**
This version does not include device binding. Certificate sharing across devices is not cryptographically prevented.

**Revocation latency (v0.1)**
The revocation SMT snapshot update is not real-time. The window between CRL publication and snapshot rebuild depends on the update mechanism (manual, automated). During this window, revoked certificates remain usable.

**On-chain verification (v0.1)**
On-chain verification is deferred for this version. See [On-Chain Verification Status](#on-chain-verification-status) for the full rationale.

# Implementation Notes

A reference implementation is available at [zkID](https://github.com/zkmopro/zkID). Implementation tasks and progress are tracked at [ZK-based-Human-Verification](https://github.com/zkmopro/ZK-based-Human-Verification/issues).

The current implementation includes:

- **Mobile native bindings** (iOS / Android) via [mopro-ffi](https://github.com/zkmopro/mopro), enabling client-side proof generation on mobile devices.
- **Mobile proof generation flow** integrated with the [Ptt-iOS](https://github.com/Ptt-official-app/Ptt-iOS) and [Ptt-Android](https://github.com/Ptt-official-app/Ptt-Android) forum apps.
- **WASM browser proof generation** via mopro, enabling client-side proof generation in web apps.
- **Server backend verification** with OpenAC verification logic ported from Rust to Go for the BBS server backend.
- **Client-side SMT revocation** with local snapshot download and local non-inclusion proof generation (see [Witness Retrieval](#witness-retrieval)).

Implementations SHOULD provide test vectors for:

- `Encode()` canonicalization,
- nullifier derivation,
- signature verification inputs,
- SMT non-inclusion proof generation and verification.

# References

- [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt)
- [FIPS 180-4 (SHA-256)](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [Poseidon Hash (circomlib)](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom)
- [OpenAC (paper)](https://github.com/privacy-ethereum/zkID/blob/main/paper/zkID.pdf)
- [ZK Circuit Specification for Human Verification (prior art)](https://github.com/zkmopro/ZK-based-Human-Verification/issues/3)
- [Revocation in zkID: Merkle Tree Based Approaches (PSE)](https://pse.dev/blog/revocation-in-zkid-merkle-tree-based-approaches)
- [MOICA Certificate Revocation List](https://moica.nat.gov.tw/del.html)
- [Client-side SMT proof generation for revocation privacy](https://github.com/zkmopro/ZK-based-Human-Verification/issues/16)
- [Exploring Spartan2 Proofs for On-Chain Verification](https://github.com/zkmopro/zkID/blob/main/wallet-unit-poc/onchain-research.md)

# Glossary

## Certificate

A CA-signed certificate `S` containing a subject distinguished name (`subjectDN`), attributes `m`, and an RSA signature `σ`.

## Nullifier

A deterministic value derived in zero-knowledge and used to prevent duplicate verification.

## Challenge

A verifier-provided nonce bound to the proof to prevent replay.

## Revocation List

A set of certificate identifiers that have been invalidated by the issuing CA, represented as a Sparse Merkle Tree for ZK-compatible non-inclusion proofs.

## Subject Number (`sn`)

A certificate field distinct from `subjectDN`, used as the key for revocation lookups. The `sn` does not directly reveal the prover's identity and is used locally to generate a non-inclusion witness from a downloaded SMT snapshot.

## Sparse Merkle Tree (SMT)

A binary Merkle trie where each element has a fixed position determined by its key. Supports efficient non-membership proofs by demonstrating that a given position is empty.

# Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
