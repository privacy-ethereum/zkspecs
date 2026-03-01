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

This document is governed by the [1/COSS](../1) (COSS).

# Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

# Abstract

This specification defines a privacy-preserving protocol for a BBS server (the Verifier) to grant a one-time "verified human" status to a forum account (the User) without learning personally identifying information from the user's government-issued credential. The User generates a zero-knowledge proof on a client device (web or mobile app) that:

1. They hold a valid issuer-signed credential of the required type; and
2. They have not previously registered this credential with the BBS (via a nullifier); and optionally
3. The proof is bound to the current device/session (device-binding).

The Verifier checks the proof and updates its user database with a boolean `vcVerified` flag.

This protocol follows OpenAC's split between (a) an offline Prepare proof (amortized per credential) and (b) an online Show proof per presentation, with re-randomization to prevent linkability across presentations.

# Motivation

Current identity verification methods for online forums and bulletin board systems require users to expose sensitive personal data, creating privacy risks and discouraging participation. This protocol addresses the following challenges:

- **Privacy-preserving human verification**: Users can prove they hold a valid government-issued credential without revealing any personal attributes (name, ID number, date of birth, address, etc.).
- **Sybil resistance**: A nullifier mechanism prevents the same credential from being used to verify multiple accounts on the same deployment.
- **Issuer compatibility**: The protocol works with existing government credential issuance systems (e.g., Taiwan's Citizen Digital Certificate) without requiring modifications to the issuer's infrastructure.
- **Client-side proving**: All proof generation runs on user-controlled hardware (web browser or mobile device), ensuring sensitive credential data never leaves the user's device.

# Specification

## Roles

- **Issuer (I)**: Government or authorized authority that issues the credential and signs it (unmodified existing system).
- **Holder / User (U)**: Person who possesses the credential and wants BBS verification.
- **Prover (P)**: Software running on user hardware (web app or mobile app) that constructs ZK proofs.
- **Verifier / BBS Server (V)**: BBS-style service backend that verifies proofs and updates account state.

## System Requirements

Implementations MUST provide:

### 1. Credential Parsing

The credential format MAY be SD-JWT-like, JWT-wrapped, or another container, as long as:

- The prover can extract a canonical ordered attribute vector `m = (m_1 ... m_n)`.
- The issuer signature `σ_I` can be verified over an authenticated payload representation (e.g., hashes of salted claims), consistent with OpenAC's wrapper/normalization model.

### 2. Commitment Scheme

The prover commits to `m` using a binding and hiding commitment scheme `Com(m; r)`.

OpenAC's architecture uses a vector commitment (Hyrax/Pedersen-style) so that the same committed witness can be linked between the Prepare and Show proofs while keeping the credential attributes hidden.

### 3. Issuer Signature Verification in ZK

The circuit MUST verify that the credential's issuer signature is valid under a trusted issuer public key. The specific signature scheme depends on the credential system:

- For Taiwan's Citizen Digital Certificate: SHA256withRSA (OID: 1.2.840.113549.1.1.11).
- Other deployments MAY use different schemes as appropriate.

Only the end-entity certificate to intermediate CA link needs to be verified in-circuit; root CA to intermediate CA verification MAY be performed off-chain.

### 4. Nullifier Generation

A nullifier is a deterministic value derived from credential secrets and a domain separator, used to prevent duplicate registration.

```
nullifier = H(app_id || cred_scope || cred_secret)
```

Where:

- `app_id`: A domain separator for the relying party deployment. MUST be unique per deployment.
- `cred_scope`: A string constant for credential type (e.g., `"TW_CITIZENSHIP_CERT"`).
- `cred_secret`: A credential-unique secret that the prover can derive (e.g., an issuer-provided random field, or a stable attribute combined with a wallet-held salt).

The Verifier MUST store accepted nullifier values. If a submitted nullifier already exists, the Verifier MUST reject the registration attempt.

### 5. Session Challenge

The Verifier issues a fresh challenge `ch` per registration attempt. The prover includes `ch` as a public input to the Show proof. The challenge MUST be unpredictable and MUST expire.

## Protocol Flow

### Web-based Approach

1. User obtains a credential from the Issuer (e.g., via card reader or mobile certificate API).
2. Web app fetches credential data and wraps it into a VC container for proof input.
3. Web app generates ZKP (OpenAC-style) client-side using WASM.
4. Web app submits proof bundle to BBS server.
5. BBS server verifies proof and updates user record (`vcVerified = true` or `failed`).

### Mobile-based Approach

Same as above, but the prover runs inside a mobile app using native ZK bindings (e.g., mopro-ffi).

### Verifier Challenge (Step 1)

Endpoint: `GET /v1/human-verification/challenge`

Response:

```json
{
  "challenge": "<random bytes, base64>",
  "expires_at": "<timestamp>",
  "app_id": "<relying party domain separator>",
  "policy": "<statement of what is being proven>"
}
```

### Proof Submission (Step 2)

Endpoint: `POST /v1/human-verification/submit`

Request: ProofBundle (see [Data Structures](#data-structures))

The Verifier checks (in order):

1. Challenge is valid and unexpired.
2. Verify `prepare_proof` (if present) OR verify a combined proof variant.
3. Verify `show_proof` against: challenge, `app_id`, and policy constraints (credential type, etc.).
4. Check nullifier is not already registered.

On success:

- Insert nullifier into nullifier set.
- Set `user.vcVerified = true`.

On failure:

- Return error with appropriate error code.

## Circuit Design

This spec mirrors OpenAC's split: Prepare relation (amortized) and Show relation (per session).

### Prepare Relation (Offline, Reusable)

The Prover proves knowledge of a credential `S` and witness `m` such that:

1. `Parse(S) = (m, aux)`
2. `VerifyIssuerSignature(PK_I, S) = 1`
3. `C = Com(m; r)` is correctly formed

#### Private Inputs

- `S`: Credential (signed payload from issuer)
- `m`: Attribute vector extracted from the credential
- `r`: Commitment randomness

#### Public Inputs

- `PK_I`: Issuer public key or trust anchor reference
- `C`: Commitment to the attribute vector

#### Outputs

- `commitment`: `C`
- `prepare_proof`: The zero-knowledge proof

This proof MAY be precomputed and cached. Multiple uses employ re-randomized commitments to prevent linkability across presentations.

### Show Relation (Online, Per Session)

Given a commitment `C` linked to the Prepare proof, a verifier challenge `ch`, and policy inputs:

The Prover proves:

1. **Policy compliance**: `Policy(m) = 1` for the relying party policy. For the one-time human verification policy, this means the credential is of the required type (`cred_scope`). Optionally: validity time window, nationality/age predicates.
2. **Nullifier correctness**: `nullifier = H(app_id || cred_scope || cred_secret)` is correctly computed from hidden values derived from `m`.
3. **Challenge binding**: `ch` is included as a public input (anti-replay).
4. **Device binding** (optional): `VerifyDeviceSig(PK_D, Sig(SK_D, ch)) = 1`, binding the session to a device key.

#### Private Inputs

- Credential attributes `m` (via commitment opening)
- `cred_secret` (for nullifier derivation)
- Device private key `SK_D` (if device-binding is enabled)

#### Public Inputs

- `C`: Commitment (or commitment reference)
- `ch`: Verifier challenge
- `app_id`: Relying party domain separator
- `cred_scope`: Credential type constant
- `nullifier`: Computed nullifier value
- `PK_D`: Device public key (if device-binding is enabled)

#### Outputs

- `show_proof`: The zero-knowledge proof

### Linking Prepare and Show

The Verifier MUST enforce that the Show proof operates over the same committed witness as the Prepare proof. Both proofs MUST reference the same commitment `C`, or include compatible commitment openings whose equality can be checked.

### Proof Generation

#### Prover MUST

- Validate the credential signature before proof generation.
- Generate a correct nullifier scoped to the relying party.
- Include the verifier's challenge as a public input.
- Generate a valid zero-knowledge proof.

#### Prover MAY

- Cache the Prepare proof and reuse it across sessions with re-randomized commitments.
- Include device-binding by signing the challenge with a device key.

### Proof Verification

#### Verifier MUST

- Validate the zero-knowledge proof(s).
- Verify the issuer public key is in the trusted key set.
- Verify the challenge is valid and unexpired.
- Check the nullifier against the stored nullifier set.

#### Verifier SHOULD

- Maintain an allowlist of acceptable issuer keys or key identifiers.
- Log verification failures for operational monitoring.

#### Verifier MAY

- Verify device-binding signatures if the deployment requires it.
- Use a Merkle root / trust list root for issuer key verification (better privacy if multiple issuers exist).

## Data Structures

### ProofBundle

```json
{
  "version": "zk-human-verif-raw-0",
  "app_id": "<relying party identifier>",
  "cred_scope": "<credential type, e.g. TW_CITIZENSHIP_CERT>",
  "challenge": "<base64>",
  "nullifier": "<hex or base64>",
  "commitment": "<hex or base64>",
  "prepare_proof": "<base64>",
  "show_proof": "<base64>",

  "device_binding": {
    "enabled": false,
    "device_pubkey": "<base64>",
    "device_sig_over_challenge": "<base64>"
  },

  "meta": {
    "prover": "web | android | ios",
    "prover_build": "<optional build identifier>",
    "timestamp": 0
  }
}
```

Notes:

- `prepare_proof` MAY be omitted if using a single combined proof, but the split is RECOMMENDED for performance and architecture clarity.
- `device_binding.enabled = false` is allowed if the threat model does not require it for one-time verification.

### Verifier Database Schema

The BBS server MUST store at minimum:

| Column | Type | Description |
|--------|------|-------------|
| `id_verified` | boolean | Whether the user has been verified |
| `id_nullifier` | string | The accepted nullifier value |
| `id_proof` | string (optional) | The stored proof for audit |

## Error Handling

Implementations MUST handle:

1. Invalid or expired challenge
2. Invalid proof (Prepare or Show)
3. Duplicate nullifier
4. Untrusted issuer key
5. Invalid device-binding signature (if enabled)

Error responses MUST include:

1. Error code
2. Error message
3. Error details (when available)

# Security Considerations

## Threat Model

The protocol assumes:

- **Prover may be malicious**: May attempt to forge verification or register multiple accounts.
- **Verifier is honest-but-curious**: Verifies correctly but may try to correlate sessions or exfiltrate identifying data.
- **Network attacker**: May attempt to replay old proofs (mitigated by challenge binding).
- **Proven security of the used proving system**, and the trusted setup of the circuit if required by the proving system being used.
- **Trusted issuer key**: The issuer's private key is assumed to be secure and will not sign illegitimate credentials.

## Replay Resistance

The Show proof MUST bind to the verifier's challenge. The Verifier MUST reject expired challenges.

## Duplicate Registration Resistance

The Verifier MUST maintain a set of accepted nullifiers. If one person should only verify one BBS account, then the nullifier MUST be unique per credential per deployment (scoped by `app_id`).

## Linkability

If the same commitment/proof material is reused across multiple presentations, verifiers can link sessions. The prover SHOULD re-randomize (or consume one-time prepared states) to avoid linkability, consistent with OpenAC's reblind approach.

## Nullifier Privacy

A nullifier is a stable identifier within the relying party scope. This is an explicit trade-off:

- It prevents duplicate registration.
- It introduces a stable per-deployment token.

Mitigations:

- Strong domain separation (`app_id`) so nullifiers cannot be correlated across relying parties.
- `cred_secret` SHOULD NOT be a raw personal ID attribute unless combined with a wallet-held secret (e.g., `cred_secret = H(stable_attribute || wallet_secret)`).

## Device-Binding Trade-offs

Device-binding helps against credential sharing but can harm usability (device change) and complicate privacy. For one-time verification, deployments MAY choose:

- **No device-binding**: Simpler; relies on nullifier uniqueness alone.
- **Soft binding**: Device signature over challenge, but allow re-verification on new device via support flow.
- **Hard binding**: Strong anti-sharing, but more operational complexity.

## Issuer Trust Model

The Verifier MUST have an allowlist/trust store for acceptable issuer keys. Two approaches:

- **Direct key**: `PK_I` is hardcoded or configured (simple, but can leak issuer identity if multiple issuers exist).
- **Merkle root / trust list root**: The prover proves issuer key membership in an allowlisted root (better privacy if issuer identity matters).

## Known Limitations

- **Credential format dependency**: The protocol depends on the ability to parse and verify issuer signatures within ZK circuits. Changes to the issuer's credential format require circuit updates.
- **One-person-one-account limitation**: The protocol cannot fully guarantee "one natural person = one BBS account" across all possible collusion and device-sharing scenarios. This is policy-dependent and may require stronger binding.

## Privacy Guarantees

The protocol MUST guarantee:

1. That the Verifier cannot learn raw credential attributes (name, ID number, DOB, address, etc.) from the proof.
2. That the nullifier cannot be used to track users across different relying parties (due to `app_id` scoping).

# Implementation Notes

The reference implementation targets a PTT-like BBS deployment with the following technology stack:

**Client-side (Web)**:
- OpenAC compiled to WASM via `mopro build` with wasm target
- Credential data fetched via card reader (HiPKI local server at `http://127.0.0.1:61161/sign`) or mobile certificate API

**Client-side (Mobile)**:
- OpenAC via mopro-ffi bindings (Swift for iOS, Kotlin for Android)
- Integration with existing BBS mobile apps (e.g., Ptt-iOS, Ptt-Android)

**Server-side**:
- Go backend with Rust FFI for OpenAC verification (via rust2go)

**Proof generation (Web)**:

```javascript
// 1. Fetch credential data from card reader or mobile API
const signResponse = await fetch('http://127.0.0.1:61161/sign', {
  method: 'POST',
  body: JSON.stringify({ tbs: challengeHash, hashAlgorithm: 'SHA256' })
});

// 2. Extract credential data
const { certb64, signature } = await signResponse.json();

// 3. Generate ZK proof client-side (WASM)
const proof = await generateProof({
  credential: certb64,
  signature: signature,
  challenge: serverChallenge,
  appId: 'ptt-mainnet',
  credScope: 'TW_CITIZENSHIP_CERT'
});

// 4. Submit proof bundle to BBS server
await fetch('/v1/human-verification/submit', {
  method: 'POST',
  body: JSON.stringify(proof)
});
```

For the current implementation status and source code, see the [reference repository](https://github.com/zkmopro/ZK-based-Human-Verification).

# Extensions

## Revocation / Status Checks

Add a predicate `NotRevoked(m, status_root)` proven in Show, where `status_root` comes from an external status list. This can remain out-of-circuit in a first iteration, matching the initial one-time use case.

## On-chain Nullifier Registry

Instead of (or in addition to) a server-side nullifier database, publish accepted nullifiers on-chain:

- **Pros**: Public auditability; reuse across other relying parties; censorship-resistance.
- **Cons**: Fees; public metadata; contract upgrade concerns; privacy trade-offs.

This can be designed so the on-chain registry only stores nullifiers and minimal metadata.

# References

1. [OpenAC: Anonymous Credentials from ZK](https://github.com/privacy-ethereum/zkID) - PSE zkID team
2. [ZK-based Human Verification Repository](https://github.com/zkmopro/ZK-based-Human-Verification)
3. [mopro - Client-side ZK proving on mobile](https://github.com/zkmopro/mopro)
4. [RFC 2119 - Key words for use in RFCs](https://www.ietf.org/rfc/rfc2119.txt)
5. [Taiwan Citizen Digital Certificate (MOICA)](https://moica.nat.gov.tw/)
6. [HiPKI Local Signing Server](https://publicca.hinet.net/HiPKI-01.htm)
7. [rust2go - Rust to Go FFI](https://github.com/ihciah/rust2go)

# Appendix A: Open Questions

The following items need to be resolved as this specification matures:

1. **Credential type and container**: What exactly is `S`? (SD-JWT VC? Custom JWT wrapper? Raw payload + signature?)
2. **Issuer signature scheme in circuit**: RSA vs ECDSA P-256 vs other? (Affects circuit complexity.)
3. **Nullifier secret source**: What is `cred_secret` for nullifier derivation? (Issuer-provided random? Wallet secret + stable attribute? Something else?)
4. **Device-binding requirement**: If required, what is the device key source? (Secure enclave key? Embedded key in credential? Wallet key?)
5. **Account re-binding**: Do we require "one credential = one account" strictly, or allow re-binding if account is lost?
6. **Failure semantics**: Should `vcVerified = failed` be stored, or treat failures as transient?

# Appendix B: Trusted Issuer Certificate Chain (Taiwan)

For the Taiwan Citizen Digital Certificate deployment:

| Level | Subject | Thumbprint |
|-------|---------|------------|
| Root CA | `C=TW, O=Government Root Certification Authority` | `B091AA91...` |
| Intermediate CA | `C=TW, O=行政院, OU=內政部憑證管理中心` | `2797EFFF...` |

The in-circuit verification checks the end-entity certificate against the intermediate CA. Root CA to intermediate CA verification is performed off-chain.

# Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
