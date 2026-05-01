# OpenAC Core Maintainer Decisions

This note records the editorial decisions currently applied to
`6/OPENAC-CORE` as it moves from `raw` toward `draft`.

## 1. Canonical Scope

Resolution:

- `OPENAC-CORE` remains intentionally narrow.
- Core standardizes the current two-phase `Prepare` / `Show` model, proof
  linking semantics, verifier requirements, proof-bundle serialization, and
  the current `SD-JWT-P256` profile.
- Revocation, nullifiers, on-chain verifier interfaces, `mdoc`, `X.509`, and
  generalized cross-credential predicates remain out of scope for this
  document.

Effect on the spec:

- Core text treats those items as future extensions or future profile specs,
  not latent requirements of the current protocol.

## 2. Device Public Key Exposure

Resolution:

- Exposure of a stable device public key is not an intended OpenAC Core
  protocol property.
- Core requires proof of possession of the bound device key, but does not
  require disclosure of a stable verifier-observable device identifier.
- The current `openac-sdk` verifier surface exposing `deviceKeyX` and
  `deviceKeyY` is treated as a current implementation artifact and privacy
  caveat, not as a required long-term core output.

Effect on the spec:

- `expression_result` remains the required core verifier-facing semantic
  output.
- Device-key coordinates are documented as a current compatibility/privacy
  issue for the present `SD-JWT-P256` implementation line.

## 3. Version Field Semantics

Resolution:

- The serialized `version` field identifies proof-bundle or profile semantics,
  not SDK release metadata.
- SDK semantic-version strings are not the protocol version.
- Verifiers must bind accepted `version` values to specific verification keys,
  circuit parameterization, and profile semantics.

Effect on the spec:

- The core spec separates protocol/profile versioning from implementation
  versioning.
- The current `openac-sdk` use of `SDK_VERSION` in the bundle is treated as a
  legacy placeholder rather than a normative protocol definition.

## 4. Claim Normalization and `claimFormats`

Resolution:

- Core continues to standardize only the role of normalized scalar claim
  values in the `Show` relation.
- There is no cross-profile claim-normalization registry in core at this time.
- The current normalization tags are standardized only within the
  `SD-JWT-P256` profile.

Effect on the spec:

- `claimFormats` stays profile-specific.
- The current `SD-JWT-P256` profile now records the visible format-tag
  behavior from the circom and SDK implementation:
  - `0 = bool`
  - `1 = uint`
  - `2 = iso_date`
  - `3 = roc_date`
  - `4 = string`

## 5. Linking Construction

Resolution:

- The linking security property is normative.
- The exact shared-commitment construction from the paper and current backend
  remains informative rather than mandatory.

Effect on the spec:

- Implementations may use alternate proving backends or linking internals, but
  they must preserve the same binding property between `Prepare` and `Show`.

## 6. Challenge Encoding

Resolution:

- Challenge binding remains profile-specific at the byte-encoding layer.
- For `SD-JWT-P256`, the verifier challenge is treated as a UTF-8 string,
  hashed with `SHA-256`, and then reduced mod `q_P256` for the `Show`
  relation.

Effect on the spec:

- The current `SD-JWT-P256` behavior is normative for that profile.
- Core leaves room for other profiles to use different challenge encodings if
  they standardize them explicitly.

## 7. Proof Validity Versus Policy Acceptance

Resolution:

- These remain separate outputs.
- A presentation with `expression_result = 0` may still be cryptographically
  valid, but it is not acceptable for authorization.

Effect on the spec:

- Verifier conformance text distinguishes proof verification from application
  acceptance.

## 8. Holder-Local Precompute State

Resolution:

- Precompute artifacts remain holder-local cache state.
- They are not standardized as transferable network objects in core.

Effect on the spec:

- Only the presentation proof bundle is network-facing in this document.

## 9. Next Profile Work

Resolution:

- Additional profiles should proceed as separate specs without broadening the
  current core.
- The likely next profile candidates remain `mdoc` and `X.509` / MOICA, but
  their order does not affect the present core draft.

Effect on the spec:

- Core text keeps profile hooks abstract where needed, but does not import
  those formats early.

## 10. Canonical Home and Responsible Editor

Resolution:

- `privacy-ethereum/zkspecs` is treated as the canonical editorial home for
  `OPENAC-CORE`.
- Responsible-editor assignment remains a process item rather than a protocol
  design question.

Effect on the spec:

- The protocol text can continue to tighten while editor assignment remains
  pending for a later status promotion step.

## Remaining Follow-Up Before Status Promotion

The protocol-shape questions above are now resolved for editorial purposes.
The remaining work before advancing beyond `raw` is primarily:

- assigning a responsible editor;
- publishing conformance fixtures and test vectors; and
- deciding whether to preserve compatibility with legacy SDK-written
  `version` strings during transition to profile-defined identifiers.
