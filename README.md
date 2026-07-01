# zkspecs

Specifications for privacy, verifiability, and programmable cryptography protocols, following a [COSS-based](specs/1/README.md) editorial process. See the [HackMD](https://hackmd.io/UdMwH3nES8qTkRBOn02L8w) for broader context.

These specs aim to keep Ethereum's access paths censorship-resistant, ownerless, private, and secure — covering identity and credentials, anonymous signaling, private reads and writes, credential portability, and more.

## Specifications

| # | Name | Status | Description |
|---|------|--------|-------------|
| 1 | [1/COSS](specs/1/README.md) | draft | Specification framework and editorial process |
| 2 | [2/ANON-AADHAAR-V2](specs/2/README.md) | draft | Privacy-preserving verification of Aadhaar identity cards using ZK proofs |
| 3 | [3/SEMAPHORE-V4](specs/3/README.md) | draft | Anonymous group membership and signaling protocol |
| 4 | [4/EXCUBIAE](specs/4/README.md) | draft | Composable attribute-based access control framework for EVM |
| 5 | [5/ZK-PROOF-OF-PERSONHOOD](specs/5/README.md) | raw | ZK-based proof of personhood for online forums |

Each spec follows a lifecycle from **Raw → Draft → Stable** as defined in [1/COSS](specs/1/README.md).

## Access Layer Spec Map

`zkspecs` began as an attempt to collect PSE and adjacent privacy,
verifiability, and programmable cryptography specifications in one place. As
that work moves into the Access Layer context, this repo can help gather related
specs and spec-like documents that currently live in different repositories or
ad hoc locations into one place over time.

| Area | Work | Location | zkspecs context | Notes |
|------|------|----------|-----------------|-------|
| Personhood | ZK Proof of Personhood | [`privacy-ethereum/zkID/specs/2-zk-proof-of-personhood`](https://github.com/privacy-ethereum/zkID/blob/main/specs/2-zk-proof-of-personhood/README.md) | Related to [`5/ZK-HUMAN-VERIFICATION`](specs/5/README.md), [#18](https://github.com/privacy-ethereum/zkspecs/pull/18), [#20](https://github.com/privacy-ethereum/zkspecs/pull/20), and [#24](https://github.com/privacy-ethereum/zkspecs/pull/24) | Adjacent Access Layer spec work |
| Credentials | OpenAC Core | [`privacy-ethereum/zkID/specs/1-openac`](https://github.com/privacy-ethereum/zkID/blob/main/specs/1-openac/README.md) | Drafted in [#21](https://github.com/privacy-ethereum/zkspecs/pull/21) and [#23](https://github.com/privacy-ethereum/zkspecs/pull/23) | Protocol/spec material alongside implementation work |
| Age verification | ZK Age Verification | [`privacy-ethereum/zkID/specs/3-zk-age-verification`](https://github.com/privacy-ethereum/zkID/blob/main/specs/3-zk-age-verification/README.md) | Related to `6/ZK-AGE-ELIGIBILITY` in [#19](https://github.com/privacy-ethereum/zkspecs/pull/19) | Adjacent Access Layer spec work |

## License

[MIT](LICENSE)
