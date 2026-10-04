# Phase 3–5 cryptographic conformance tools

All functions are exported from `@bitpeek/core` and the blockchain barrel.
The six formats below use the existing `bitpeek_secp256k1_audit` MCP tool.
Results include matching JSON text/structured content and `reportMarkdown`.

| Format | Input and result |
| --- | --- |
| `tapscript-audit` | Script via `leafScriptHex`, `rawHex` or file session. Bounded conservative paths, potential nonempty-signature costs, public witnesses and permanent-failure proofs. |
| `tapscript-eval` | Script plus bottom-to-top `witnessHexes`. Optional precomputed 32-byte `messageHex`, transaction timelock context and bounded trace. |
| `bip375-audit` | Extracted `signers`, `scanKeyHex`, `spendKeyHex`, `outpointSmallestHex`, and `allInputPubkeysHex`. Verifies every DLEQ proof, multiset coverage, aggregate share, scalar fold and optional outputs. |
| `bip324-swift-ec` | Decode `swiftEcHex` or source bytes. Encode with `swiftAction: "encode"`, a SEC/x-only `pubkeyHex` and explicit 32-byte `auxRandHex`. |
| `bip324-frame-audit` | One `bip324PacketHex` or source frame. Authenticate with both initial directional keys or an encoding-bound shared secret plus network magic and direction. |
| `secp256k1-diff-oracle` | `diffOp` selects arithmetic, identities or Schnorr verification. `runBoundaries` runs an automated boundary campaign. Optional observed results compare a caller's native/Wasm/C output. |

Phase 3 retains the existing `profile: "specification"` default. Choose
`"published-bip"` for BIP-342 opcode assignments/full-witness budgets and the
BIP-352 aggregate-key input hash. Published Tapscript requires an explicitly
supplied `serializedWitnessSize` that includes every witness item, CompactSize
prefix, script, control block and optional annex. Stack inputs exclude the last
three components. Signature verification uses the caller's precomputed sighash;
script commitments and the transaction sighash computation are separate checks.
`simulationMode: true` explicitly simulates signatures and reports
`cryptographicSignaturesVerified: false`.

BIP-324 uses the published wire layout: **3 encrypted length bytes, encrypted
flags/content, 16-byte Poly1305 tag**. `Bip324PacketCipher` represents one direction
and advances both ciphers on every packet, including decoys. It ratchets every 224
packets and closes permanently after framing/authentication failure. `packetIndex`
starts at zero and advances initial supplied keys through all preceding ratchets;
it is not a snapshot of keys from the middle of a session. `aadHex` is the first
packet's handshake garbage. An empty negotiation packet is valid; command framing
checks only run when `inspectApplicationPayload` is explicitly enabled. Reserved
flag bits are ignored as specified. Without keys, authenticity is `null` and status
is `INCOMPLETE`. Corruption does not expose unauthenticated plaintext.

SwiftEC decoding reduces both 32-byte wire integers modulo p, remaps exceptional
inputs and lifts with reduced t parity as libsecp256k1 does. The field API accepts
canonical elements. Encoding uses all eight inverse branches with rejection
sampling and a domain-separated SHA-256/HMAC stream from the supplied entropy.
Fresh unpredictable aux data is required for pseudorandom encodings; statistical
regression tests do not prove indistinguishability.

The differential oracle uses an independent Jacobian BigInt model; repository
arithmetic uses affine coordinates and Euclidean inversion. Native/Wasm/C adapters
can implement `Secp256k1DifferentialAdapter` for a direct boundary campaign.
Adapters return canonical affine points, `null` for infinity, field inverses, or
Schnorr booleans. Group multiplication reduces scalars modulo n; canonical scalar
and public-key encodings are separately represented by the boundary generator.
There are no nontrivial low-order secp256k1 points because its cofactor is one.

Reference arithmetic and encoding are variable-time. Every result keeps
`constantTimeProven: false`; optional `criticalCodeHex` connects the existing
machine-code hazard inspector. A successful arithmetic comparison only describes
the selected implementation or supplied observation. Extracted BIP-375 eligibility
and smallest-outpoint selection remain the caller's responsibility.

Protocol references: [BIP-324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki),
[BIP-342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki),
[BIP-375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki).
