# secp256k1 audit

The core entry point exports `Secp256k1Engine`, `TaprootEngine`, curve constants `SECP256K1_P`,
`SECP256K1_N`, `SECP256K1_HALF_N`, `SECP256K1_GX`, `SECP256K1_GY`,
`ConstantTimeAuditor`, `auditSecp256k1`, and `SECP256K1_AUDIT_RECIPE` through its
blockchain, native, and operations barrels.

## Public keys and ECDSA encodings

`Secp256k1Engine.inspectPubKey(bytes)` accepts SEC compressed (33 bytes), SEC
uncompressed (65 bytes), and BIP-340 x-only (32 bytes) public keys. It checks
coordinate bounds and the curve equation, recovers compressed Y with the encoded
parity, and returns even Y for x-only keys. Hybrid and infinity encodings are
rejected. Integers use big-endian byte order and exact `bigint` arithmetic.

`inspectSignatureDER(bytes)` accepts the DER sequence alone, without Bitcoin's
trailing sighash byte. It applies the positive-integer encoding rules in
[BIP-66](https://bips.dev/66/), then checks scalar bounds and low-S policy.
`isDer` reports encoding validity; a correctly encoded zero or overflowing scalar
can have `isDer: true` and `isStrictlyValid: false`. `isLowS` is the numerical
predicate `s <= n/2`; scalar validity is reported separately.

`inspectCompactSignature(bytes)` accepts exactly 64 bytes of ECDSA `r || s`.
It does not interpret those bytes as Schnorr or a recoverable signature.
`isStrictlyValid` means canonical encoding, nonzero scalars below the curve order,
and low-S policy. Message authenticity requires the signed message and public key
and is outside these inspection methods.

`sqrtModP(a)` reduces signed input modulo the field prime and evaluates the fixed
public exponent `(p + 1) / 4` in 256 rounds, checking the result by squaring.
JavaScript BigInt and the JavaScript runtime do not provide constant-time execution
guarantees. Signing and nonce derivation are reference workbench operations, not a
constant-time secret-key signing backend.
Curve parameters and x-only lifting follow [BIP-340](https://bips.dev/340/).

## BIP-340 reference signing and auxiliary audit

`bip340DeriveNonce(seckey32, msg32, auxRand32?)` implements the BIP-340 tagged
aux/nonce hash transcript and returns `k` normalized to an even-Y commitment,
plus `rx`. `bip340Sign` returns a 64-byte `R.x || s` signature and the x-only
public key, and verifies the generated signature before returning it. Keys,
messages and supplied auxiliary data must each contain exactly 32 bytes. Secret
keys must satisfy `0 < d < n`; invalid keys are rejected before reduction.
Omitting aux selects 32 zero bytes. These APIs intentionally retain the
workbench's 32-byte message contract; modern BIP-340 also supports other message
lengths.

`bip340AuditSignatureAux(seckey32, msg32, sig64, candidateAux32?)` compares the
observed signature with both the zero-aux default and a supplied candidate.
`valid` indicates that comparison inputs are valid; `matchesAux` and
`isDeterministicDefault` report independent comparisons. Without a candidate,
`matchesAux` equals `isDeterministicDefault`. A mismatch does not establish that
the original signer used fresh randomness, nor does this API independently
verify an unmatched signature. Malformed candidate aux is an invalid audit.

Tests use [published BIP-340 signing vectors 0–3](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv).
The two Schnorr samples in `BITPEEK_UPGRADE_SPEC.txt` differ from these published
vectors, so they are not used as conformance expectations.

## BIP-352 output batch scanning

`scanSilentPaymentOutputs` accepts transaction output x-only keys, a spend public
key, scan private key, one precomputed shared-secret tweak `t_k`, an optional
precomputed label cache, and `batchSize` (default 50). It calculates
`P_unlabeled = B_spend + t_k*G` and checks each output directly or through label
points `P_even - P_unlabeled` and `-P_even - P_unlabeled`. Lookup keys preserve
the label point's Y parity. `candidateSlotParity` selects the output's even-Y
lift (0) or its negation (1), independently of the label point's parity.

For slot `i` within a batch starting at transaction position `j_start`, the
output index is `j_start + floor(i / 2)`. Matches retain absolute output indices,
batch indices, batch starting offsets, and label metadata. Malformed output
keys are skipped without compacting positions; `totalOutputsScanned` counts
all supplied positions. An empty output list returns one empty batch, following
the directive. Batch sizes must be positive safe integers.

This API scans all transaction batches for the supplied `t_k`; it does not
derive ECDH or iterate protocol output counter `k`. The scan private key is
validated, while tweaks and label points are provided by the caller. Include
change label 0 in the cache when needed. Optional `labelPubKey33` is the trusted
precomputed point `m*G`, corresponding to `labelTweak32`, not the labeled spend
key. `verifySilentPaymentBatchMapping(jStart, slotIndex)` exposes the correct
index and the known incorrect `floor((j_start + i) / 2)` index for invariant
audits; invalid or imprecise indices throw `RangeError`.

The batch scanner tests exercise published BIP-352 labeled outputs, independent
OpenSSL curve fixtures, both output-lift parities, and single matches in later
batches with exact transaction-position assertions.

## BIP-341 TapTrees and script-path commitments

`TaprootEngine` is exported from the blockchain and core barrels, along with
`TapLeaf`, `TapTreeStructure`, `TapTreeLeafInfo`, `TapTreeResult`,
`TaprootControlBlockInspection`, `TaprootScriptPathVerificationResult`, and the
Tapscript key audit types. The same seven methods are available as forwarding
helpers on `Secp256k1Engine`.

`tapLeafHash(script, leafVersion?)` hashes the even version byte (default `0xc0`),
canonical Bitcoin CompactSize script length, and script under the `TapLeaf` tag.
`tapBranchHash(a32, b32)` hashes the lexicographically smaller child before the
larger child under `TapBranch`; equal children are permitted. `tapTweakHash`
hashes an internal x-only key and optional Merkle root under `TapTweak`. Omitting
the root differs from supplying a zero root.

`inspectControlBlock(bytes)` checks the `33 + 32*m` encoding, limits `m` to
0–128, validates the internal key, and extracts `leafVersion = header & 0xfe`
and `outputParity = header & 1`. It returns independent copies of wire bytes,
internal key and leaf-to-root siblings, including for Node Buffer inputs.

`verifyScriptPath(controlBlock, outputKey32, leafScript)` evaluates the leaf and
siblings, rejects tweaks at or above the group order before scalar reduction,
and checks both the output X coordinate and the control block's Y parity. Zero
tweaks are permitted; infinity is rejected. This verifies the BIP-341 script
commitment. It does not execute Tapscript, validate signatures or transaction
sighashes, or process witness annexes. Future even leaf versions can also have
their commitments verified. See [BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki).

`buildTapTree(leaves, internalKey32, structure?)` pairs adjacent nodes at each
level and carries an unpaired node forward. Its optional custom binary shape
uses leaf indices, e.g. `[0, [1, 2]]`; every leaf index must occur exactly once,
and no proof may exceed 128 siblings. Returned leaves retain input order and
include script copies, leaf hashes, Merkle paths and synthesized control blocks.
Duplicate scripts and empty scripts are valid commitment inputs. Hashing and
building methods throw `RangeError` for invalid inputs; inspectors and verifiers
return invalid results with exact reasons.

Conformance tests reproduce all published script-path hashes and control blocks
from the [BIP-341 wallet vectors](https://github.com/bitcoin/bips/blob/e35a46ecf3031c21dc7f7fdb694986789a3a8144/bip-0341/wallet-test-vectors.json).
Mutation tests change scripts, sibling nodes, internal/output keys, leaf versions
and parity, and exercise the maximum control-block depth.

## Tapscript descriptor key canonicalization

`auditTapscriptKeys(pubkeys)` accepts descriptor keys in x-only or compressed
SEC form, validates their curve coordinates, and groups them by canonical X.
Opposite compressed parities produce a `parity-collision` warning; other
repeated canonical keys produce a `duplicate-xonly` informational finding.
Parity-collision findings take precedence over duplicate findings for the same
group. Invalid encodings or off-curve keys produce `invalid-key` warnings and
`valid: false`; collision warnings leave input validity unchanged.

This audits conversion to x-only keys. BIP-342 does not automatically strip SEC
prefixes in an executing script: a raw 33-byte key is an unknown public-key type,
with different signature-validation rules. Collision findings identify redundant
or ambiguous descriptor key conditions, not proof of transaction malleability.
See [BIP-342 key rules](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#rules-for-signature-opcodes).

## Operation and recipe

`createDefaultOperationRegistry()` registers the read-only, deterministic
`secp256k1.audit` operation with category `crypto`. It accepts a `Uint8Array`,
`{ bytes, format? }`, `{ rawHex, format? }`, or `{ format? }` with a ByteSource
execution context. Hex input must be valid, complete bytes. Inputs exceeding
1 MiB, incomplete source reads, and conflicting byte/hex inputs are rejected.

Supported format hints are `auto`, `pubkey`, `der`, `compact`, and `bitcoin-tx`.
Auto detection first attempts exact transaction framing, then DER, public keys,
and compact ECDSA. Raw encodings can overlap; supply a format hint when the origin
is known. Malformed transactions can otherwise be reported as unrecognized input.

```typescript
import {
  createDefaultOperationRegistry,
  SECP256K1_AUDIT_RECIPE,
  runRecipe,
} from './packages/core/src/index'
import type {
  Secp256k1AuditInput,
  Secp256k1AuditResult,
} from './packages/core/src/index'

const registry = createDefaultOperationRegistry()
const report = await registry.execute<Secp256k1AuditInput, Secp256k1AuditResult>(
  'secp256k1.audit',
  { rawHex: '3006020101020101', format: 'der' },
)
console.log(JSON.stringify(report))

const signature = Uint8Array.from([0x30, 6, 2, 1, 1, 2, 1, 1])
const replay = runRecipe(SECP256K1_AUDIT_RECIPE, { input: signature }, { dryRun: true })
console.log(JSON.stringify(replay.stepResults))
```

Recipe-v1 accepts `secp256k1.audit` as a step, respects its byte range, and reports
findings in `outputValue`. It works through the existing browser recipe panel,
CLI `recipe run`, and MCP `bitpeek_run_recipe` tool. Select a format using the
step's `parameters.format` or the browser's operation parameter.

For CLI or MCP, save this executable recipe and bind `input` to the binary:

```json
{
  "schemaVersion": 1,
  "recipeId": "secp256k1.audit",
  "title": "secp256k1 Audit",
  "inputs": [{ "id": "input" }],
  "steps": [{
    "id": "audit",
    "operation": "secp256k1.audit",
    "input": "input",
    "parameters": { "format": "auto" }
  }]
}
```

```sh
bitpeek recipe run audit.json --input input=signature.bin --dry-run --json
```

Reports use decimal strings for scalar values, coordinates, and satoshi totals,
so they serialize to JSON without precision loss. Findings include severity, code,
message, and a location in the input. High-S receives the required BIP-62/146 warning;
field/scalar overflow and invalid curve points receive critical findings. Low-S
is an audit policy here, not a claim that all high-S legacy transactions violate
active consensus: [BIP-146](https://bips.dev/146/) is a closed proposal.

## Transaction coverage

The Bitcoin parser rejects noncanonical CompactSize encodings, impossible item
counts, unsupported optional-data flags, superfluous witness records, truncation,
and trailing bytes. TXID uses stripped serialization for SegWit. Transaction
audits check empty inputs/outputs, duplicate outpoints, null prevouts, coinbase
scriptSig size, MAX_MONEY per output and in aggregate, and block weight bounds.

The audit extracts likely DER signatures with their final sighash byte removed
from scriptSig pushes, recognizes P2WPKH-shaped witness stacks, and inspects exact
P2PK and Taproot output-key templates. It skips coinbase metadata and reports
unrecognized pushed data, other witness stacks, and other output scripts in
`uninspectedLocations`. These are candidate inspections: script semantics depend
on the spent output and execution context. Arbitrary 64/65-byte witness items are
not subjected to ECDSA low-S checks, avoiding Schnorr misclassification.

The result declares `cryptographicSignaturesVerified: false` and its verification
scope. Raw transaction bytes cannot establish full consensus validity without
previous outputs, script execution, signature hashes, and chain context.

## MCP tools

The server advertises 17 tools, including `bitpeek_secp256k1_audit` and
`bitpeek_constant_time_audit`. Both are annotated read-only and return matching
JSON in `content[0].text` and `structuredContent`. Successful audit calls can
contain critical findings; `isError: true` indicates a rejected call, such as
invalid arguments, expired handles, or a failed read.

The launcher is `packages/mcp/bin/bitpeek-mcp.js`. It loads TypeScript through its
runtime dependency `tsx`, so `node` can start it after `npm install`; no generated
`server.js` is required. The README contains an absolute-path MCP configuration
for this checkout. Restart the MCP server/client connection after upgrading so
`tools/list` includes the new tools. Startup diagnostics go to stderr; stdout
contains protocol messages.

For a quick DER encoding check, call:

```json
{
  "name": "bitpeek_secp256k1_audit",
  "arguments": { "rawHex": "3006020101020101", "format": "der" }
}
```

For a compressed generator key, call:

```json
{
  "name": "bitpeek_secp256k1_audit",
  "arguments": {
    "rawHex": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "format": "pubkey"
  }
}
```

To audit a selected range in a file, first call `bitpeek_open` with `filePath`,
then use its returned opaque handle:

```json
{
  "name": "bitpeek_secp256k1_audit",
  "arguments": { "handle": "sess_from_open", "offset": 128, "length": 33, "format": "pubkey" }
}
```

Without `length`, this tool audits the remaining file bytes and rejects ranges
above 1 MiB. For transactions, use `format: "bitcoin-tx"` to retain parser error
details even for malformed input.

For an x86 region containing one conditional branch and one division:

```json
{
  "name": "bitpeek_constant_time_audit",
  "arguments": { "rawHex": "90740048f7f1c3", "arch": "x86_64", "baseAddress": "0x8000000000000000" }
}
```

For AArch64 conditional branch and division instructions:

```json
{
  "name": "bitpeek_constant_time_audit",
  "arguments": { "rawHex": "000000542008c29a", "arch": "aarch64" }
}
```

Timing audits accept file sessions in the same way, up to 65,536 bytes. Their
default range is the first 256 remaining bytes, and their instruction budget is
10,000 (configurable through `maxInstructions` in the range 1..10,000). Unexamined
bytes make the result non-clean. Finding `offset` is relative to the selected
region; session findings additionally include absolute `fileOffset`. Addresses
are unsigned 64-bit hex strings, preserving values above `Number.MAX_SAFE_INTEGER`.
`baseAddress` describes the region's first byte; by default it is the file offset
for sessions and zero for inline hex.

For the existing audit formats, choose exactly one input form, `rawHex` or
`handle`. Offset and length apply only to sessions. Numbers are validated without coercion or clipping, unknown arguments
are rejected, file paths are revalidated against allowed roots, and changed file
sizes require reopening. Every report includes the selected byte count and SHA-256
in `source` to identify the bytes inspected. Capability discovery also reports
the audit tools, byte limits, and `secp256k1.audit` recipe.

The MCP tool additionally exposes `bip340-sign`, `bip340-aux-audit`, and
`bip352-scan`:

- Signing requires `seckeyHex`, a message supplied as `messageHex` or through
  `rawHex`/`handle`, and optional `auxRandHex`. The reply includes `signatureHex`,
  `publicKeyHex`, and hexadecimal `rx`/`s`; secret keys and nonces are not echoed.
- Aux audit requires the observed signature in `rawHex`/`handle`, `seckeyHex`,
  `messageHex`, and optional candidate `auxRandHex`. It returns the comparison
  flags and `expectedSignatureHex`/`candidateSignatureHex`. `status` is PASS
  when the supplied candidate (or omitted zero default) matches; a completed
  unmatched comparison has `valid: true` and `status: "FAIL"`.
- Scanning requires `spendKeyHex`, `scanPrivKeyHex`, `tweakHex`, and either
  `outputsHex` or packed consecutive 32-byte keys in `rawHex`/`handle`. Optional
  `batchSize` and `labels` expose the core scanner options. Each label has
  `labelIndex`, `labelTweakHex`, and optional compressed `labelPubKeyHex`.
  Matches contain `outputKeyHex` and optional `labelTweakHex`, alongside the
  core match indices and parity. Empty `outputsHex` is accepted.

Direct signing messages and output arrays also receive source byte counts and
SHA-256 metadata. Conflicting message/output sources are rejected. All new
results serialize byte arrays and bigints as hexadecimal strings.

Phase 2 adds three more formats to the same MCP tool:

- `taproot-control-block`: supply the expected 32-byte output key in
  `rawHex`/`handle`, `controlBlockHex`, and `leafScriptHex` (which may be empty).
  The response includes commitment verification, decoded version/parity, root,
  path depth and computed output key as hex. Its scope is
  `taproot-script-commitment`; it does not report signatures as verified.
- `tapscript-keys`: supply mixed descriptor encodings in `keysHex`, or packed
  `rawHex`/file bytes with `keySize` 32 (default) or 33. Reports use PASS for clean
  inputs, WARN for valid inputs with canonicalization findings, and FAIL for
  invalid keys. Empty arrays are accepted and report zero keys examined.
- `taptree-builder`: supply `scriptHexes` and the internal key through
  `internalKeyHex` or `rawHex`/`handle`. Optional `leafVersions` contains one even
  version per script, and `treeStructure` selects the custom shape. Replies
  include `merkleRootHex`, `outputKeyHex`, output parity, and each leaf's
  `scriptHex`, `leafHashHex`, `merklePathHexes`, and `controlBlockHex`.

The new array inputs have count and combined-byte limits; source conflicts,
malformed hex, mismatched versions and invalid custom shapes are rejected.
Existing file authorization, range checks and cancellation apply to these formats.

```json
{
  "format": "taptree-builder",
  "internalKeyHex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "scriptHexes": ["51", "52", "53"],
  "treeStructure": [0, [1, 2]]
}
```

## Static timing inspection

```typescript
import { ConstantTimeAuditor } from './packages/core/src/index'

const report = ConstantTimeAuditor.auditBytes(
  Uint8Array.from([0x90, 0x74, 0, 0xc3]),
  { arch: 'x86_64', baseAddress: 0x1000n },
)
```

`auditX86_64` and `auditARM64` accept the project's `DecodedInstruction` records
(also exported as `DisassembledInstruction`). `auditBytes` uses the existing
`ReferenceDisassembler`; this is the actual disassembler name in this repository.
New decoding covers x86 short/near conditional jumps, loop/count branches, integer
division with ModRM/SIB/displacements, and AArch64 conditional/compare/test-bit
branches and integer division. Unknown/truncated instructions, architecture
mismatches, and bytes left by instruction limits prevent a clean result.

Finding offsets are byte positions from the beginning of the supplied instruction
stream, independent of its bigint base address. `branchCount` counts conditional
branches, not divisions or decode failures. The caller selects the region that
handles secrets. Branch dependency, memory access, processor-specific latency,
and called functions require further analysis. `isCleanConstantTime` means the
nonempty supplied stream has no listed static hazards; it is not a timing proof.

## Checks

```sh
npm test
npm run build
npm run lint
```

The new suites cover curve boundaries, BIP-340/OpenSSL key vectors, DER encoding
and malleability, instruction decoding and conservative timing findings, operation
registration, JSON serialization, transaction framing/invariants, and recipe execution.
