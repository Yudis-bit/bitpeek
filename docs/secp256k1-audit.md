# secp256k1 audit

The core entry point exports `Secp256k1Engine`, curve constants `SECP256K1_P`,
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
guarantees. This engine inspects public data and is not a secret-key signing backend.
Curve parameters and x-only lifting follow [BIP-340](https://bips.dev/340/).

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

Choose exactly one input form, `rawHex` or `handle`. Offset and length apply only
to sessions. Numbers are validated without coercion or clipping, unknown arguments
are rejected, file paths are revalidated against allowed roots, and changed file
sizes require reopening. Every report includes the selected byte count and SHA-256
in `source` to identify the bytes inspected. Capability discovery also reports
the audit tools, byte limits, and `secp256k1.audit` recipe.

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
