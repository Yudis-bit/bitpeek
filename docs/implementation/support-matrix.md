# Bitpeek Capability & Support Matrix

This matrix tracks the concrete implementation, verification level, availability, maturity, and supported subsets across Bitpeek modules according to the Bitpeek Ultra specification (Section 02).

## Status Accounting Definitions
- **Implementation**: `absent` | `implemented`
- **Verification**: `not-run` | `failed` | `fixture-verified` | `integration-verified` | `hardware-verified`
- **Availability**: `ready` | `missing-dependency` | `unavailable-platform` | `missing-profile` | `disabled`
- **Maturity**: `experimental` | `stable`

---

## 1. Core Platform & Sources

| Capability ID | Feature | Implementation | Verification | Availability | Maturity | Supported Subset |
|---|---|---|---|---|---|---|
| `CORE-01` | Portable Core Boundaries | implemented | fixture-verified | ready | stable | Pure TypeScript, zero platform I/O in core |
| `CORE-02` | Exact Types, Spans & Ints | implemented | fixture-verified | ready | stable | Half-open `[start, endExclusive)`, BigInt for u64/u128/u256 |
| `CORE-03` | Bounded Checked Reader | implemented | fixture-verified | ready | stable | Endian scalars, bitfields, canonical varint, fuel limits |
| `CORE-04` | Source Snapshots | implemented | fixture-verified | ready | stable | Memory, Blob (browser), Handle-backed (Node), Slice, Overlay |
| `CORE-05` | Resource Budgets & Cancel | implemented | fixture-verified | ready | stable | Chunked cancellation, managed buffer quotas, read budgets |
| `CORE-06` | Unified Operation Registry | implemented | fixture-verified | ready | stable | Multi-surface dispatch (Web, CLI, MCP) with schema validation |

---

## 2. Streaming Data & Edits

| Capability ID | Feature | Implementation | Verification | Availability | Maturity | Supported Subset |
|---|---|---|---|---|---|---|
| `DATA-01` | Streaming Hash/Checksum | implemented | fixture-verified | ready | stable | SHA-256, CRC-16-CCITT, CRC-32-IEEE, Sum8, XOR8, Shannon entropy |
| `DATA-02` | Streaming Pattern Search | implemented | fixture-verified | ready | stable | Masked hex (`??`), text (ASCII/UTF-8), cross-chunk boundaries |
| `DATA-03` | Streaming Strings | implemented | fixture-verified | ready | stable | ASCII, UTF-8, UTF-16LE/BE with surrogate preservation & bounds |
| `DATA-04` | Bounded Diff & Semantics | implemented | fixture-verified | ready | stable | Offset-aligned diff with bounded run count, difference ranges |
| `DATA-05` | Piece Table / Sparse Edits | implemented | fixture-verified | ready | stable | Transactional insert/delete/replace with undo/redo & stream save |
| `DATA-06` | Transforms & Inverses | implemented | fixture-verified | ready | stable | Reverse, invert, XOR mask, byteswap, bit permutation with inverse map |

---

## 3. Formats & Structures

| Capability ID | Feature | Implementation | Verification | Availability | Maturity | Supported Subset |
|---|---|---|---|---|---|---|
| `FMT-01` | ELF32/64 & PNG | implemented | fixture-verified | ready | stable | ELF LE/BE, sections/programs, PNG chunk layout & CRC checks |
| `FMT-02` | PE / COFF | implemented | fixture-verified | ready | stable | PE32/PE32+, headers, sections, data directories, bounded RVA mapping |
| `FMT-03` | WebAssembly Binary | implemented | fixture-verified | ready | stable | Wasm magic, version, section framing, bounded LEB128 metadata |
| `FMT-04` | ZIP Archive | implemented | fixture-verified | ready | stable | Central & local headers, bounded ZIP64, entry mismatch checks |
| `FMT-05` | GPT / MBR Partitions | implemented | fixture-verified | ready | stable | Protective MBR, GPT header & partition table with CRC32 verification |
| `FMT-06` | UBI Volume Headers | implemented | fixture-verified | ready | stable | Eraseblock headers, volume IDs, sequence metadata & CRC |
| `FMT-07` | SquashFS / Filesystem | implemented | fixture-verified | ready | experimental | Superblock inspection, directory & regular-file metadata |
| `FMT-08` | Custom Schema Interpreter v2 | implemented | fixture-verified | ready | stable | Sandboxed declarative AST: nested structs, arrays, bitfields, assertions |

---

## 4. Provenance & Projects

| Capability ID | Feature | Implementation | Verification | Availability | Maturity | Supported Subset |
|---|---|---|---|---|---|---|
| `PROV-01` | Provenance DAG & Integrity | implemented | fixture-verified | ready | stable | Acyclic derivations, content hashing, event IDs distinct from data |
| `PROV-02` | Cross-Layer Mapping | implemented | fixture-verified | ready | stable | Affine, piecewise, permutation, scatter-gather, region dependency |
| `PROV-03` | Uncertainty & Candidates | implemented | fixture-verified | ready | stable | Observed vs derived vs inferred; candidate voting & confidence labels |
| `PROJ-01` | Project Storage & Recovery | implemented | fixture-verified | ready | stable | Indexed chunks, transaction manifests, interrupted write recovery |
| `PROJ-02` | Safe Import & Export | implemented | fixture-verified | ready | stable | Archive traversal protection, symlink & ADS rejection, relocation |
| `EVID-01` | Patch v1/v2 Migration | implemented | fixture-verified | ready | stable | Dual-dialect v1 loader, strict v2 with SHA-256 integrity hashes |
| `EVID-02` | Recipe v2 Replay | implemented | fixture-verified | ready | stable | Versioned DAG replay, deterministic seed verification, budgets |
| `EVID-03` | Evidence Bundles | implemented | fixture-verified | ready | stable | Cryptographic bundle manifests, reproduction commands, audit records |
| `EVID-04` | Recursive Redaction | implemented | fixture-verified | ready | stable | Deep object/array redaction of secrets, hashes, and binary payloads |

---

## 5. Domain Modules

| Capability ID | Feature | Implementation | Verification | Availability | Maturity | Supported Subset |
|---|---|---|---|---|---|---|
| `NAND-01..05` | NAND & SECDED ECC | implemented | fixture-verified | ready | stable | Geometry, OOB viewer, multi-read comparison, Hamming SECDED codec, synthetic FTL |
| `NAND-06` | Real Chip Layout Profiles | implemented | fixture-verified | missing-profile | experimental | Reference synthetic lab profile verified; vendor profiles extensible |
| `CAP-01..03` | Hardware Captures & Signals | implemented | fixture-verified | ready | stable | CSV samples, bounded VCD, UART, SPI, I2C transaction decoders |
| `CAP-04` | Physical Side-Channel / EM | implemented | fixture-verified | ready | experimental | Normalized trace import, sample alignment, distribution comparison |
| `NATIVE-01..04` | Native Code & Address Spaces | implemented | fixture-verified | ready | stable | Multi-module VA mapping, x86-64/AArch64 disasm adapter, minidump parser, ASan/UBSan |
| `NATIVE-05` | MMIO / CMSIS-SVD Profiles | implemented | fixture-verified | ready | experimental | SVD peripheral & register field parsing, read-only inspection |
| `TRACE-01..05` | Trace Model & GDB/MI | implemented | fixture-verified | ready | stable | Indexed event timeline, clock domain sync, GDB/MI transport, QEMU debug config |
| `RUN-01..06` | Experiment Runner & Reducer | implemented | fixture-verified | ready | stable | Deterministic mutation, oracle verification, delta reducer, differential testing |
| `BCHAIN-01..05` | Blockchain & Crypto Lab | implemented | fixture-verified | ready | stable | Bitcoin CompactSize/tx parser, Ethereum RLP, EVM trace import, 256-bit limb math |
| `AI-01..07` | AI Tensors & GPU Diagnostics | implemented | fixture-verified | ready | stable | SafeTensors & ONNX parser, exact tensor bounds & strides, GPU sanitizer import |
| `DISC-01..02` | Hypothesis & Discovery Engine | implemented | fixture-verified | ready | stable | Multi-sample training/holdout split, length vs record count, experiment proposals |
