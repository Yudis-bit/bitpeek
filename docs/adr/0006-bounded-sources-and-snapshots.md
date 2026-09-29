# ADR 0006: Bounded Sources, Chunk Validation, and Content Snapshots

## Context
Bitpeek was originally designed with `MemoryByteSource`, `BlobByteSource`, and `FileByteSource` in `packages/core`. Audit findings revealed:
1. `MemoryByteSource` held the caller's `Uint8Array` by reference, allowing external mutation to alter internal state.
2. `chunks()` iterator did not validate `chunkSize <= 0`, non-integer values, or invalid ranges, posing a potential infinite loop hazard.
3. `FileByteSource` in `core` directly imported `node:fs/promises`, violating the platform-independence requirement of core.
4. `FileByteSource` treated partial reads as immediate EOF truncation rather than retrying to complete the requested chunk.
5. Snapshot revisions were based on `mtimeMs-size`, which is not content-addressable or race-free.

## Decision
1. **Core Independence**: `packages/core` exports the abstract `ByteSource` interface, `MemoryByteSource` (with defensive buffer cloning), `SliceByteSource`, and `OverlayByteSource`.
2. **Platform I/O Separation**: Node-specific file operations reside in `packages/io-node` (`NodeFileByteSource`) using opened file handles, retrying partial reads until completion, and verifying content identity. Browser-specific adapters reside in `packages/io-browser` (`BlobByteSource`, `OpfsByteSource`).
3. **Rigorous Chunk Validation**: `chunks()` and `read()` validate that `offset` and `length` are non-negative safe integers within source bounds, and `chunkSize` is a positive safe integer within configured budgets (default 1 MiB).
4. **Snapshot Identity**: Pinned snapshots use content-addressed hashes (`sha256`) or explicit snapshot handles. Reference-mode sources verify handle and size consistency before each read.

## Consequences
- Guarantees zero platform-specific imports in `packages/core`.
- Eliminates infinite loops and unexpected truncation on large or streaming sources.
- Enables safe multi-gigabyte navigation without whole-file allocation.
