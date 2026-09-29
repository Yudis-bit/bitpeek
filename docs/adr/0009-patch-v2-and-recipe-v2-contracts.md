# ADR 0009: Patch v2 and Recipe v2 Contracts Migration

## Context
Inspection identified discrepancies between patch implementations:
- `packages/core/src/patch.ts` supported `version: 1` with `{ changes: [{ offset, remove, insert }] }`.
- `public/schemas/offset-patch-v1.json` defined `{ operations: [{ offset, bytes, precondition }] }`.
- `public/schemas/offset-patch-v2.json` required SHA-256 hashes (`sourceSha256`, `targetSha256`) and operations.
Furthermore, legacy recipes were linear execution lists rather than versioned directed acyclic graphs of operations.

## Decision
1. **Patch Dialects**:
   - Maintain backwards-compatible loaders for both v1 dialects:
     - Dialect 1A: `{ changes: [{ offset, remove, insert }] }`.
     - Dialect 1B: `{ operations: [{ offset, bytes, precondition }] }`.
   - Standardize canonical Patch v2 requiring cryptographic SHA-256 hashes of source and target, atomic staging, and precondition validation.
   - Patch application must never mutate source in-place, must stage output in temporary files, verify target hash, and atomically commit.
2. **Recipe v2**:
   - Structure recipes as a versioned DAG of operations with explicit artifact dependencies, inputs, expected output hashes, and resource quotas.
   - Separate pure deterministic replay recipes (which cannot execute subprocesses) from experimental runner recipes (which declare process execution effects).

## Consequences
- Preserves compatibility with all existing patches while enforcing cryptographic integrity for modern workflows.
- Eliminates ambiguities in patch verification and application across Web, CLI, and MCP.
