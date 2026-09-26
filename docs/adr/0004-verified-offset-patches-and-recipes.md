# ADR 0004: Verified Offset Patches and Declarative Replay Recipes

## Status
Accepted

## Context
Standard text unified diffs are unsuited for binary files. Existing binary patch utilities often create non-deterministic delta encodings or modify target files without cryptographic verification, leading to corrupted binaries when applied against mismatched sources.

## Decision
1. Retain the `bitpeek-offset-patch` version 1 specification for backward compatibility, while establishing `bitpeek-offset-patch` version 2 with mandatory cryptographic source and target SHA-256 integrity verification.
2. Implement a 7-step atomic verified patch application pipeline:
   - Validate patch JSON schema and resource bounds.
   - Verify source length and source SHA-256.
   - Verify byte preconditions prior to any memory mutation.
   - Form target binary atomically in a fresh buffer.
   - Verify target SHA-256.
   - Commit as a single transaction or export to an atomic temporary file.
3. Introduce Declarative Replay Recipes (`recipe-v1.json`) allowing multi-step inspection and transformation sequences to be recorded and re-executed deterministically across Web, CLI, and MCP.

## Consequences
- Guaranteed atomicity: corrupted or mismatched inputs fail completely without partial file corruption.
- Reproducible, audit-grade evidence exchange for bug bounty reports and PRs.
