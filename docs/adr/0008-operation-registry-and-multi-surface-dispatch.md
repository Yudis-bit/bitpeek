# ADR 0008: Unified Operation Registry and Multi-Surface Dispatch

## Context
Bitpeek is accessible via three distinct surfaces:
1. Web Workbench (browser React UI).
2. Command-Line Interface (`bitpeek` CLI).
3. Model Context Protocol (`bitpeek` MCP server for AI tools).

Previously, some CLI and MCP handlers duplicated parsing logic or called non-streaming core functions directly, risking behavioral divergence and redundant maintenance.

## Decision
1. **Central Operation Registry**:
   - All analytical and transformation operations are declared in a shared registry in `packages/core/src/operations`.
   - Each operation defines:
     - Stable ID and schema version.
     - Input and output schemas (with runtime validation).
     - Execution environment (`any`, `browser-only`, `node-only`).
     - Resource profile and budgets.
     - Read/write side effects and determinism indicator.
     - Cancellation support and cursor-based pagination.
2. **Multi-Surface Dispatch**:
   - Web, CLI, and MCP surfaces act as thin protocol adapters routing requests to the operation registry.
   - Identical inputs yield identical canonical outputs regardless of surface.
   - CLI convenience subcommands (`bitpeek inspect`, `bitpeek nand`, etc.) route directly to corresponding registry operations.
3. **Automated Manifests**:
   - Public capability manifests (`capabilities.json`), documentation matrices, and MCP tool declarations are generated from this single registry.

## Consequences
- Single source of truth for all Bitpeek operations.
- Cross-surface semantic parity guaranteed by shared test fixtures.
