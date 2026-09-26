# ADR 0001: Unified TypeScript Core and Adapter Architecture

## Status
Accepted

## Context
Bitpeek requires consistent byte inspection, structure parsing (ELF, PNG, custom schemas), hashing, diffing, and patch application across three distinct operational environments:
1. Client-side browser web application.
2. CLI binary tool for automated scripting and terminal use.
3. Local Model Context Protocol (MCP) server for tool-using AI agents.

A rewrite into Rust/WASM was evaluated. However, WASM compilation adds bundle weight, increases memory serialization overhead between JavaScript ArrayBuffers and WASM linear memory, and complicates source-level debugging and web worker communication without demonstrating a profile-verified bottleneck on target files up to 64 MiB.

## Decision
1. Retain pure TypeScript as the core language for all parsers, algorithms, and validation engines located in `packages/core`.
2. Strictly forbid DOM, React, UI notifications, or Node filesystem imports in `packages/core`.
3. Abstract binary I/O via the `ByteSource` interface (`read`, `chunks`, `size`, `close`), with `MemoryByteSource` and `BlobByteSource` for browser contexts, and `FileByteSource` for Node.js/CLI/MCP environments.
4. Separate delivery adapters into `src/` (web UI), `packages/cli/` (terminal executable), and `packages/mcp/` (local stdio server).

## Consequences
- Single source of truth for all byte algorithms, preventing divergent behavior across Web, CLI, and MCP.
- Web bundle remains lightweight (under 95 KiB gzip initial payload).
- Zero external native compilation toolchains needed for builds or tests.
