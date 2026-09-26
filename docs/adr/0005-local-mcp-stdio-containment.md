# ADR 0005: Local MCP Stdio Server and Sandbox Containment

## Status
Accepted

## Context
AI developer agents require structured access to binary files without invoking shell commands or loading multi-megabyte raw binaries directly into LLM prompt contexts. Running arbitrary tool execution without boundaries can lead to directory traversal, accidental file overwrites, or secret leakage.

## Decision
1. Implement the local Model Context Protocol (MCP) server using the official `@modelcontextprotocol/sdk` over local `stdio` transport.
2. Maintain strict security boundaries via `McpSecurityManager`:
   - Configurable `allowedInputRoots` and `allowedOutputRoots`.
   - Realpath resolution to prevent directory traversal and symlink escapes.
   - Opaque session handles (`sess_<id>`) for opened documents; agents cannot pass arbitrary unverified file paths to read/inspect tools.
   - Bounded reading with default 4 KiB and max 64 KiB chunks per response.
   - Export tool is isolated to `allowedOutputRoots` with `fail-if-exists` by default.
3. Keep stdout strictly dedicated to JSON-RPC protocol frames; all diagnostics and errors stream to stderr.

## Consequences
- AI agents receive concise, structured tool responses suitable for prompt windows.
- Operator's filesystem is protected against unauthorized traversal or accidental data destruction.
