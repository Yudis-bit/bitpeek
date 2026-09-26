# ADR 0002: Zero-Upload Local-First Privacy Boundary

## Status
Accepted

## Context
Binary files inspected by engineers frequently contain sensitive material: firmware blobs, credentials, proprietary protocol dumps, memory snapshots, or vulnerability testcases. Uploading such binaries to remote servers or third-party cloud APIs poses severe privacy and security risks.

## Decision
1. All binary analysis, parsing, hashing, diffing, and editing in the web application must occur entirely client-side in the browser execution context.
2. The application architecture prohibits any backend processing endpoint, upload API, database storage, or remote telemetry server.
3. Hosting is static on Vercel; server interactions are strictly limited to fetching immutable static assets and documentation.
4. Content-Security-Policy (CSP) headers enforce restrictions on connect-src and form actions to guarantee that user byte data cannot be exfiltrated.
5. In the CLI and MCP environments, file analysis executes locally on the operator's machine within strict allowed-root boundaries.

## Consequences
- Guaranteed zero data leakage of user files to Bitpeek servers or third parties.
- Full offline operability once static web assets are cached by the browser.
- Free tier hosting remains predictable and indefinitely sustainable with zero backend compute costs.
