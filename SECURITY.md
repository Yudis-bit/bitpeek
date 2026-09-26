# Security Policy

## Security Model
Bitpeek operates under a zero-server upload security model:
- **Client-Side Isolation**: All byte parsing, editing, hashing, and patch operations run inside the client environment (browser memory or local Node process).
- **No Remote Processing**: User binary data is never transmitted to Bitpeek servers or third-party cloud services.
- **Untrusted Input Invariant**: All binary files and schemas are treated as untrusted. Parsers enforce strict range bounds, checked arithmetic, and allocation limits to mitigate resource exhaustion or parser denial of service.
- **MCP Containment**: The local MCP server enforces explicit directory boundaries (`allowedInputRoots` and `allowedOutputRoots`) and opaque session handles.

## Reporting a Vulnerability
If you discover a security vulnerability in Bitpeek, please report it responsibly:
- **Email**: `pyudistira519@gmail.com` (or create a private GitHub Security Advisory at [github.com/Yudis-bit/bitpeek/security/advisories](https://github.com/Yudis-bit/bitpeek/security/advisories)).
- Please include:
  1. Description of the issue (e.g. parser hang, directory traversal escape, improper memory exhaustion).
  2. Minimal reproducible steps and proof-of-concept fixture.
  3. Affected component (Web, CLI, or MCP).

We acknowledge reports promptly and coordinate responsible disclosures with regression tests.
