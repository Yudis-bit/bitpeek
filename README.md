# Bitpeek

A local-first binary workbench for inspecting bytes, checking structure, and reproducing changes in the browser, terminal, and AI tool contexts.

[Live Production Workbench](https://bitpeek-seven.vercel.app) · [Technical Documentation](https://bitpeek-seven.vercel.app/docs) · [Verified Upstream Track Record](https://bitpeek-seven.vercel.app/about)

---

## Key Differentiators
- **Field-to-Byte Semantic Mapping**: Click any structure field (in ELF, PNG, or declarative custom schemas) to highlight exact byte coordinates with interpretation rules and bounds checks.
- **Local-First & Zero-Upload**: All file reads, hashing, diffs, and edits execute entirely on your machine. No user bytes are ever uploaded to a server.
- **Unified Engine**: The exact same TypeScript core powers the web interface, the `bitpeek` CLI tool, and the local Model Context Protocol (MCP) server.
- **Reproducible Evidence**: Export verifiable audit reports and deterministic replay recipes suitable for GitHub issues, pull requests, and bug bounty disclosures.

---

## Workbench Features
- **secp256k1 Audit**: Check curve points, strict DER/compact ECDSA encoding, low-S policy, and Bitcoin transaction invariants; inspect x86-64/AArch64 snippets for timing hazards. See [API, recipes, and verification limits](docs/secp256k1-audit.md).
- **Input Modes**: Hexadecimal, binary, decimal, UTF-8 text, and Base64 with instant bidirectional synchronization.
- **Structure Inspector**: Real-time parser for ELF32/ELF64 (LE/BE), PNG chunk layout with CRC checks, and user-defined JSON schemas.
- **Byte Inspector**: Scaled integer decoding (8 to 64 bits), IEEE-754 single and double precision floats with raw bit display, ASCII, UTF-8, CRC-16, CRC-32, Sum-8, XOR-8, and streaming SHA-256 (FIPS 180-4).
- **Transforms & Transactional History**: Reversal, bitwise inversion, XOR masking, byte filling, byteswapping, and bit toggling with unbounded multi-level undo/redo.
- **Binary Diff & Offset Patches**: Synchronized comparison against a reference binary, generating verified offset patches with SHA-256 integrity checks.

---

## Command-Line Interface (`bitpeek`)
The Bitpeek CLI provides fast terminal binary operations and scriptable JSON piping with standard POSIX exit codes:

```sh
# Inspect scalar value at offset
bitpeek inspect firmware.bin --offset 0x1000 --length 4 --type u32 --endian le --json

# Find byte pattern with wildcards
bitpeek find firmware.bin --hex "7F 45 4C 46 ?? 01" --limit 10 --json

# Extract printable strings
bitpeek strings payload.bin --min-length 6 --json

# Compute streaming hash
bitpeek hash firmware.bin --algorithm sha256 --json

# Parse ELF or PNG structure
bitpeek structure kernel.elf --format elf --json

# Diff two binaries
bitpeek diff baseline.bin updated.bin --json

# Verify and atomically apply offset patch
bitpeek patch verify changes.json --source baseline.bin --json
bitpeek patch apply changes.json --source baseline.bin --output patched.bin
```

---

## Model Context Protocol (MCP) Server
Bitpeek provides a local stdio MCP server for AI developer tools implementing 17 tools, including direct secp256k1 and static timing audits. After `npm install`, launch the server with Node using the absolute path to its launcher:

```json
{
  "mcpServers": {
    "bitpeek": {
      "command": "node",
      "args": [
        "C:/Users/LENOVO/Documents/bugbounty/bitpeek/packages/mcp/bin/bitpeek-mcp.js",
        "--allowed-roots",
        "C:/Users/LENOVO/Documents/bugbounty"
      ]
    }
  }
}
```

The MCP server enforces path canonicalization, opaque session handles, and strictly contained filesystem boundaries.

Use `bitpeek_secp256k1_audit` for keys, ECDSA encodings, and raw Bitcoin transactions;
use `bitpeek_constant_time_audit` for selected x86-64/AArch64 code regions. Both accept
inline `rawHex` or a session `handle` with `offset` and `length`. See
[MCP examples and verification limits](docs/secp256k1-audit.md#mcp-tools).

---

## Built by Yudistira Putra (Yudis-bit)
Bitpeek is built and maintained by **Yudistira Putra** (`Yudis-bit`), with a focus on systems engineering, compiler semantics, buffer boundaries, and protocol correctness. Verified upstream contributions include:
- **LLVM / AMDGPU**: [PR #210583](https://github.com/llvm/llvm-project/pull/210583) — Preserved status register semantics for image loads with TFE/LWE.
- **Khronos Vulkan Validation Layers**: [PR #12743](https://github.com/KhronosGroup/Vulkan-ValidationLayers/pull/12743) — Fixed out-of-bounds access in static descriptor validation.
- **bitcoin-core/secp256k1**: [PR #1893](https://github.com/bitcoin-core/secp256k1/pull/1893) — Extended constant-time CHECKMEM verification for custom Schnorr signatures.
- **OpenSBI**: [Commit f95648d](https://github.com/riscv-software-src/opensbi/commit/f95648d3955d72f77e13315a990a6135303978a5) — Prevented buffer overflow in extension string formatting.
- **Microsoft MsQuic**: [PR #6320](https://github.com/microsoft/msquic/pull/6320) — Fixed source and destination memory ordering in header protection sampling.
- **Google Kafel**: [PR #46](https://github.com/google/kafel/pull/46) — Corrected syscall argument table definitions on m68k.

---

## Quality & Development
```sh
npm install
npm test         # Run unit, integration, and SEO verification tests
npm run lint     # Run ESLint validation
npm run build    # Typecheck, build production bundles, and verify size budgets
```

## License
[MIT](LICENSE)
