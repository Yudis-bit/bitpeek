# Changelog

All notable changes to Bitpeek are documented here in accordance with Semantic Versioning.

## Workbench interface refresh - 2026-09-27

- Rebuilt the interface around a warm paper palette, navy window chrome, clear type, and consistent desktop-style controls across the workbench, reference pages, and dialogs.
- Split the inspector into Values, Analysis, and Text & encoding views; added dedicated Bytes, Inspector, and Structure views on smaller screens.
- Added responsive eight-byte rows with matching keyboard navigation, larger byte cells, and visible editing hints.
- Improved file-action labels, copy controls, focus indicators, offset error feedback, and the structure panel toggle.
- Updated the site identity and install metadata while preserving byte-processing behavior and public routes.

## [1.0.0] - 2026-09-27

### Added
- **Structure Inspector**:
  - Interactive ELF parser (ELF32 and ELF64, Little-Endian and Big-Endian, e_ident, program headers, section headers, string table resolution).
  - PNG parser (signature, chunks, IHDR field mappings, chunk CRC-32 verification).
  - Custom Declarative Structure Schema engine supporting scalars, bitfields, fixed-length arrays, and structs.
  - Interactive tree UI with bi-directional field-to-byte range selection.
- **Unified Engine & Architecture**:
  - `packages/core`: Pure TypeScript algorithmic foundation with zero DOM/React dependencies.
  - `ByteSource` abstraction supporting memory buffers, blobs, and streaming file sources.
  - Pure incremental streaming SHA-256 (FIPS 180-4 compliant) with standard NIST test vector verification.
- **CLI & Automation**:
  - `bitpeek` CLI with subcommands: `inspect`, `find`, `strings`, `hash`, `structure`, `diff`, `patch verify`, `patch apply`, `recipe run`.
  - JSON output mode with clean stderr/stdout separation and standardized POSIX-compliant exit codes (0, 1, 2, 3, 4, 5, 130).
  - Atomic temporary file writes for safe patch exports.
- **Model Context Protocol (MCP)**:
  - Local stdio MCP tool server powered by official `@modelcontextprotocol/sdk`.
  - 12 official tools for AI agents (`bitpeek_capabilities`, `bitpeek_open`, `bitpeek_read`, `bitpeek_inspect`, `bitpeek_find`, `bitpeek_strings`, `bitpeek_structure`, `bitpeek_diff`, `bitpeek_verify_patch`, `bitpeek_run_recipe`, `bitpeek_export`, `bitpeek_close`).
  - Security containment manager with path canonicalization and restricted input/output roots.
- **Reproducibility & Evidence**:
  - Declarative Recipe Runner (`recipe-v1.json`) with deterministic verification.
  - Reproducible Evidence Report generator (`evidence-report-v1.json`) with configurable redaction for PR and bug bounty disclosures.
  - Offset Patch v2 specification with cryptographic SHA-256 integrity verification.
  - 7-step atomic verified patch application.
- **Documentation & Discovery**:
  - 14 technical manual and documentation guides (`/docs`, `/docs/quickstart`, `/docs/byte-semantics`, `/docs/structures`, `/docs/patches`, `/docs/recipes`, `/docs/cli`, `/docs/mcp`, `/docs/limits`, `/docs/privacy`, `/examples`, `/benchmarks`, `/about`, `/changelog`).
  - Public machine-readable manifests (`/capabilities.json`, `/version.json`, `/llms.txt`).
  - Public JSON schemas in `/schemas/`.
  - Preserved all 10 existing SEO landing pages and homepage with updated navigation.

### Fixed
- Fixed browser private browsing crash when `localStorage` is blocked via `SafeStorage` in-memory fallback.
- Fixed 0-byte document export bug, enabling valid 0-byte binary file creation.
- Eliminated draft state ambiguity: invalid drafts now clearly warn without replacing committed bytes.
- Implemented `UnifiedHistoryState` enabling full undo/redo across both patch and full replacement transactions.
