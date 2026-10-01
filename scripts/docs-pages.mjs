export const docsPages = [
  {
    type: 'doc',
    slug: '/docs',
    lastModified: '2026-09-27',
    label: 'Documentation',
    eyebrow: 'Technical Manual',
    title: 'Bitpeek Technical Documentation & Architecture Manual',
    description:
      'Documentation for the Bitpeek local-first binary workbench. Covers byte semantics, structure parsing, offset patches, CLI automation, and local MCP.',
    h1: 'Bitpeek Technical Documentation & Manual',
    lead: 'Read bytes, inspect file structures, compare changes, and export evidence. Includes browser, CLI, and MCP workflows.',
    ctaHref: '/?intent=open#workspace',
    ctaLabel: 'Open the workbench',
    ctaHeading: 'Start inspecting bytes in Bitpeek',
    ctaText:
      'Open local files up to 512 MiB. Use the guides below for editing, analysis, and automation.',
    sections: [
      {
        id: 'architecture-overview',
        title: 'Architecture & Engine Design',
        html: `
          <p>Bitpeek processes files locally. The shared engine is separate from its browser, CLI, and MCP interfaces:</p>
          <ul>
            <li><strong>packages/core</strong>: A pure TypeScript engine containing parsers (ELF, PNG, declarative schemas), byte streaming abstractions (<code>ByteSource</code>), hashing algorithms (FIPS 180-4 SHA-256, CRC-32, CRC-16), offset diffing, and declarative recipe execution. It has zero dependencies on React, the DOM, or Node.js.</li>
            <li><strong>src/ (Web Workbench)</strong>: React 19 interface with virtualized hex and ASCII grid rendering, real-time structure tree navigation, bit toggling, and in-memory transactional history.</li>
            <li><strong>packages/cli</strong>: Standalone Node.js CLI executable (<code>bitpeek</code>) providing scriptable JSON output, standard POSIX exit codes, and atomic file writes.</li>
            <li><strong>packages/mcp</strong>: Local Model Context Protocol (MCP) server communicating over <code>stdio</code>, exposing 12 structured tools for autonomous developer agents.</li>
          </ul>
        `,
      },
      {
        id: 'core-differentiators',
        title: 'Workspace features',
        html: `
          <p>The workspace connects parsed fields, raw bytes, and reproducible operations:</p>
          <ul>
            <li><strong>Field-to-Byte Semantic Mapping</strong>: High-level structural fields (such as ELF section headers or PNG chunk lengths) are mapped directly to exact byte coordinates in the raw binary view.</li>
            <li><strong>Zero Server Uploads</strong>: All byte analysis and manipulation execute entirely within the user's local execution environment. No bytes ever leave your device.</li>
            <li><strong>Cross-Platform Parity</strong>: The exact same TypeScript core powers the web interface, the CLI binary, and the MCP agent server, using the same parsers and byte operations.</li>
            <li><strong>Verifiable Evidence & Replay</strong>: Export reproducible markdown summaries, JSON evidence reports, and declarative replay recipes suitable for pull requests and bug bounty submissions.</li>
          </ul>
        `,
      },
      {
        id: 'documentation-index',
        title: 'Documentation Index',
        html: `
          <p>Explore the specialized documentation sections:</p>
          <ul>
            <li><a href="/docs/quickstart">Quickstart Guide</a>: Three hands-on tasks to get started in minutes.</li>
            <li><a href="/docs/byte-semantics">Byte Semantics</a>: Ranges, endianness, 64-bit integer strings, and float representations.</li>
            <li><a href="/docs/structures">Structure Inspector</a>: ELF32/ELF64, PNG chunk layout, and custom JSON schemas.</li>
            <li><a href="/docs/patches">Patches & Diff</a>: Offset-aligned diff semantics, precondition checks, and atomic apply.</li>
            <li><a href="/docs/recipes">Recipes & Replay</a>: Declarative automation pipelines for multi-step transforms.</li>
            <li><a href="/docs/cli">CLI Reference</a>: Terminal commands, arguments, exit codes, and piping.</li>
            <li><a href="/docs/mcp">MCP Server</a>: Setup for Claude Desktop, Cursor, and security containment.</li>
            <li><a href="/docs/limits">Limits & Budgets</a>: Memory constraints, streaming chunk sizes, and platform guarantees.</li>
            <li><a href="/docs/privacy">Privacy Architecture</a>: Client-only guarantees, CSP enforcement, and data flows.</li>
          </ul>
        `,
      },
    ],
    faqs: [
      {
        question: 'Is Bitpeek free and open source?',
        answer:
          'Yes. Bitpeek is licensed under the permissive MIT license and hosted openly on GitHub.',
      },
      {
        question: 'Does Bitpeek require an account or API key?',
        answer:
          'No. Bitpeek requires no login, no accounts, and no paid API keys. The app processes files locally. Tools loaded on demand need a connection on first use.',
      },
      {
        question: 'Can Bitpeek be used in CI/CD pipelines?',
        answer:
          'Yes. The bitpeek CLI provides exit code 0 on success, exit code 4 on verification failure, and JSON output for automated scripting.',
      },
    ],
    related: [
      { slug: '/docs/quickstart', label: 'Quickstart guide', note: 'Start with 3 practical tasks' },
      {
        slug: '/docs/byte-semantics',
        label: 'Byte semantics',
        note: 'Coordinate and numeric rules',
      },
      {
        slug: '/docs/structures',
        label: 'Structure inspector',
        note: 'ELF, PNG, and custom schemas',
      },
    ],
  },
  {
    type: 'doc',
    slug: '/docs/quickstart',
    lastModified: '2026-09-27',
    label: 'Quickstart',
    eyebrow: 'Hands-on Guide',
    title: 'Quickstart Guide: Fast Binary Inspection with Bitpeek',
    description:
      'Learn three essential binary inspection workflows in Bitpeek: inspecting header fields, detecting byte patterns, and generating atomic offset diff patches.',
    h1: 'Quickstart Guide for Binary Inspection',
    lead: 'Three realistic inspection tasks demonstrating byte navigation, field highlight inspection, and reproducible patch creation in under five minutes.',
    ctaHref: '/?intent=open#workspace',
    ctaLabel: 'Try the quickstart in Bitpeek',
    ctaHeading: 'Open the interactive workbench',
    ctaText:
      'Follow along with these three tasks by opening the Bitpeek workbench in your browser.',
    sections: [
      {
        id: 'task-1-header-inspection',
        title: 'Task 1: Inspecting an Unknown File Header',
        html: `
          <p>When investigating an unfamiliar binary blob, determining its signature and initial header fields is the first step:</p>
          <ol>
            <li>Open the Bitpeek workbench and click <strong>Open</strong> to select a binary file, or paste hex bytes into the input box.</li>
            <li>Observe the <strong>Interpretation Panel</strong> on the right. Bitpeek immediately displays detected file signatures (e.g. <code>ELF</code>, <code>PNG</code>, <code>ZIP</code>).</li>
            <li>Select the first 4 bytes (offset <code>0x00..0x04</code>). Review the 32-bit unsigned integer values displayed in both <em>Little-Endian</em> and <em>Big-Endian</em> format.</li>
            <li>If the file is an ELF or PNG, the <strong>Structure</strong> panel automatically parses header fields. Click any field (such as <code>e_type</code> or <code>IHDR.width</code>) to highlight its exact byte coordinates in the hex grid.</li>
          </ol>
        `,
      },
      {
        id: 'task-2-pattern-search',
        title: 'Task 2: Searching with Hex Wildcards & String Scans',
        html: `
          <p>Locating specific opcodes or memory patterns often requires wildcard searches:</p>
          <ol>
            <li>Press <kbd>Ctrl+F</kbd> (or <kbd>Cmd+F</kbd>) to focus the byte search input.</li>
            <li>Select <strong>Hex</strong> mode and type a wildcard pattern such as <code>DE ?? BE EF</code>. Bitpeek finds matches where the second byte can be any value.</li>
            <li>Use the navigation arrows to jump between match offsets in the byte table.</li>
            <li>Click <strong>Strings</strong> in the toolbar to scan for printable ASCII and UTF-16 strings with their exact file offsets. Selecting any string navigates directly to those bytes.</li>
          </ol>
        `,
      },
      {
        id: 'task-3-diff-patch',
        title: 'Task 3: Comparing Two Binaries and Exporting a Verified Patch',
        html: `
          <p>Compare an edited file against an original baseline and generate a verifiable patch:</p>
          <ol>
            <li>Load your current working binary into the workbench.</li>
            <li>Click <strong>Compare</strong> in the input toolbar and select the baseline reference binary.</li>
            <li>The <strong>DiffBar</strong> displays the count of modified bytes and ranges. Use the arrow buttons to step through each differing offset.</li>
            <li>Click <strong>Download patch</strong> to export an atomic <code>.bitpeek.patch.json</code> file containing SHA-256 hashes and byte preconditions.</li>
          </ol>
        `,
      },
    ],
    faqs: [
      {
        question: 'Can I undo my edits if I make a mistake?',
        answer:
          'Yes. Press Ctrl+Z or Cmd+Z (or click Undo in the toolbar) to revert any byte edit, bit toggle, or transform transaction.',
      },
      {
        question: 'Does Bitpeek modify my original file on disk?',
        answer:
          'No. Bitpeek operates entirely in browser memory. Clicking Save triggers a new file download without touching the source file.',
      },
    ],
    related: [
      { slug: '/docs', label: 'Documentation index', note: 'Complete architecture manual' },
      { slug: '/docs/byte-semantics', label: 'Byte semantics', note: 'Data representation rules' },
      {
        slug: '/docs/structures',
        label: 'Structure inspector',
        note: 'Deep dive into ELF and PNG',
      },
    ],
  },
  {
    type: 'doc',
    slug: '/docs/byte-semantics',
    lastModified: '2026-09-27',
    label: 'Byte semantics',
    eyebrow: 'Data Representation',
    title: 'Byte Semantics & Numeric Representation Guide | Bitpeek',
    description:
      'Understand how Bitpeek encodes half-open byte ranges, little and big endian integers, IEEE-754 floating-point numbers, and text encodings with zero loss.',
    h1: 'Byte Semantics and Numeric Representations',
    lead: 'Mathematical and algorithmic rules governing half-open intervals, 64-bit integer strings, raw float bits, and character encoding transformations.',
    ctaHref: '/?mode=hex#workspace',
    ctaLabel: 'Test byte conversions',
    ctaHeading: 'Explore numeric representations',
    ctaText:
      'Enter byte values in the Bitpeek workspace to observe real-time interpretations across formats.',
    sections: [
      {
        id: 'half-open-intervals',
        title: 'Coordinate System: Half-Open Intervals',
        html: `
          <p>All internal ranges across the Bitpeek core, CLI, MCP tools, and recipes adhere to the standard mathematical convention of half-open intervals: <code>[start, endExclusive)</code>.</p>
          <ul>
            <li><code>start</code>: The 0-based index of the first byte included in the range.</li>
            <li><code>end</code>: The 0-based index of the first byte excluded from the range.</li>
            <li><code>length</code>: Always equal to <code>end - start</code>.</li>
            <li>A range of length 0 (e.g. <code>[4, 4)</code>) represents an insertion point with zero bytes.</li>
          </ul>
          <p>In user-facing UI displays, coordinates are presented clearly with bracket notation (e.g. <code>[0x00..0x04)</code>) so developers never confuse inclusive bounds with half-open slices.</p>
        `,
      },
      {
        id: 'integer-fidelity',
        title: '64-Bit Integer Precision & JSON Serialization',
        html: `
          <p>Standard JavaScript numbers use IEEE-754 double precision floats, which can only represent integers accurately up to 2<sup>53</sup> - 1 (<code>9,007,199,254,740,991</code>). Values above this threshold lose precision silently.</p>
          <p>Bitpeek solves this issue definitively:</p>
          <ul>
            <li>64-bit unsigned (<code>u64</code>) and signed (<code>i64</code>) integers are parsed using native <code>BigInt</code> arithmetic.</li>
            <li>In JSON API responses, CLI outputs, and MCP tool payloads, 64-bit integers are encoded as exact decimal strings (e.g. <code>"18446744073709551615"</code>) rather than truncated numbers.</li>
          </ul>
        `,
      },
      {
        id: 'float-semantics',
        title: 'Floating-Point Semantics: NaN Payloads & Signed Zero',
        html: `
          <p>When inspecting IEEE-754 floating-point numbers (16-bit half precision, 32-bit single precision, and 64-bit double precision), Bitpeek preserves critical edge cases:</p>
          <ul>
            <li><strong>Positive and Negative Zero</strong>: <code>+0.0</code> and <code>-0.0</code> are distinguished and preserved.</li>
            <li><strong>Infinities</strong>: <code>+Infinity</code> and <code>-Infinity</code> are explicitly serialized.</li>
            <li><strong>NaN Payloads</strong>: Because JavaScript <code>JSON.stringify</code> converts <code>NaN</code> to <code>null</code>, Bitpeek displays both the floating-point interpretation and the exact raw hexadecimal bits so NaN diagnostic payloads are never lost.</li>
          </ul>
        `,
      },
    ],
    faqs: [
      {
        question: 'Why are 64-bit numbers returned as strings in JSON?',
        answer:
          'To prevent silent precision loss caused by standard JSON parsers converting integers above 2^53 - 1 into double-precision approximations.',
      },
      {
        question: 'How does Bitpeek handle invalid UTF-8 sequences?',
        answer:
          'Invalid UTF-8 byte sequences are highlighted with error flags, and non-printable bytes in ASCII columns are displayed as safe dots (.) rather than broken replacement characters.',
      },
    ],
    related: [
      { slug: '/docs', label: 'Documentation index', note: 'Architecture and core contracts' },
      { slug: '/docs/structures', label: 'Structure inspector', note: 'Struct field mapping' },
      { slug: '/docs/patches', label: 'Patches & diff', note: 'Offset-aligned diff semantics' },
    ],
  },
  {
    type: 'doc',
    slug: '/docs/structures',
    lastModified: '2026-09-27',
    label: 'Structures',
    eyebrow: 'Format Specification',
    title: 'Binary Structure Inspection: ELF, PNG, and Schemas',
    description:
      'Inspect ELF binaries, PNG chunks with CRC verification, and custom declarative JSON schemas. Map high-level structural fields directly to raw source bytes.',
    h1: 'Structured Binary Inspection: ELF, PNG, & Schemas',
    lead: 'Real-time parsing of ELF32/ELF64 headers, PNG chunk hierarchies with CRC verification, and declarative custom schemas with direct field-to-byte highlighting.',
    ctaHref: '/file-formats/elf',
    ctaLabel: 'View ELF format reference',
    ctaHeading: 'Explore binary file structures',
    ctaText:
      'Open an ELF or PNG file in Bitpeek to see real-time structure tree parsing and byte mapping.',
    sections: [
      {
        id: 'elf-parser',
        title: 'ELF32 & ELF64 Inspection',
        html: `
          <p>The Bitpeek ELF engine parses Executable and Linkable Format binaries according to the System V ABI specification without running external tools like <code>readelf</code>:</p>
          <ul>
            <li><strong>Class & Data Detection</strong>: Reads <code>EI_CLASS</code> (ELF32 vs ELF64) and <code>EI_DATA</code> (Little-Endian vs Big-Endian) from the 16-byte <code>e_ident</code> array.</li>
            <li><strong>ELF Header</strong>: Parses object type (<code>e_type</code>), machine architecture (<code>e_machine</code>), entry point (<code>e_entry</code>), and table offsets.</li>
            <li><strong>Section Header Table</strong>: Resolves section offsets, sizes, flags, and reads section names directly from the string table (<code>.shstrtab</code>).</li>
            <li><strong>Program Header Table</strong>: Parses segments, memory permissions, virtual addresses, and alignment constraints.</li>
            <li><strong>Boundary Safety</strong>: Bounds-checks all offsets, arithmetic multiplications, and table counts. Truncated headers trigger structured warnings rather than crashes.</li>
          </ul>
        `,
      },
      {
        id: 'png-parser',
        title: 'PNG Chunks & CRC-32 Validation',
        html: `
          <p>The PNG inspector validates Portable Network Graphics files according to the W3C PNG 3rd Edition specification:</p>
          <ul>
            <li><strong>Signature Verification</strong>: Confirms the 8-byte magic sequence: <code>89 50 4E 47 0D 0A 1A 0A</code>.</li>
            <li><strong>Chunk Hierarchy</strong>: Iterates through chunks (<code>IHDR</code>, <code>PLTE</code>, <code>IDAT</code>, <code>IEND</code>, and ancillary chunks), extracting length, type, and data bounds.</li>
            <li><strong>CRC-32 Integrity Checks</strong>: Computes the IEEE 802.3 CRC-32 over chunk type and data bytes, comparing it against the stored CRC. Any altered byte triggers an immediate CRC mismatch alert.</li>
            <li><strong>IHDR Field Breakdown</strong>: Maps image width, height, bit depth, color type, compression method, filter method, and interlace method to exact byte slices.</li>
          </ul>
        `,
      },
      {
        id: 'custom-schemas',
        title: 'Declarative Custom Structure Schemas',
        html: `
          <p>Define proprietary binary protocols and file headers using declarative JSON schemas (<code>schema-definition-v1.json</code>):</p>
          <ul>
            <li><strong>Scalar Types</strong>: <code>u8</code>, <code>i8</code>, <code>u16</code>, <code>i16</code>, <code>u32</code>, <code>i32</code>, <code>u64</code>, <code>i64</code>, <code>f32</code>, <code>f64</code>.</li>
            <li><strong>Bitfields</strong>: Extract specific bit ranges from container integers by defining <code>containerType</code>, <code>lsb</code>, and <code>width</code>.</li>
            <li><strong>Arrays & Strings</strong>: Fixed-count arrays, ASCII strings, and raw byte buffers.</li>
            <li><strong>Zero Eval / Safe Execution</strong>: Schemas are purely declarative data definitions. No JavaScript code or external network resources are evaluated.</li>
          </ul>
        `,
      },
    ],
    faqs: [
      {
        question: 'Does Bitpeek execute or decompile ELF binaries?',
        answer:
          'No. Bitpeek is strictly a passive structural parser and hex inspector. It never executes code or runs dynamic analysis.',
      },
      {
        question: 'Can I load my own custom schema in the browser?',
        answer:
          'Yes. Click Load Custom Schema in the Structure panel and paste your JSON schema definition to inspect any custom format.',
      },
    ],
    related: [
      {
        slug: '/docs/byte-semantics',
        label: 'Byte semantics',
        note: 'Endianness and scalar rules',
      },
      { slug: '/docs/patches', label: 'Patches & diff', note: 'Verifying structure mutations' },
      { slug: '/docs/recipes', label: 'Recipes & replay', note: 'Automating structure checks' },
    ],
  },
  {
    type: 'doc',
    slug: '/docs/patches',
    lastModified: '2026-09-27',
    label: 'Patches',
    eyebrow: 'Diff & Patching',
    title: 'Offset-Aligned Binary Patches & Verification | Bitpeek',
    description:
      'Specification for bitpeek-offset-patch formats v1 and v2. Learn how precondition checks and cryptographic SHA-256 hashes guarantee atomic patch application.',
    h1: 'Offset-Aligned Binary Patches and Verification',
    lead: 'Deterministic binary difference recording using absolute byte offsets, strict preconditions, and cryptographic SHA-256 verification.',
    ctaHref: '/tools/binary-diff',
    ctaLabel: 'Try binary diff tool',
    ctaHeading: 'Compare binary files online',
    ctaText:
      'Load two binaries in Bitpeek to generate reproducible offset patches with precondition checks.',
    sections: [
      {
        id: 'offset-patch-concept',
        title: 'Why Offset-Aligned Binary Patches?',
        html: `
          <p>Traditional textual diff algorithms (such as Myers or unified diff) are designed for line-oriented text files. When applied to binaries, insert/delete shifts invalidate absolute offsets, making verification unreliable.</p>
          <p>Bitpeek uses <strong>Offset-Aligned Binary Patches</strong>:</p>
          <ul>
            <li>Operations reference absolute byte offsets in the source file.</li>
            <li>Every mutation includes a <code>precondition</code>: the exact expected bytes that must exist at that offset in the source.</li>
            <li>If any precondition fails, the patch application aborts immediately without corrupting the file.</li>
          </ul>
        `,
      },
      {
        id: 'patch-v1-vs-v2',
        title: 'Specification: Format v1 vs v2',
        html: `
          <p>Bitpeek supports two versions of the <code>bitpeek-offset-patch</code> specification:</p>
          <ul>
            <li><strong>Version 1 (Preconditions-Only)</strong>: Legacy format recording target length and replacement operations with optional byte preconditions. Supported for backwards compatibility.</li>
            <li><strong>Version 2 (Cryptographic Integrity)</strong>: Modern format requiring source file length, target file length, <code>sourceSha256</code>, and <code>targetSha256</code>. Patches can be independently verified before touching disk.</li>
          </ul>
        `,
      },
      {
        id: 'atomic-apply-algorithm',
        title: 'The 7-Step Atomic Apply Algorithm',
        html: `
          <p>Applying a verified patch follows a strict 7-step atomic pipeline:</p>
          <ol>
            <li><strong>Source Stabilization</strong>: Acquire an immutable snapshot of source bytes.</li>
            <li><strong>Schema & Budget Validation</strong>: Check that target length and operation counts are within resource limits.</li>
            <li><strong>Source Integrity Verification</strong>: Validate source length and verify <code>sourceSha256</code> if provided.</li>
            <li><strong>Precondition Checks</strong>: Verify that every replacement offset matches the expected precondition bytes in the source.</li>
            <li><strong>Target Assembly</strong>: Construct the target binary in a newly allocated buffer.</li>
            <li><strong>Target Integrity Verification</strong>: Compute the SHA-256 hash of the generated target and assert that it matches <code>targetSha256</code>.</li>
            <li><strong>Atomic Commit</strong>: Commit the new binary as a single transaction in UI history or write to a temporary file before renaming on disk.</li>
          </ol>
        `,
      },
    ],
    faqs: [
      {
        question: 'What happens if a patch is applied to the wrong source file?',
        answer:
          'The patch fails immediately during source hash or precondition checks, leaving the original file completely untouched.',
      },
      {
        question: 'Can offset patches change the length of a file?',
        answer:
          'Yes. Target length can truncate or extend a binary; extensions append data, while mutations modify bytes at specified offsets.',
      },
    ],
    related: [
      { slug: '/docs/recipes', label: 'Recipes & replay', note: 'Chaining patches in recipes' },
      { slug: '/docs/cli', label: 'CLI manual', note: 'Applying patches from the terminal' },
      { slug: '/docs/byte-semantics', label: 'Byte semantics', note: 'Range and integer rules' },
    ],
  },
  {
    type: 'doc',
    slug: '/docs/recipes',
    lastModified: '2026-09-27',
    label: 'Recipes',
    eyebrow: 'Automated Replay',
    title: 'Deterministic Replay Recipes & Pipelines | Bitpeek',
    description:
      'Execute automated binary operation sequences using declarative recipe JSON. Reproduce transforms, checks, and evidence across Web, CLI, and MCP engines.',
    h1: 'Deterministic Binary Replay Recipes',
    lead: 'A declarative, versioned execution model for chaining binary inspections, transforms, searches, and validations with deterministic expected outputs.',
    ctaHref: '/examples',
    ctaLabel: 'View runnable recipe examples',
    ctaHeading: 'Explore verified replay recipes',
    ctaText: 'See complete, runnable recipe JSON documents for real-world binary validation tasks.',
    sections: [
      {
        id: 'recipe-concept',
        title: 'Declarative Binary Automation',
        html: `
          <p>Debugging binary issues often requires executing a series of precise steps: selecting a range, reversing endianness, verifying a checksum, applying an XOR mask, or checking a struct field.</p>
          <p>Bitpeek <strong>Recipes</strong> codify these operations into a versioned, declarative JSON document (<code>recipe-v1.json</code>) that can be replayed deterministically across Web, CLI, and MCP environments.</p>
        `,
      },
      {
        id: 'supported-operations',
        title: 'Supported Recipe Operations',
        html: `
          <p>Version 1 of the Recipe Runner supports twelve pure algorithmic operations:</p>
          <ul>
            <li><code>inspect-scalar</code>: Decodes unsigned/signed integers or floats at specified offsets.</li>
            <li><code>reverse</code>: Reverses byte order across the selected range.</li>
            <li><code>invert</code>: Flips all bits across the selection.</li>
            <li><code>xor-mask</code>: Applies a repeating byte mask across selected bytes.</li>
            <li><code>fill</code>: Fills the selected range with a constant byte value (0..255).</li>
            <li><code>byteswap</code>: Swaps endianness in 2, 4, or 8-byte word groupings.</li>
            <li><code>find-pattern</code>: Searches for exact or wildcard byte patterns.</li>
            <li><code>extract-strings</code>: Scans for printable ASCII or UTF-16 text.</li>
            <li><code>compute-hash</code>: Calculates SHA-256, CRC-32, or CRC-16 checksums.</li>
            <li><code>inspect-structure</code>: Parses ELF, PNG, or custom schema hierarchies.</li>
            <li><code>diff</code>: Compares working bytes against a secondary reference input.</li>
            <li><code>apply-patch</code>: Atomically applies a verified offset patch.</li>
          </ul>
        `,
      },
      {
        id: 'determinism-and-checks',
        title: 'Expected Outputs & Dry-Run Mode',
        html: `
          <p>Each recipe step can declare <code>expectedOutputs</code> containing assertion checks (such as expected SHA-256 hash or scalar values). If any check fails, execution halts with an explicit error code.</p>
          <p>In dry-run mode (<code>--dry-run</code>), the recipe engine executes all steps in memory and returns the complete result report without writing any files to disk.</p>
        `,
      },
    ],
    faqs: [
      {
        question: 'Does a recipe embed the binary file inside the JSON?',
        answer:
          'No. Recipes separate code from data; inputs specify file IDs, expected byte lengths, and SHA-256 fingerprints to ensure correct input binding.',
      },
      {
        question: 'Can recipes run arbitrary JavaScript or shell scripts?',
        answer:
          'No. Recipes are strictly declarative JSON specifications executed by the sandboxed Bitpeek core. No arbitrary code execution is permitted.',
      },
    ],
    related: [
      { slug: '/docs/cli', label: 'CLI manual', note: 'Running recipes with bitpeek recipe run' },
      { slug: '/docs/mcp', label: 'MCP server', note: 'AI agent recipe execution' },
      { slug: '/examples', label: 'Verified examples', note: 'Explore four core recipe demos' },
    ],
  },
  {
    type: 'doc',
    slug: '/docs/cli',
    lastModified: '2026-09-27',
    label: 'CLI',
    eyebrow: 'Command-Line Tool',
    title: 'Bitpeek CLI Manual: Binary Inspection in the Terminal',
    description:
      'Complete command-line manual for bitpeek. Inspect, find, hash, diff, and patch binary files from your terminal with scriptable JSON output and POSIX exits.',
    h1: 'Bitpeek Command-Line Interface Manual',
    lead: 'Automate binary inspection, searches, hashing, structure parsing, and atomic patch application in CI/CD pipelines and shell environments.',
    ctaHref: '/docs/quickstart',
    ctaLabel: 'Read quickstart guide',
    ctaHeading: 'Automate binary inspection',
    ctaText: 'Use the bitpeek CLI tool in shell scripts, Makefiles, and GitHub Actions workflows.',
    sections: [
      {
        id: 'installation-and-usage',
        title: 'Installation & Basic Usage',
        html: `
          <p>The Bitpeek CLI executable is bundled in the <code>packages/cli</code> package and can be run via Node.js:</p>
          <pre><code># Display version and general help
bitpeek --version
bitpeek --help</code></pre>
        `,
      },
      {
        id: 'subcommands',
        title: 'Available Subcommands',
        html: `
          <ul>
            <li><code>bitpeek inspect &lt;file&gt; [--offset &lt;n&gt;] [--length &lt;n&gt;] [--type &lt;t&gt;] [--endian &lt;le|be&gt;] [--json]</code></li>
            <li><code>bitpeek find &lt;file&gt; (--hex &lt;pattern&gt; | --text &lt;str&gt;) [--limit &lt;n&gt;] [--cursor &lt;n&gt;] [--json]</code></li>
            <li><code>bitpeek strings &lt;file&gt; [--min-length &lt;n&gt;] [--limit &lt;n&gt;] [--json]</code></li>
            <li><code>bitpeek hash &lt;file&gt; [--algorithm &lt;sha256|crc32|crc16&gt;] [--json]</code></li>
            <li><code>bitpeek structure &lt;file&gt; [--format &lt;elf|png|custom-schema&gt;] [--schema &lt;file.json&gt;] [--json]</code></li>
            <li><code>bitpeek diff &lt;reference&gt; &lt;current&gt; [--json] [--check]</code></li>
            <li><code>bitpeek patch verify &lt;patch.json&gt; --source &lt;reference&gt; [--json]</code></li>
            <li><code>bitpeek patch apply &lt;patch.json&gt; --source &lt;reference&gt; --output &lt;result&gt; [--force]</code></li>
            <li><code>bitpeek recipe run &lt;recipe.json&gt; [--input &lt;id=file&gt;...] [--dry-run] [--json]</code></li>
          </ul>
        `,
      },
      {
        id: 'exit-codes',
        title: 'Standardized Exit Codes',
        html: `
          <p>The CLI adheres to strict POSIX exit code conventions for predictable shell integration:</p>
          <ul>
            <li><code>0</code>: Success (including diff runs where differences were detected).</li>
            <li><code>1</code>: Internal error or unclassified I/O error.</li>
            <li><code>2</code>: Invalid command-line usage or missing arguments.</li>
            <li><code>3</code>: Invalid input format, malformed hex string, or out-of-bounds range.</li>
            <li><code>4</code>: Integrity verification failed, precondition check failed, or hash mismatch.</li>
            <li><code>5</code>: Resource budget or file size limit exceeded.</li>
            <li><code>130</code>: Process interrupted by user (SIGINT / Ctrl+C).</li>
          </ul>
        `,
      },
    ],
    faqs: [
      {
        question: 'Can I pipe the JSON output into jq?',
        answer:
          'Yes. When --json is specified, all diagnostics and progress stream to stderr, keeping stdout clean for piping directly into jq.',
      },
      {
        question: 'Does bitpeek patch apply overwrite files by default?',
        answer:
          'No. The CLI defaults to fail-if-exists for all output files. Overwriting an existing destination requires the explicit --force flag.',
      },
    ],
    related: [
      { slug: '/docs/recipes', label: 'Recipes & replay', note: 'Running automated recipes' },
      { slug: '/docs/mcp', label: 'MCP server', note: 'AI agent tools' },
      { slug: '/docs/limits', label: 'Limits & budgets', note: 'Streaming chunk sizes' },
    ],
  },
  {
    type: 'doc',
    slug: '/docs/mcp',
    lastModified: '2026-09-27',
    label: 'MCP server',
    eyebrow: 'Model Context Protocol',
    title: 'Local MCP Server for AI Agent Binary Tools | Bitpeek',
    description:
      'Equip AI developer tools with local binary inspection tools using the Model Context Protocol. Stdio transport, opaque sessions, and sandboxed root boundaries.',
    h1: 'Local Model Context Protocol (MCP) Server',
    lead: 'A secure stdio MCP tool server providing 12 specialized binary inspection and diff tools for AI developer agents like Claude, Cursor, and Antigravity.',
    ctaHref: '/docs/cli',
    ctaLabel: 'View CLI reference',
    ctaHeading: 'Equip AI agents with binary tools',
    ctaText: 'Learn how to configure the local Bitpeek MCP server in your AI coding assistant.',
    sections: [
      {
        id: 'mcp-overview',
        title: 'Why MCP for Binary Data?',
        html: `
          <p>Large Language Models cannot reliably parse raw binary buffers injected directly into prompt context windows. Binary data consumes excessive tokens, triggers hallucinations, and risks encoding errors.</p>
          <p>The Bitpeek <strong>Model Context Protocol (MCP)</strong> server solves this by exposing 12 structured inspection and transformation tools over local <code>stdio</code> transport.</p>
        `,
      },
      {
        id: 'mcp-tools-list',
        title: 'The 12 Official Bitpeek MCP Tools',
        html: `
          <ul>
            <li><code>bitpeek_capabilities</code>: Returns supported schemas, limits, and format versions.</li>
            <li><code>bitpeek_open</code>: Registers a local file within allowed roots and returns an opaque session handle.</li>
            <li><code>bitpeek_read</code>: Reads bounded byte slices (default 4 KiB, max 64 KiB) as hex and ASCII.</li>
            <li><code>bitpeek_inspect</code>: Decodes scalars, checksums, and hashes across a specific byte range.</li>
            <li><code>bitpeek_find</code>: Searches for hex or text patterns with pagination cursors.</li>
            <li><code>bitpeek_strings</code>: Extracts printable ASCII and UTF-16 text runs.</li>
            <li><code>bitpeek_structure</code>: Returns parsed ELF, PNG, or schema trees with field coordinates.</li>
            <li><code>bitpeek_diff</code>: Computes differences between two registered file sessions.</li>
            <li><code>bitpeek_verify_patch</code>: Validates patch preconditions and cryptographic SHA-256 hashes.</li>
            <li><code>bitpeek_run_recipe</code>: Executes multi-step declarative recipes with dry-run support.</li>
            <li><code>bitpeek_export</code>: Writes modified binaries safely to allowed output directories.</li>
            <li><code>bitpeek_close</code>: Closes session handles and frees system resources.</li>
          </ul>
        `,
      },
      {
        id: 'mcp-security',
        title: 'Security Sandbox & Containment',
        html: `
          <p>To protect the host system, <code>McpSecurityManager</code> enforces strict containment:</p>
          <ul>
            <li><strong>Path Canonicalization</strong>: Resolves realpaths to block directory traversal and symlink escapes.</li>
            <li><strong>Allowed Roots</strong>: Restricts file access strictly to operator-configured directory paths.</li>
            <li><strong>Opaque Handles</strong>: Agents cannot inject raw filesystem paths into read/inspect tools; all access uses opaque handles (<code>sess_&lt;id&gt;</code>).</li>
            <li><strong>Output Isolation</strong>: Exports cannot overwrite source files and are restricted to designated output directories.</li>
          </ul>
        `,
      },
    ],
    faqs: [
      {
        question: 'Does the MCP server connect to external cloud APIs?',
        answer:
          'No. The Bitpeek MCP server runs completely locally via standard input/output (stdio). It makes no outbound network connections.',
      },
      {
        question: 'Can the MCP server read sensitive system files?',
        answer:
          'No. Access is restricted strictly to directories explicitly specified in the --allowed-roots configuration.',
      },
    ],
    related: [
      { slug: '/docs/cli', label: 'CLI manual', note: 'Terminal command reference' },
      { slug: '/docs/privacy', label: 'Privacy model', note: 'Data handling boundaries' },
      { slug: '/examples', label: 'Verified examples', note: 'AI agent evidence demonstration' },
    ],
  },
  {
    type: 'doc',
    slug: '/docs/limits',
    lastModified: '2026-09-27',
    label: 'Limits & budgets',
    eyebrow: 'Operational Bounds',
    title: 'Operational Limits, Budgets, and Browser Guarantees',
    description:
      'Transparent operational limits and memory budgets for Bitpeek. Details workspace caps, bounded streaming, chunk sizes, and browser compatibility limits.',
    h1: 'Operational Limits and Performance Budgets',
    lead: 'Detailed technical limits, bounded memory allocations, streaming chunk sizes, and platform guarantees for local-first binary processing.',
    ctaHref: '/benchmarks',
    ctaLabel: 'View benchmark metrics',
    ctaHeading: 'Measured performance data',
    ctaText:
      'Review real-world latency, memory retention, and throughput metrics across file sizes.',
    sections: [
      {
        id: 'file-size-limits',
        title: 'File Size Limits & Operating Modes',
        html: `
          <p>Different operations have different limits:</p>
          <ul>
            <li><strong>Source input</strong>: 256 KiB for typed or pasted bytes.</li><li><strong>File editing</strong>: Files up to 512 MiB use a piece table and 64 KiB viewing windows. Byte edits, insertion, deletion, and undo/redo do not copy the entire file.</li>
            <li><strong>Analysis</strong>: Search, ASCII string extraction, entropy maps, and SHA-256 run in background workers for files up to 512 MiB. Structure parsing supports 64 MiB.</li><li><strong>Recipes</strong>: Preview inputs up to 16 MiB, with at most 100 steps and a 128 MiB cumulative processing budget.</li>
            <li><strong>CLI & MCP Streaming</strong>: Files up to 512 MiB are processed using bounded 1 MiB chunk streams, keeping heap consumption below 128 MiB.</li>
          </ul>
        `,
      },
      {
        id: 'result-caps',
        title: 'Result Caps & Pagination',
        html: `
          <p>Operations that could produce unbounded outputs enforce explicit pagination:</p>
          <ul>
            <li><strong>Pattern Searches</strong>: Capped at 1,000 matches per page with a <code>nextCursor</code> offset to continue scanning.</li>
            <li><strong>String Extraction</strong>: Capped at 1,000 strings per page with preview length limits.</li>
            <li><strong>Structure Nodes</strong>: Capped at 10,000 tree nodes per document with a maximum nesting depth of 32.</li>
            <li><strong>Custom Schemas</strong>: Schemas are capped at 256 KiB file size and 1,000 field definitions.</li>
          </ul>
        `,
      },
      {
        id: 'web-bundle-budgets',
        title: 'Web Build Size Budgets',
        html: `
          <p>Bitpeek strictly monitors bundle size on every build:</p>
          <ul>
            <li>Homepage HTML: ≤ 6 KiB gzip.</li>
            <li>Initial Application JavaScript: ≤ 110 KiB gzip.</li>
            <li>Application CSS: ≤ 7 KiB gzip.</li>
            <li>Total Initial Transfer: ≤ 150 KiB gzip.</li>
          </ul>
        `,
      },
    ],
    faqs: [
      {
        question: 'Can I edit files larger than 256 KiB?',
        answer:
          'Yes. Open a file to use the large-document editor. The 256 KiB limit applies to typed source input; file editing supports up to 512 MiB.',
      },
      {
        question: 'Can I inspect larger files without browser memory issues?',
        answer:
          'The browser reads large files in windows and runs analysis in workers. CLI and MCP also support chunked processing. Edit history and browser storage still consume space.',
      },
    ],
    related: [
      { slug: '/benchmarks', label: 'Benchmarks', note: 'Empirical performance data' },
      { slug: '/docs/privacy', label: 'Privacy model', note: 'Data boundary guarantees' },
      { slug: '/docs/cli', label: 'CLI manual', note: 'Large file terminal workflows' },
    ],
  },
  {
    type: 'doc',
    slug: '/docs/privacy',
    lastModified: '2026-09-27',
    label: 'Privacy model',
    eyebrow: 'Data Protection',
    title: 'Privacy Architecture & Zero-Upload Boundary | Bitpeek',
    description:
      'Learn about the strict client-only security architecture of Bitpeek. Zero server uploads, local storage isolation, CSP headers, and offline capability.',
    h1: 'Privacy Architecture & Zero-Upload Guarantee',
    lead: 'Why Bitpeek processes all bytes locally in browser memory or local process without external telemetry, tracking, or remote server file uploads.',
    ctaHref: '/?intent=open#workspace',
    ctaLabel: 'Test local workbench',
    ctaHeading: 'Verify privacy in your browser',
    ctaText:
      'Open your browser Network tab to verify that zero byte data is sent over the network during file inspection.',
    sections: [
      {
        id: 'zero-upload-invariant',
        title: 'The Zero-Upload Invariant',
        html: `
          <p>Files, names, searches, hashes, and analysis results stay on your device. Nothing is sent to a Bitpeek server.</p>
          <p>When you open a file in Bitpeek:</p>
          <ul>
            <li>The browser reads the file directly from your local filesystem into client-side JavaScript memory using the standard HTML5 File and Blob APIs.</li>
            <li>All scalar decoding, bit toggles, transforms, structure parsing, and cryptographic hashes are calculated entirely by your device's CPU.</li>
            <li>Saving an edited binary triggers a standard browser download from an in-memory <code>blob:</code> URL.</li>
          </ul>
        `,
      },
      {
        id: 'no-tracking',
        title: 'Zero Tracking, Analytics, or Third-Party Fonts',
        html: `
          <p>Bitpeek deliberately excludes all third-party telemetry and tracking:</p>
          <ul>
            <li>No Google Analytics, Mixpanel, Segment, or tracking pixels.</li>
            <li>No remote web fonts (system monospace and sans-serif fonts are used exclusively).</li>
            <li>No external CDN scripts or third-party cookies.</li>
            <li>No account, API key, or remote processing service is needed.</li>
          </ul>
        `,
      },
      {
        id: 'storage-and-headers',
        title: 'Storage Isolation & Security Headers',
        html: `
          <p>Session recovery stores files, comparison references, selections, recipes, and notes in this browser’s <code>IndexedDB</code>. Input format and theme preferences use <code>localStorage</code>. Use <strong>Save project</strong> to download a separate copy. If browser storage is blocked or full, file editing still works but session recovery may be unavailable.</p>
          <p>Strict security headers protect the application:</p>
          <ul>
            <li><code>X-Content-Type-Options: nosniff</code></li>
            <li><code>X-Frame-Options: DENY</code></li>
            <li><code>Referrer-Policy: strict-origin-when-cross-origin</code></li>
            <li><code>Permissions-Policy: camera=(), microphone=(), geolocation=()</code></li>
          </ul>
        `,
      },
    ],
    faqs: [
      {
        question: 'Can I use Bitpeek completely offline?',
        answer:
          'Editing uses local bytes after the app loads. Tools loaded on demand need a connection on first use; keep the page open when working offline.',
      },
      {
        question: 'Are file contents logged in Vercel server logs?',
        answer:
          'No. Because files are never sent via HTTP requests, hosting server logs only record requests for static web assets (.js, .css, .html).',
      },
    ],
    related: [
      { slug: '/docs/limits', label: 'Limits & budgets', note: 'Operational constraints' },
      { slug: '/docs/mcp', label: 'MCP server', note: 'Local AI agent privacy' },
      { slug: '/about', label: 'About the creator', note: 'Engineering background' },
    ],
  },
  {
    type: 'doc',
    slug: '/examples',
    lastModified: '2026-09-27',
    label: 'Examples',
    eyebrow: 'Verifiable Case Studies',
    title: 'Verifiable Binary Inspection Examples & Demos | Bitpeek',
    description:
      'Explore four reproducible technical demonstrations: ELF header analysis, PNG CRC editing, synthetic packet schema diffing, and AI agent evidence generation.',
    h1: 'Verifiable Binary Inspection Demonstrations',
    lead: 'Four realistic technical demonstrations with verifiable input vectors, expected semantic outputs, and replayable execution recipes.',
    ctaHref: '/?intent=open#workspace',
    ctaLabel: 'Open sample in workbench',
    ctaHeading: 'Try these examples live',
    ctaText:
      'Load sample bytes in the Bitpeek workbench to verify these demonstrations interactively.',
    sections: [
      {
        id: 'demo-1-elf',
        title: 'Demo 1: Systems & Firmware — ELF Header Interpretation',
        html: `
          <p><strong>Goal</strong>: Inspect a 64-bit Little-Endian ELF executable header and explain how <code>EI_CLASS</code> and <code>EI_DATA</code> govern field offsets.</p>
          <p><strong>Input Bytes (Hex)</strong>:</p>
          <pre><code>7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 3E 00 01 00 00 00 78 00 40 00 00 00 00 00</code></pre>
          <p><strong>Findings</strong>:</p>
          <ul>
            <li>Byte 0..4: Magic <code>7F 45 4C 46</code> confirms ELF format.</li>
            <li>Byte 4 (<code>EI_CLASS</code>): Value <code>0x02</code> indicates 64-bit architecture.</li>
            <li>Byte 5 (<code>EI_DATA</code>): Value <code>0x01</code> selects 2's complement little-endian byte ordering.</li>
            <li>Offset <code>0x10..0x12</code> (<code>e_type</code>): Value <code>0x0002</code> identifies an executable object (<code>ET_EXEC</code>).</li>
            <li>Offset <code>0x12..0x14</code> (<code>e_machine</code>): Value <code>0x003E</code> confirms Advanced Micro Devices x86-64.</li>
            <li>Offset <code>0x18..0x20</code> (<code>e_entry</code>): Decoded 64-bit entry address is <code>0x400078</code>.</li>
          </ul>
        `,
      },
      {
        id: 'demo-2-png-crc',
        title: 'Demo 2: Format & Security — PNG IHDR Mutation & CRC Mismatch',
        html: `
          <p><strong>Goal</strong>: Mutate image height in a synthetic PNG header and observe the resulting CRC-32 checksum mismatch.</p>
          <p><strong>Baseline IHDR Bytes</strong>: <code>00 00 00 0D 49 48 44 52 00 00 00 01 00 00 00 01 08 06 00 00 00 1F 15 C4 89</code></p>
          <p><strong>Mutation</strong>: Change height at offset <code>0x0F</code> from <code>0x01</code> to <code>0x02</code>.</p>
          <p><strong>Observed Result</strong>:</p>
          <ul>
            <li>Height field updates from 1 to 2 pixels.</li>
            <li>Chunk CRC check fails: Expected <code>0x1F15C489</code>, computed <code>0x8849E2AF</code>.</li>
            <li>Status badge updates from <span class="format-status status-valid">VALID</span> to <span class="format-status status-partial">PARTIAL</span> with explicit CRC warning.</li>
          </ul>
        `,
      },
      {
        id: 'demo-3-packet-schema',
        title: 'Demo 3: Protocol Debugging — Synthetic Packet Schema Diff',
        html: `
          <p><strong>Goal</strong>: Compare two network packet headers using a custom declarative JSON schema to detect flipped flag bits.</p>
          <p><strong>Schema Definition</strong>: Contains a 16-bit <code>magic</code>, 16-bit <code>length</code>, and an 8-bit <code>flags</code> bitfield with <code>syn</code> (bit 0) and <code>ack</code> (bit 1).</p>
          <p><strong>Diff Analysis</strong>:</p>
          <ul>
            <li>Packet A flags: <code>0x01</code> (SYN=1, ACK=0).</li>
            <li>Packet B flags: <code>0x03</code> (SYN=1, ACK=1).</li>
            <li>Bit inspector highlights bit 1 toggled from 0 to 1, cleanly demonstrating protocol state progression.</li>
          </ul>
        `,
      },
      {
        id: 'demo-4-ai-mcp',
        title: 'Demo 4: AI Tooling — MCP Evidence Generation & CLI Verification',
        html: `
          <p><strong>Goal</strong>: An autonomous AI developer agent reads bytes via MCP and produces an audit evidence report verified against the CLI.</p>
          <p><strong>Replay Pipeline</strong>:</p>
          <ol>
            <li>Agent calls <code>bitpeek_open</code> with allowed file path, receiving handle <code>sess_a1b2</code>.</li>
            <li>Agent calls <code>bitpeek_inspect</code> on range <code>[0, 8)</code>, extracting SHA-256 and scalar interpretations.</li>
            <li>Agent formats finding into a Markdown evidence summary with reproduction steps.</li>
            <li>Engineer runs <code>bitpeek inspect sample.bin --offset 0 --length 8 --json</code> to verify identical semantic output independently.</li>
          </ol>
        `,
      },
    ],
    faqs: [
      {
        question: 'Can I download the test files used in these demonstrations?',
        answer:
          'Yes. All test fixtures and synthetic byte sequences are included in the open source test corpus under packages/core/fixtures.',
      },
      {
        question: 'Are the recipes for these demos deterministic?',
        answer:
          'Yes. Running the associated recipe JSON produces identical checksums and output reports across Web, CLI, and MCP.',
      },
    ],
    related: [
      { slug: '/docs/structures', label: 'Structure inspector', note: 'ELF and PNG details' },
      { slug: '/docs/recipes', label: 'Recipes & replay', note: 'Automating replay sequences' },
      { slug: '/docs/mcp', label: 'MCP server', note: 'Tool server details' },
    ],
  },
  {
    type: 'doc',
    slug: '/benchmarks',
    lastModified: '2026-09-27',
    label: 'Benchmarks',
    eyebrow: 'Performance',
    title: 'File Limits and Performance Checks | Bitpeek',
    description:
      'Check Bitpeek performance on your own files. Covers file limits up to 512 MiB, memory use, background operations, and production bundle budgets.',
    h1: 'Performance Checks and File Limits',
    lead: 'How to check responsiveness, memory use, and production bundle size on your own files.',
    ctaHref: '/docs/limits',
    ctaLabel: 'View limits and budgets',
    ctaHeading: 'File and operation limits',
    ctaText: 'View the limits for editing, structure parsing, and recipe previews.',
    sections: [
      {
        id: 'benchmark-methodology',
        title: 'Checking performance',
        html: `
          <p>File size, file contents, browser version, available memory, and edit history all affect performance. A single number does not describe every workload.</p>
          <ol>
            <li>Open a local file and measure the time until the first bytes appear.</li>
            <li>Navigate to the final byte, edit it, undo, and check that the interface responds.</li>
            <li>Run search or Analyze file and measure completion time. Cancel a long operation to check responsiveness.</li>
            <li>Use browser performance tools to measure memory. Separate JavaScript heap, Blob storage, and browser process memory.</li>
            <li>Record the browser version, machine, input hash, and operation. Repeat runs before comparing results.</li>
          </ol>
        `,
      },
      {
        id: 'latency-and-memory',
        title: 'Operation limits',
        html: `
          <table class="benchmark-table"><thead><tr><th>Operation</th><th>File limit</th><th>Processing</th></tr></thead><tbody>
            <tr><td>Typed source input</td><td>256 KiB</td><td>In-memory buffer</td></tr>
            <tr><td>File viewing and editing</td><td>512 MiB</td><td>64 KiB windows and a piece table</td></tr>
            <tr><td>Search, ASCII strings, entropy, SHA-256</td><td>512 MiB</td><td>Background workers and chunks</td></tr>
            <tr><td>Structure inspection</td><td>64 MiB</td><td>Background parser for large files</td></tr>
            <tr><td>Recipe preview</td><td>16 MiB</td><td>Worker preview; one undo step when applied</td></tr>
          </tbody></table>
          <p>Opening a large file does not read all its bytes into a JavaScript array. Added bytes and undo history still consume memory; session recovery also needs browser storage.</p>
        `,
      },
      {
        id: 'bundle-budgets',
        title: 'Build checks',
        html: `
          <p><code>npm run build</code> checks the production assets with <code>scripts/verify-build.mjs</code>:</p>
          <ul><li>Homepage HTML: at most 6 KiB gzip.</li><li>Initial JavaScript: at most 110 KiB gzip.</li><li>Application and shared CSS: at most 7 KiB gzip each.</li><li>Total initial transfer: at most 150 KiB gzip.</li></ul>
          <p>Workers and optional tools load separately. Run the build to see the current measured sizes.</p>
        `,
      },
    ],
    faqs: [
      {
        question: 'Does the editor load a 512 MiB file into one array?',
        answer:
          'No. The editor reads 64 KiB windows. The piece table keeps references to original ranges and stores added bytes separately.',
      },
      {
        question: 'Where are the current bundle measurements?',
        answer:
          'Run npm run build. Its output reports the actual compressed sizes and checks them against the budgets above.',
      },
    ],
    related: [
      { slug: '/docs/limits', label: 'Limits & budgets', note: 'Operational constraints' },
      { slug: '/docs/quickstart', label: 'Quickstart guide', note: 'Hands-on tasks' },
      { slug: '/docs/cli', label: 'CLI manual', note: 'Running CLI operations' },
    ],
  },
  {
    type: 'doc',
    slug: '/about',
    lastModified: '2026-09-27',
    label: 'About',
    eyebrow: 'Creator & Provenance',
    title: 'About Bitpeek and Creator Yudistira Putra (Yudis-bit)',
    description:
      'Learn about the origins of Bitpeek and creator Yudistira Putra (Yudis-bit), with verified upstream contributions across LLVM, Vulkan, secp256k1, and OpenSBI.',
    h1: 'About Bitpeek and Yudistira Putra',
    lead: 'Built by Yudistira Putra (Yudis-bit). Bitpeek connects raw bytes, file structures, and reproducible analysis.',
    ctaHref: '/?intent=open#workspace',
    ctaLabel: 'Try Bitpeek workbench',
    ctaHeading: 'About the project',
    ctaText: 'Open a file to inspect bytes, select parsed fields, or compare it with a reference.',
    sections: [
      {
        id: 'creator-background',
        title: 'About the Creator: Yudistira Putra',
        html: `
          <p>Bitpeek was created and is actively maintained by <strong>Yudistira Putra</strong> (<a href="https://github.com/Yudis-bit">@Yudis-bit</a> on GitHub). His work focuses on low-level systems programming, compiler semantics, formal verification, memory safety, and protocol correctness.</p>
          <p>Bitpeek uses bounded byte reads and explicit offset ranges. Parsed fields link back to the bytes they describe.</p>
        `,
      },
      {
        id: 'verified-contributions',
        title: 'Verified Upstream Contributions',
        html: `
          <p>Yudis-bit's contributions span major open source compilers, graphics runtimes, cryptographic libraries, and firmware ecosystems:</p>
          <ul>
            <li><strong>LLVM / AMDGPU</strong> (<a href="https://github.com/llvm/llvm-project/pull/210583">Merged PR #210583</a>, Aug 2026): Fixed optimization pass bug by excluding image load instructions with TFE/LWE from unsafe merge candidates that altered status register semantics; included MIR regression suite.</li>
            <li><strong>Khronos Vulkan Validation Layers</strong> (<a href="https://github.com/KhronosGroup/Vulkan-ValidationLayers/pull/12743">Merged PR #12743</a>, Jul 2026): Repaired an out-of-bounds array access in static descriptor validation during shader module verification.</li>
            <li><strong>bitcoin-core/secp256k1</strong> (<a href="https://github.com/bitcoin-core/secp256k1/pull/1893">Merged PR #1893</a>, Sep 2026): Expanded constant-time testing coverage and memory safety validation (CHECKMEM) for custom Schnorr signatures and nonce callbacks.</li>
            <li><strong>RISC-V OpenSBI Firmware</strong> (<a href="https://github.com/riscv-software-src/opensbi/commit/f95648d3955d72f77e13315a990a6135303978a5">Upstream Commit f95648d</a>, Aug 2026): Implemented buffer capacity checks in extension string formatting to prevent buffer overflows and stack corruption.</li>
            <li><strong>Microsoft MsQuic</strong> (<a href="https://github.com/microsoft/msquic/pull/6320">Merged PR #6320</a>, Sep 2026): Corrected destination/source argument ordering in <code>CxPlatMoveMemory</code> during QUIC header protection sample extraction.</li>
            <li><strong>Google Kafel</strong> (<a href="https://github.com/google/kafel/pull/46">Merged PR #46</a>, Sep 2026): Corrected <code>ARG_2</code> syscall argument name to <code>flags</code> for <code>mseal</code> in the Motorola 68000 syscall definition tables.</li>
            <li><strong>QEMU x86_64</strong> (<a href="https://github.com/qemu/qemu/commit/3589cd995b4facf34071e944fd8ec2294524e25a">Commit 3589cd9</a>): Credited as <code>Tested-by</code> for independent reproduction and verification of x86 hypervisor patch.</li>
          </ul>
        `,
      },
      {
        id: 'contributing',
        title: 'Report a problem or contribute',
        html: `
          <p>Use <a href="https://github.com/Yudis-bit/bitpeek/issues">GitHub issues</a> to report a bug. Include your browser version, the steps to reproduce it, and the affected offset or field when relevant.</p>
          <p>A small test file helps reproduce parsing and editing problems. Remove private data before sharing a sample. Code changes can be submitted through a pull request.</p>
        `,
      },
    ],
    faqs: [
      {
        question: 'How can I get in touch with the author?',
        answer:
          'You can reach Yudistira Putra via GitHub at github.com/Yudis-bit or via email at pyudistira519@gmail.com.',
      },
      {
        question: 'Is Bitpeek affiliated with Google or Microsoft?',
        answer: 'No. Bitpeek is an independent personal project created by Yudistira Putra.',
      },
    ],
    related: [
      { slug: '/docs', label: 'Documentation index', note: 'Technical documentation' },
      { slug: '/docs/privacy', label: 'Privacy model', note: 'Zero-upload guarantee' },
      { slug: '/changelog', label: 'Changelog', note: 'Release history' },
    ],
  },
  {
    type: 'doc',
    slug: '/changelog',
    lastModified: '2026-10-01',
    label: 'Changelog',
    eyebrow: 'Release History',
    title: 'Bitpeek Changelog and Workspace Release Notes',
    description:
      'Complete version history and capability evolution for Bitpeek. Detailed release notes covering core parsers, CLI commands, MCP tools, and bug fixes.',
    h1: 'Bitpeek Version History & Release Notes',
    lead: 'Changes to the browser workspace, shared engine, and automation tools.',
    ctaHref: '/?intent=open#workspace',
    ctaLabel: 'Open Bitpeek v1.0.0',
    ctaHeading: 'Open the current workspace',
    ctaText:
      'Launch Bitpeek v1.0.0 in your browser to inspect binary files with the updated engine.',
    sections: [
      {
        id: 'workspace-2026-10-01',
        title: 'Workspace upgrade (October 1, 2026)',
        html: `
          <ul>
            <li>Kept the paper palette, navy chrome, monospace tables, and desktop controls.</li>
            <li>Added 16 document tabs, resizable panels, a command palette, focus view, and optional dark theme.</li>
            <li>Added file editing up to 512 MiB with 64 KiB windows, insertion, deletion, undo/redo, and background search and analysis.</li>
            <li>Added structure filtering, entropy and frequency maps, structure regions, and annotation bookmarks.</li>
            <li>Added insertion-aware comparison, byte previews, and structure-field comparison.</li>
            <li>Added annotations, local session recovery, and portable projects with reference files.</li>
            <li>Added visual recipes, byte previews, and JSON/Markdown investigation reports. Recipe previews support 16 MiB inputs; structure parsing supports 64 MiB.</li>
          </ul>
        `,
      },
      {
        id: 'v1-0-0',
        title: 'Version 1.0.0 (September 2026) — Initial Production Release',
        html: `
          <p>The first release introduced these tools:</p>
          <ul>
            <li><strong>Structure Inspector</strong>: Added ELF32/ELF64 and PNG interactive parsers with bi-directional field-to-byte coordinate selection. Added support for custom declarative JSON structure schemas.</li>
            <li><strong>Pure TypeScript Core</strong>: Established <code>packages/core</code> with zero external dependencies, streaming <code>ByteSource</code> abstractions, and NIST-verified SHA-256 (FIPS 180-4).</li>
            <li><strong>CLI Executable</strong>: Introduced <code>bitpeek</code> CLI tool supporting 9 commands (<code>inspect</code>, <code>find</code>, <code>strings</code>, <code>hash</code>, <code>structure</code>, <code>diff</code>, <code>patch verify</code>, <code>patch apply</code>, <code>recipe run</code>) with JSON mode and POSIX exit codes.</li>
            <li><strong>Model Context Protocol (MCP) Server</strong>: Implemented official stdio MCP server in <code>packages/mcp</code> exposing 12 tools for AI agents within a secure allowed-roots sandbox.</li>
            <li><strong>Deterministic Replay Recipes</strong>: Added declarative recipe runner (<code>recipe-v1.json</code>) and verifiable evidence report generator (<code>evidence-report-v1.json</code>).</li>
            <li><strong>Integrity Fixes</strong>: Integrated <code>SafeStorage</code> in-memory fallback for private browsing, fixed 0-byte document export bug, eliminated draft state ambiguity, and unified transactional history across patch and replacement operations.</li>
            <li><strong>Documentation Suite</strong>: Launched 14 technical documentation pages, machine-readable manifests (<code>/capabilities.json</code>, <code>/version.json</code>, <code>/llms.txt</code>), and versioned schemas.</li>
          </ul>
        `,
      },
    ],
    faqs: [
      {
        question: 'How is Bitpeek versioned?',
        answer:
          'Bitpeek strictly follows Semantic Versioning (SemVer 2.0.0). Schema specifications (such as recipe-v1.json) maintain independent version numbers.',
      },
      {
        question: 'Where can I see the commit history?',
        answer:
          'The complete, unedited commit history is publicly available on GitHub at github.com/Yudis-bit/bitpeek.',
      },
    ],
    related: [
      { slug: '/docs', label: 'Documentation index', note: 'Technical documentation' },
      { slug: '/about', label: 'About the creator', note: 'Creator background' },
      { slug: '/benchmarks', label: 'Benchmarks', note: 'Measured performance' },
    ],
  },
]
