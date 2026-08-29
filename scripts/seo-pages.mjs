export const SITE_URL = 'https://bitpeek-seven.vercel.app'
export const LAST_MODIFIED = '2026-08-29'

export const toolPages = [
  {
    type: 'tool',
    slug: '/tools/hex-editor',
    label: 'Online hex editor',
    eyebrow: 'Browser-based byte editing',
    title: 'Online Hex Editor for Binary Files | Bitpeek',
    description:
      'Open, inspect, and edit hexadecimal bytes in your browser. Search patterns, toggle bits, undo changes, and export a new file without uploading it.',
    h1: 'Online Hex Editor for Local Binary Files',
    lead:
      'Edit raw bytes in a focused hexadecimal workspace. Bitpeek keeps the file in browser memory, shows the matching ASCII view, and lets you export a separate edited copy.',
    ctaHref: '/?mode=hex#workspace',
    ctaLabel: 'Open the hex editor',
    ctaHeading: 'Edit bytes in the Bitpeek workspace',
    ctaText:
      'Paste hexadecimal input or open a local file. Select a byte to edit it directly, toggle individual bits, or transform a larger selection.',
    sections: [
      {
        id: 'how-to-use',
        title: 'How to edit a file in hexadecimal',
        html: `
          <ol>
            <li><strong>Open or paste the data.</strong> Choose <em>Open</em> for a local file, or paste complete hexadecimal bytes such as <code>DE AD BE EF</code>.</li>
            <li><strong>Navigate to the target offset.</strong> Use the offset column, Go to control, or hexadecimal search. Search accepts full-byte and nibble wildcards such as <code>??</code> and <code>D?</code>.</li>
            <li><strong>Edit deliberately.</strong> Double-click a byte cell to enter a new value, select one byte to toggle bits, or use Reverse and Invert on a selection.</li>
            <li><strong>Review and export.</strong> Undo and redo byte changes, inspect the updated representations, then save a separate <code>.bitpeek.bin</code> file.</li>
          </ol>
        `,
      },
      {
        id: 'capabilities',
        title: 'Hex editing capabilities',
        html: `
          <p>Bitpeek is designed for small, targeted binary inspection rather than unrestricted multi-gigabyte editing. The workspace accepts files up to 256 KiB and keeps an in-memory edit history.</p>
          <ul>
            <li>Hexadecimal, binary, decimal, UTF-8 text, and Base64 input modes.</li>
            <li>Hex and ASCII rows with stable byte offsets.</li>
            <li>Direct byte editing, single-bit toggles, selection inversion, and byte-order reversal.</li>
            <li>Exact or wildcard byte-pattern search and direct offset navigation.</li>
            <li>Undo and redo for byte edits and selection transforms.</li>
            <li>Local export without replacing the original file automatically.</li>
          </ul>
        `,
      },
      {
        id: 'use-cases',
        title: 'Useful hex editor workflows',
        html: `
          <p>A byte editor is useful when the location and meaning of the change are already understood. Typical Bitpeek workflows include:</p>
          <ul>
            <li>Checking a file header or protocol fixture against documented bytes.</li>
            <li>Changing a small flag, identifier, or test value at a known offset.</li>
            <li>Building compact binary examples for documentation or unit tests.</li>
            <li>Comparing the effect of one controlled byte change on checksums, hashes, or interpretations.</li>
          </ul>
        `,
      },
      {
        id: 'safety',
        title: 'Editing limits and safe handling',
        html: `
          <p class="notice">Bitpeek edits raw bytes; it does not understand every format rule or repair dependent length fields and checksums automatically. Work on a copy and validate the exported file with the software that owns the format.</p>
          <p>Saving creates a new download. The original file on your device is not overwritten, and Bitpeek does not retain an uploaded server copy because no upload occurs.</p>
        `,
      },
    ],
    faqs: [
      {
        question: 'Does Bitpeek upload the file I edit?',
        answer:
          'No. The browser reads the selected file into local memory and all byte editing happens on the device.',
      },
      {
        question: 'What is the maximum file size?',
        answer:
          'The current workspace limit is 256 KiB per opened file. This keeps inspection and editing responsive in the browser.',
      },
      {
        question: 'Can I undo a hex edit?',
        answer:
          'Yes. Direct byte changes, bit toggles, reverse operations, and invert operations can be undone and redone during the current session.',
      },
      {
        question: 'Will saving overwrite the original?',
        answer:
          'No. Bitpeek downloads a separate file with a .bitpeek.bin suffix so the source file remains unchanged.',
      },
    ],
    related: [
      { slug: '/tools/binary-viewer', label: 'Binary viewer', note: 'Interpret selected bytes and headers' },
      { slug: '/tools/binary-diff', label: 'Binary diff', note: 'Compare the edited copy with a reference' },
      { slug: '/tools/hex-to-text', label: 'Hex to text', note: 'Decode bytes as UTF-8 and ASCII' },
    ],
  },
  {
    type: 'tool',
    slug: '/tools/binary-viewer',
    label: 'Binary viewer',
    eyebrow: 'Local binary inspection',
    title: 'Online Binary Viewer & Byte Inspector | Bitpeek',
    description:
      'View binary files as hex and ASCII with byte offsets, integer and float interpretations, hashes, checksums, entropy, strings, and magic bytes.',
    h1: 'View and Analyze Binary Files Online',
    lead:
      'Open a local file and examine its bytes without uploading it. Bitpeek connects the hex table, ASCII view, selected-byte interpretations, checksums, hashes, entropy, and file-signature detection.',
    ctaHref: '/?intent=open#workspace',
    ctaLabel: 'Open the binary viewer',
    ctaHeading: 'Inspect a local binary file',
    ctaText:
      'Open a file up to 256 KiB, select a byte range, and Bitpeek will update every interpretation for that selection.',
    sections: [
      {
        id: 'what-you-see',
        title: 'What the binary viewer shows',
        html: `
          <p>The main byte table displays 16 bytes per row. Every row has a hexadecimal offset, individual editable byte cells, and an ASCII column that replaces non-printable values with a dot.</p>
          <p>Selecting bytes connects the table to a detailed interpretation panel:</p>
          <ul>
            <li>Unsigned and signed integers in big-endian and little-endian order.</li>
            <li>16-, 32-, and 64-bit floating-point values when the selection width matches.</li>
            <li>Hex, binary, decimal, Base64, ASCII, and escaped UTF-8 representations.</li>
            <li>CRC-16, CRC-32, Sum-8, XOR-8, SHA-256, SHA-512, and Shannon entropy.</li>
            <li>Known file signatures at the start of the document.</li>
          </ul>
        `,
      },
      {
        id: 'navigation',
        title: 'Navigate bytes by offset, pattern, or string',
        html: `
          <p>Use Go to with a decimal offset or a hexadecimal value prefixed by <code>0x</code>. Hex search accepts exact bytes and wildcard nibbles, while text search encodes the query as UTF-8 before matching.</p>
          <p>The string scanner extracts printable ASCII, UTF-16LE, and UTF-16BE runs with their offsets. Selecting a result returns directly to the corresponding byte range.</p>
        `,
      },
      {
        id: 'use-cases',
        title: 'When a browser binary viewer is useful',
        html: `
          <ul>
            <li>Confirming a magic number and the bytes immediately after it.</li>
            <li>Reading a small protocol capture, binary fixture, save file, or embedded resource.</li>
            <li>Checking how the same bytes decode under different endianness.</li>
            <li>Extracting readable strings from an unfamiliar file.</li>
            <li>Comparing a documented field offset with the actual bytes.</li>
          </ul>
        `,
      },
      {
        id: 'scope',
        title: 'Scope and interpretation limits',
        html: `
          <p class="notice">A generic binary viewer exposes bytes; it does not replace a format-specific parser. A plausible number, string, or file signature is evidence to investigate, not proof that the file is valid or safe.</p>
          <p>Bitpeek intentionally limits the workspace to 256 KiB. For larger files, extract the relevant range with a trusted local tool before inspecting it.</p>
        `,
      },
    ],
    faqs: [
      {
        question: 'Can Bitpeek read a file without uploading it?',
        answer:
          'Yes. The File API provides the selected bytes directly to browser memory; Bitpeek has no file-upload endpoint.',
      },
      {
        question: 'Does the viewer support little-endian values?',
        answer:
          'Yes. Supported integer and floating-point widths are shown in both big-endian and little-endian order when enough bytes are selected.',
      },
      {
        question: 'Can it extract strings?',
        answer:
          'Yes. The string scanner identifies printable ASCII, UTF-16LE, and UTF-16BE runs and reports their byte offsets.',
      },
    ],
    related: [
      { slug: '/tools/file-signature-checker', label: 'File signature checker', note: 'Identify common magic bytes' },
      { slug: '/tools/hex-editor', label: 'Online hex editor', note: 'Change a known byte or bit' },
      { slug: '/file-formats/elf', label: 'ELF header reference', note: 'Read class and byte-order fields' },
    ],
  },
  {
    type: 'tool',
    slug: '/tools/binary-diff',
    label: 'Binary diff',
    eyebrow: 'Offset-based comparison',
    title: 'Binary Diff Tool — Compare Files by Offset | Bitpeek',
    description:
      'Compare two local binary files by offset, navigate changed ranges, distinguish modified and extra bytes, and export a reproducible JSON offset patch.',
    h1: 'Compare Two Binary Files by Byte Offset',
    lead:
      'Bitpeek compares the current bytes with a local reference file, highlights every different offset, groups adjacent changes, and can export a human-readable offset patch.',
    ctaHref: '/?intent=compare#workspace',
    ctaLabel: 'Start a binary comparison',
    ctaHeading: 'Open the Bitpeek binary diff workflow',
    ctaText:
      'Load the current file with Open, choose Compare for the reference file, then navigate each changed byte or range.',
    sections: [
      {
        id: 'workflow',
        title: 'How to compare binary files',
        html: `
          <ol>
            <li><strong>Open the current file.</strong> This is the byte sequence shown in the main workspace.</li>
            <li><strong>Choose Compare.</strong> Select the local reference file. Neither file is uploaded.</li>
            <li><strong>Review the diff bar.</strong> Bitpeek reports modified bytes, bytes present only in the current file, and bytes present only in the reference.</li>
            <li><strong>Navigate changes.</strong> Previous and Next move the byte selection through the difference offsets.</li>
            <li><strong>Export if needed.</strong> Copy or download the reference-to-current offset patch as JSON.</li>
          </ol>
        `,
      },
      {
        id: 'semantics',
        title: 'What offset-based diff means',
        html: `
          <p>Bitpeek compares byte 0 with byte 0, byte 1 with byte 1, and so on. Adjacent offsets with the same difference type are grouped into ranges. This is deterministic and useful for controlled changes at known positions.</p>
          <p>An insertion near the beginning shifts every later byte and therefore produces many differences. Bitpeek does not attempt sequence alignment, binary-format parsing, or semantic comparison.</p>
        `,
      },
      {
        id: 'patch-format',
        title: 'Reproducible offset patch output',
        html: `
          <p>The exported <code>bitpeek-offset-patch</code> document records source and target lengths, contiguous remove/insert byte ranges, file labels, and SHA-256 digests for both sides.</p>
          <p>The patch is designed to document a reference-to-current transformation. It is not an executable program and should still be reviewed before use in another workflow.</p>
        `,
      },
      {
        id: 'use-cases',
        title: 'Good uses for a byte-level diff',
        html: `
          <ul>
            <li>Confirming that a controlled test changed only the expected offsets.</li>
            <li>Comparing two compact firmware fragments, fixtures, or encoded records.</li>
            <li>Documenting a manual hex edit with source and target hashes.</li>
            <li>Finding the first divergent byte in two same-layout files.</li>
          </ul>
        `,
      },
    ],
    faqs: [
      {
        question: 'Are both comparison files uploaded?',
        answer:
          'No. Both files are read and compared inside the same browser session.',
      },
      {
        question: 'Does Bitpeek align inserted or deleted blocks?',
        answer:
          'No. The comparison is intentionally offset-based. A shifted block remains visibly shifted rather than being realigned heuristically.',
      },
      {
        question: 'What does the patch contain?',
        answer:
          'It contains source and target metadata, SHA-256 digests, and contiguous hexadecimal remove/insert ranges with their offsets.',
      },
    ],
    related: [
      { slug: '/tools/hex-editor', label: 'Online hex editor', note: 'Make a controlled byte change' },
      { slug: '/tools/binary-viewer', label: 'Binary viewer', note: 'Interpret a changed range' },
      { slug: '/tools/file-signature-checker', label: 'File signature checker', note: 'Confirm both file headers' },
    ],
  },
  {
    type: 'tool',
    slug: '/tools/file-signature-checker',
    label: 'File signature checker',
    eyebrow: 'Magic-byte inspection',
    title: 'File Signature Checker — Identify Magic Bytes | Bitpeek',
    description:
      'Check a local file for common magic bytes, inspect its header in hex, and verify PNG, JPEG, PDF, ZIP, ELF, and other recognized signatures in your browser.',
    h1: 'Check File Signatures and Magic Bytes Online',
    lead:
      'Open a local file to compare its leading bytes with known signatures. Bitpeek reports recognized formats and keeps the complete inspection workflow in your browser.',
    ctaHref: '/?intent=signature#workspace',
    ctaLabel: 'Check a local file',
    ctaHeading: 'Inspect a file header in Bitpeek',
    ctaText:
      'Open the file, keep the selection at offset 0, and review the Magic field alongside the actual hexadecimal header bytes.',
    sections: [
      {
        id: 'how-it-works',
        title: 'How file-signature detection works',
        html: `
          <p>A file signature—often called a magic number—is a byte sequence at a known position that identifies a format family. Bitpeek checks the beginning of the current document against a compact, reviewed signature list.</p>
          <p>The current detector recognizes PNG, JPEG, GIF, PDF, ZIP, Gzip, ELF, WebAssembly, SQLite, BMP, WAVE, and WebP headers. The byte table remains visible so the result can be verified rather than accepted as a black box.</p>
        `,
      },
      {
        id: 'recognized-signatures',
        title: 'Recognized leading signatures',
        html: `
          <div class="data-table-wrap">
            <table class="data-table">
              <thead><tr><th>Format</th><th>Leading bytes or text</th><th>Detection note</th></tr></thead>
              <tbody>
                <tr><td>PNG</td><td>89 50 4E 47 0D 0A 1A 0A</td><td>Exact 8-byte signature</td></tr>
                <tr><td>JPEG</td><td>FF D8 FF</td><td>SOI followed by a marker prefix</td></tr>
                <tr><td>GIF</td><td>GIF87a / GIF89a</td><td>ASCII version signature</td></tr>
                <tr><td>PDF</td><td>%PDF-</td><td>ASCII header prefix</td></tr>
                <tr><td>ZIP</td><td>50 4B 03 04</td><td>Local-file-header signature</td></tr>
                <tr><td>Gzip</td><td>1F 8B</td><td>Gzip member prefix</td></tr>
                <tr><td>ELF</td><td>7F 45 4C 46</td><td>ELF identification bytes</td></tr>
                <tr><td>WebAssembly</td><td>00 61 73 6D</td><td>Wasm binary magic</td></tr>
                <tr><td>SQLite</td><td>SQLite format 3\0</td><td>16-byte ASCII header</td></tr>
                <tr><td>BMP</td><td>42 4D</td><td>ASCII “BM” prefix</td></tr>
                <tr><td>WAVE</td><td>RIFF … WAVE</td><td>RIFF at 0 and WAVE at 8</td></tr>
                <tr><td>WebP</td><td>RIFF … WEBP</td><td>RIFF at 0 and WEBP at 8</td></tr>
              </tbody>
            </table>
          </div>
        `,
      },
      {
        id: 'interpretation',
        title: 'What a signature can and cannot prove',
        html: `
          <p>A matching signature is a strong format clue, but it does not validate every field, guarantee that the file is complete, or establish that its content is safe. Different container formats can also share signatures; ZIP-based documents are a common example.</p>
          <p class="notice">Treat magic-byte detection as the first inspection step. Continue with header fields, documented offsets, length checks, and a format-aware validator when correctness or security matters.</p>
        `,
      },
      {
        id: 'unknown-files',
        title: 'When the signature is unknown',
        html: `
          <ul>
            <li>Inspect the first 32–64 bytes in both hex and ASCII.</li>
            <li>Use the string scanner to look for readable identifiers.</li>
            <li>Search for documented markers that may appear after a wrapper or preamble.</li>
            <li>Compare the file with a known-good example from the same source.</li>
          </ul>
        `,
      },
    ],
    faqs: [
      {
        question: 'Is a file extension the same as a signature?',
        answer:
          'No. An extension is a file-name convention; a signature is stored in the file bytes. Either can be absent or misleading.',
      },
      {
        question: 'Is this an antivirus scanner?',
        answer:
          'No. Bitpeek identifies selected byte patterns and exposes the header. It does not evaluate whether a file is malicious.',
      },
      {
        question: 'What happens if no signature matches?',
        answer:
          'Bitpeek reports the signature as unknown while leaving all bytes, representations, searches, hashes, and strings available for manual inspection.',
      },
    ],
    related: [
      { slug: '/file-formats/png', label: 'PNG header reference', note: 'Inspect the signature and IHDR chunk' },
      { slug: '/file-formats/zip', label: 'ZIP header reference', note: 'Read local and central-directory records' },
      { slug: '/tools/binary-viewer', label: 'Binary viewer', note: 'Inspect an unknown header manually' },
    ],
  },
  {
    type: 'tool',
    slug: '/tools/hex-to-text',
    label: 'Hex to text',
    eyebrow: 'Byte representation conversion',
    title: 'Hex to Text Converter — UTF-8 & ASCII | Bitpeek',
    description:
      'Convert hexadecimal bytes to UTF-8 text or ASCII in your browser, inspect invalid sequences, and compare binary, decimal, and Base64 representations locally.',
    h1: 'Convert Hexadecimal Bytes to Text',
    lead:
      'Paste hexadecimal bytes once and inspect their UTF-8 and ASCII representations together. Bitpeek keeps control characters visible as escapes and flags invalid UTF-8 input.',
    ctaHref: '/?mode=hex#workspace',
    ctaLabel: 'Open the hex-to-text workspace',
    ctaHeading: 'Decode hexadecimal bytes locally',
    ctaText:
      'Paste complete hex bytes in the Input panel, select the range, and read UTF-8 and ASCII under Representations.',
    sections: [
      {
        id: 'conversion',
        title: 'How to convert hex to readable text',
        html: `
          <ol>
            <li>Keep the Input mode on <strong>Hex</strong>.</li>
            <li>Paste bytes separated by spaces, commas, colons, or hyphens. A <code>0x</code> prefix is accepted.</li>
            <li>Select the bytes to decode, or choose All for the complete input.</li>
            <li>Read the ASCII and UTF-8 rows in Representations, then copy the exact output you need.</li>
          </ol>
          <div class="code-signature"><code>48 65 6C 6C 6F 2C 20 42 69 74 70 65 65 6B 21</code></div>
          <p>The example above decodes to <code>Hello, Bitpeek!</code> in both ASCII and UTF-8.</p>
        `,
      },
      {
        id: 'utf8-vs-ascii',
        title: 'UTF-8 and ASCII are not interchangeable',
        html: `
          <p>ASCII maps printable values from <code>20</code> through <code>7E</code> directly to characters. Bitpeek displays other single-byte values as dots in the compact ASCII column.</p>
          <p>UTF-8 uses one to four bytes per Unicode code point. The UTF-8 representation therefore decodes the selected sequence as a whole and escapes control characters such as line feed, carriage return, tab, and NUL.</p>
        `,
      },
      {
        id: 'invalid-input',
        title: 'Invalid or incomplete byte sequences',
        html: `
          <p>Hex input must contain complete two-digit bytes. An incomplete final nibble is rejected rather than guessed. If the bytes are valid hex but not valid UTF-8, the text preview includes <code>\uFFFD</code> replacement markers and the editor warns before text-mode editing.</p>
          <p class="notice">Switching to Text mode and editing invalid UTF-8 can replace undecodable bytes. Keep the original hex input or file available when byte preservation matters.</p>
        `,
      },
      {
        id: 'other-representations',
        title: 'Convert the same bytes without re-entering them',
        html: `
          <p>The Input tabs reformat the current byte array as hex, binary, decimal, UTF-8 text, or Base64. The interpretation panel also keeps these representations together for the selected range, making it easier to compare encodings without using separate converters.</p>
        `,
      },
    ],
    faqs: [
      {
        question: 'Does hex text have an endianness?',
        answer:
          'A raw byte sequence has a fixed order. Endianness matters when multiple bytes are interpreted as a number, not when UTF-8 decodes the bytes in sequence.',
      },
      {
        question: 'Why do some bytes appear as dots in ASCII?',
        answer:
          'The compact ASCII view uses dots for control bytes and values outside printable ASCII so table alignment remains stable.',
      },
      {
        question: 'Can I convert text back to hex?',
        answer:
          'Yes. Choose Text input mode, enter UTF-8 text, then switch to Hex or copy the Hex representation for the encoded bytes.',
      },
    ],
    related: [
      { slug: '/tools/hex-editor', label: 'Online hex editor', note: 'Change decoded bytes safely' },
      { slug: '/tools/binary-viewer', label: 'Binary viewer', note: 'Compare every representation' },
      { slug: '/file-formats/pdf', label: 'PDF header reference', note: 'Read the ASCII %PDF- prefix' },
    ],
  },
]

export const formatPages = [
  {
    type: 'format',
    slug: '/file-formats/png',
    label: 'PNG file format',
    eyebrow: 'File format reference',
    title: 'PNG File Header & Magic Bytes Reference | Bitpeek',
    description:
      'Inspect the PNG file signature, IHDR chunk fields, byte offsets, chunk layout, and CRC structure with a verified header reference and local hex viewer.',
    h1: 'PNG File Header and Magic Bytes',
    lead:
      'A PNG datastream begins with a fixed eight-byte signature followed by length-prefixed chunks. The first chunk is IHDR and the final chunk is IEND.',
    ctaHref: '/?intent=signature#workspace',
    ctaLabel: 'Inspect a PNG file',
    ctaHeading: 'Open a PNG header in Bitpeek',
    ctaText:
      'Select a PNG file locally, verify the eight-byte signature, and inspect the IHDR fields at fixed offsets.',
    sections: [
      {
        id: 'signature',
        title: 'PNG signature at offset 0',
        html: `
          <div class="code-signature"><code>89 50 4E 47 0D 0A 1A 0A</code></div>
          <p>The signature occupies offsets <code>0x00–0x07</code>. It includes the ASCII letters PNG plus bytes chosen to expose common text-transfer and line-ending corruption.</p>
        `,
      },
      {
        id: 'ihdr',
        title: 'IHDR header fields and offsets',
        html: `
          <p>The first chunk starts immediately after the signature. A conforming PNG uses a 13-byte IHDR data field.</p>
          <div class="data-table-wrap">
            <table class="data-table">
              <thead><tr><th>Offset</th><th>Length</th><th>Field</th><th>Interpretation</th></tr></thead>
              <tbody>
                <tr><td>0x08</td><td>4</td><td>Chunk data length</td><td>Big-endian; normally 13 for IHDR</td></tr>
                <tr><td>0x0C</td><td>4</td><td>Chunk type</td><td>ASCII <code>IHDR</code> (<code>49 48 44 52</code>)</td></tr>
                <tr><td>0x10</td><td>4</td><td>Width</td><td>Unsigned big-endian pixels; zero is invalid</td></tr>
                <tr><td>0x14</td><td>4</td><td>Height</td><td>Unsigned big-endian pixels; zero is invalid</td></tr>
                <tr><td>0x18</td><td>1</td><td>Bit depth</td><td>1, 2, 4, 8, or 16 subject to color type</td></tr>
                <tr><td>0x19</td><td>1</td><td>Color type</td><td>Grayscale, truecolor, indexed, or alpha variants</td></tr>
                <tr><td>0x1A</td><td>1</td><td>Compression</td><td>Method 0</td></tr>
                <tr><td>0x1B</td><td>1</td><td>Filter</td><td>Method 0</td></tr>
                <tr><td>0x1C</td><td>1</td><td>Interlace</td><td>0 for none, 1 for Adam7</td></tr>
                <tr><td>0x1D</td><td>4</td><td>IHDR CRC</td><td>CRC over chunk type and data</td></tr>
              </tbody>
            </table>
          </div>
        `,
      },
      {
        id: 'chunks',
        title: 'PNG chunk layout',
        html: `
          <p>Every chunk stores a four-byte big-endian data length, a four-byte ASCII type, the declared data bytes, and a four-byte CRC. Critical image data appears in one or more IDAT chunks; IEND terminates the datastream.</p>
          <p>Chunk lengths vary, so only the signature and first IHDR locations are fixed. To navigate later chunks, read each length and advance by <code>length + 12</code> bytes from the start of that chunk.</p>
        `,
      },
      {
        id: 'inspection',
        title: 'Practical PNG inspection checks',
        html: `
          <ul>
            <li>Confirm the full eight-byte signature, not only the letters PNG.</li>
            <li>Check that IHDR is first and declares 13 data bytes.</li>
            <li>Interpret width and height as unsigned big-endian integers.</li>
            <li>Check that the bit-depth and color-type combination is permitted by the PNG specification.</li>
            <li>Use a format-aware validator to verify every chunk length, ordering rule, and CRC.</li>
          </ul>
        `,
      },
    ],
    faqs: [
      { question: 'Are PNG integers little-endian?', answer: 'No. PNG multi-byte integers, including chunk lengths, width, and height, use network byte order (big-endian).' },
      { question: 'Is IHDR always at offset 0x0C?', answer: 'For a valid PNG datastream, yes. The eight-byte signature is followed by the first chunk length at 0x08 and the IHDR type at 0x0C.' },
      { question: 'Can Bitpeek validate a complete PNG?', answer: 'Bitpeek can expose bytes, interpretations, CRC values for selections, and the leading signature. A dedicated PNG validator is still needed for full conformance.' },
    ],
    source: { label: 'W3C PNG Specification, Third Edition', url: 'https://www.w3.org/TR/png-3/' },
    related: [
      { slug: '/tools/file-signature-checker', label: 'File signature checker', note: 'Confirm PNG magic bytes' },
      { slug: '/tools/binary-viewer', label: 'Binary viewer', note: 'Read IHDR values as big-endian' },
      { slug: '/file-formats/jpeg', label: 'JPEG header reference', note: 'Compare marker-based image structure' },
    ],
  },
  {
    type: 'format',
    slug: '/file-formats/jpeg',
    label: 'JPEG file format',
    eyebrow: 'File format reference',
    title: 'JPEG File Header & Marker Reference | Bitpeek',
    description:
      'Inspect JPEG SOI and EOI markers, common APP0 and APP1 segments, frame and scan markers, variable segment lengths, and leading magic bytes in a local hex viewer.',
    h1: 'JPEG File Header and Marker Structure',
    lead:
      'A JPEG interchange stream begins with the Start of Image marker and ends with End of Image. Between them, marker segments describe tables, frames, scans, and optional metadata.',
    ctaHref: '/?intent=signature#workspace',
    ctaLabel: 'Inspect a JPEG file',
    ctaHeading: 'Open a JPEG byte stream in Bitpeek',
    ctaText:
      'Verify the leading SOI marker, search for common marker bytes, and inspect each segment length before moving to the next structure.',
    sections: [
      {
        id: 'signature',
        title: 'JPEG Start of Image marker',
        html: `
          <div class="code-signature"><code>FF D8 FF</code></div>
          <p>The actual SOI marker is <code>FF D8</code> at offset 0. It is normally followed by another marker prefix byte <code>FF</code>, which produces the common three-byte file signature shown above.</p>
        `,
      },
      {
        id: 'markers',
        title: 'Common JPEG markers',
        html: `
          <div class="data-table-wrap">
            <table class="data-table">
              <thead><tr><th>Marker</th><th>Name</th><th>Purpose</th></tr></thead>
              <tbody>
                <tr><td>FF D8</td><td>SOI</td><td>Start of Image</td></tr>
                <tr><td>FF E0</td><td>APP0</td><td>Often carries a JFIF identifier and density fields</td></tr>
                <tr><td>FF E1</td><td>APP1</td><td>Often carries Exif or XMP metadata</td></tr>
                <tr><td>FF DB</td><td>DQT</td><td>Quantization table definition</td></tr>
                <tr><td>FF C0</td><td>SOF0</td><td>Baseline DCT frame header</td></tr>
                <tr><td>FF C2</td><td>SOF2</td><td>Progressive DCT frame header</td></tr>
                <tr><td>FF C4</td><td>DHT</td><td>Huffman table definition</td></tr>
                <tr><td>FF DA</td><td>SOS</td><td>Start of Scan</td></tr>
                <tr><td>FF D9</td><td>EOI</td><td>End of Image</td></tr>
              </tbody>
            </table>
          </div>
        `,
      },
      {
        id: 'segments',
        title: 'Variable-length marker segments',
        html: `
          <p>Most markers that carry parameters are followed by a two-byte big-endian segment length. That length includes the two length bytes themselves but not the marker. Offsets after SOI are therefore not globally fixed.</p>
          <p>Entropy-coded scan data follows SOS. Inside that data, <code>FF 00</code> represents a stuffed literal <code>FF</code> byte, so a raw search for <code>FF</code> is not enough to parse scan boundaries correctly.</p>
        `,
      },
      {
        id: 'inspection',
        title: 'Practical JPEG inspection checks',
        html: `
          <ul>
            <li>Confirm SOI at the beginning and EOI near the end.</li>
            <li>Read each parameter segment length as big-endian before advancing.</li>
            <li>Distinguish APP0/JFIF and APP1/Exif metadata rather than assuming one is always present.</li>
            <li>Use SOF0 or SOF2 to find image precision, height, width, and component information.</li>
            <li>Use a JPEG-aware parser for full entropy-stream and table validation.</li>
          </ul>
        `,
      },
    ],
    faqs: [
      { question: 'Why is the common JPEG signature three bytes if SOI is two?', answer: 'SOI is FF D8. A valid interchange stream continues with another marker, whose prefix is FF, so file-signature tables commonly use FF D8 FF.' },
      { question: 'Is Exif always present in a JPEG?', answer: 'No. Exif commonly appears in an APP1 segment, but JPEG files can omit it or use APP1 for other identified payloads such as XMP.' },
      { question: 'Are JPEG segment offsets fixed?', answer: 'No. Segment lengths and optional metadata determine later offsets. Parse the two-byte length of each applicable marker segment.' },
    ],
    source: { label: 'ITU-T Recommendation T.81 — JPEG interchange format', url: 'https://www.w3.org/Graphics/JPEG/itu-t81.pdf' },
    related: [
      { slug: '/tools/file-signature-checker', label: 'File signature checker', note: 'Confirm the SOI prefix' },
      { slug: '/tools/binary-viewer', label: 'Binary viewer', note: 'Navigate markers and lengths' },
      { slug: '/file-formats/png', label: 'PNG header reference', note: 'Compare chunk-based image structure' },
    ],
  },
  {
    type: 'format',
    slug: '/file-formats/pdf',
    label: 'PDF file format',
    eyebrow: 'File format reference',
    title: 'PDF File Header & Structure Reference | Bitpeek',
    description:
      'Inspect the %PDF- header, version bytes, indirect objects, cross-reference data, startxref pointer, and %%EOF marker with a local binary viewer.',
    h1: 'PDF File Header and Byte Structure',
    lead:
      'A PDF begins with an ASCII version header, stores a graph of numbered objects, and ends with information that lets a reader locate the latest cross-reference data.',
    ctaHref: '/?intent=signature#workspace',
    ctaLabel: 'Inspect a PDF file',
    ctaHeading: 'Open a compact PDF in Bitpeek',
    ctaText:
      'Verify the %PDF- header, search readable structural keywords, and compare startxref with the referenced byte location.',
    sections: [
      {
        id: 'signature',
        title: 'PDF header at the beginning of the file',
        html: `
          <div class="code-signature"><code>25 50 44 46 2D 31 2E 37</code></div>
          <p>The bytes above are ASCII <code>%PDF-1.7</code>. The five-character prefix <code>%PDF-</code> is fixed; the version digits vary. The first line terminates with a carriage return, line feed, or both.</p>
        `,
      },
      {
        id: 'structure',
        title: 'Core PDF structures',
        html: `
          <div class="data-table-wrap">
            <table class="data-table">
              <thead><tr><th>Structure</th><th>Typical token</th><th>Role</th></tr></thead>
              <tbody>
                <tr><td>Header</td><td>%PDF-1.x</td><td>Declares the file format and header version</td></tr>
                <tr><td>Indirect object</td><td>n g obj … endobj</td><td>Stores dictionaries, arrays, streams, pages, and other values</td></tr>
                <tr><td>Stream</td><td>stream … endstream</td><td>Contains byte data that may use one or more filters</td></tr>
                <tr><td>Cross-reference</td><td>xref or XRef stream</td><td>Maps object numbers to file positions or compressed locations</td></tr>
                <tr><td>Trailer data</td><td>trailer or XRef dictionary</td><td>Identifies the document catalog and related metadata</td></tr>
                <tr><td>Final pointer</td><td>startxref</td><td>Points to the latest cross-reference section or stream</td></tr>
                <tr><td>End marker</td><td>%%EOF</td><td>Marks the end of a PDF revision</td></tr>
              </tbody>
            </table>
          </div>
        `,
      },
      {
        id: 'trailer',
        title: 'Read the file from the end',
        html: `
          <p>A conventional PDF trailer is followed by <code>startxref</code>, a decimal byte offset, and <code>%%EOF</code>. PDF 1.5 and later can place trailer entries inside a cross-reference stream instead of using the literal <code>xref</code> and <code>trailer</code> keywords.</p>
          <p>Incremental updates append changed objects and a new cross-reference section rather than rewriting the whole document. A valid updated file can therefore contain several <code>%%EOF</code> markers; the final revision is the relevant entry point.</p>
        `,
      },
      {
        id: 'inspection',
        title: 'Practical PDF inspection checks',
        html: `
          <ul>
            <li>Confirm the ASCII <code>%PDF-</code> header and version token.</li>
            <li>Search for <code>startxref</code> and compare its number with the target byte offset.</li>
            <li>Expect streams to contain compressed or otherwise filtered bytes, not only readable text.</li>
            <li>Account for incremental revisions before treating duplicate objects as corruption.</li>
            <li>Use a sandboxed, format-aware parser for security-sensitive validation.</li>
          </ul>
        `,
      },
    ],
    faqs: [
      { question: 'Is all PDF content readable as text?', answer: 'No. PDF syntax contains readable tokens, but stream data is often compressed, encoded, encrypted, or binary.' },
      { question: 'Why can a PDF contain more than one %%EOF marker?', answer: 'Incremental updates append a complete new revision trailer and EOF marker while preserving earlier bytes.' },
      { question: 'Does the header version always control features?', answer: 'Not always. Starting with PDF 1.4, the document catalog may contain a Version entry that supersedes the header value.' },
    ],
    source: { label: 'Adobe PDF 32000-1:2008 specification', url: 'https://opensource.adobe.com/dc-acrobat-sdk-docs/standards/pdfstandards/pdf/PDF32000_2008.pdf' },
    related: [
      { slug: '/tools/file-signature-checker', label: 'File signature checker', note: 'Confirm the %PDF- prefix' },
      { slug: '/tools/hex-to-text', label: 'Hex to text', note: 'Decode readable PDF tokens' },
      { slug: '/file-formats/zip', label: 'ZIP header reference', note: 'Inspect another structured container' },
    ],
  },
  {
    type: 'format',
    slug: '/file-formats/zip',
    label: 'ZIP file format',
    eyebrow: 'File format reference',
    title: 'ZIP File Header & Magic Bytes Reference | Bitpeek',
    description:
      'Inspect ZIP local file headers, central-directory records, end-of-central-directory signatures, field offsets, flags, sizes, and little-endian values.',
    h1: 'ZIP File Header and Magic Bytes',
    lead:
      'A typical ZIP archive begins with a local file header and ends with a central directory plus an end record. Multi-byte numeric fields use little-endian byte order.',
    ctaHref: '/?intent=signature#workspace',
    ctaLabel: 'Inspect a ZIP file',
    ctaHeading: 'Open a ZIP header in Bitpeek',
    ctaText:
      'Verify the local-file-header signature, read the fixed 30-byte header, then calculate where the file name, extra field, and payload begin.',
    sections: [
      {
        id: 'signature',
        title: 'ZIP local file header signature',
        html: `
          <div class="code-signature"><code>50 4B 03 04</code></div>
          <p>These are the on-disk bytes for the 32-bit value <code>0x04034B50</code>. Most archives begin with this local header, although prefixed or self-extracting archives can place other data before it.</p>
        `,
      },
      {
        id: 'local-header',
        title: 'Local file header fields',
        html: `
          <div class="data-table-wrap">
            <table class="data-table">
              <thead><tr><th>Offset</th><th>Length</th><th>Field</th></tr></thead>
              <tbody>
                <tr><td>0x00</td><td>4</td><td>Local header signature</td></tr>
                <tr><td>0x04</td><td>2</td><td>Version needed to extract</td></tr>
                <tr><td>0x06</td><td>2</td><td>General-purpose bit flags</td></tr>
                <tr><td>0x08</td><td>2</td><td>Compression method</td></tr>
                <tr><td>0x0A</td><td>2</td><td>Last modification time</td></tr>
                <tr><td>0x0C</td><td>2</td><td>Last modification date</td></tr>
                <tr><td>0x0E</td><td>4</td><td>CRC-32</td></tr>
                <tr><td>0x12</td><td>4</td><td>Compressed size</td></tr>
                <tr><td>0x16</td><td>4</td><td>Uncompressed size</td></tr>
                <tr><td>0x1A</td><td>2</td><td>File name length</td></tr>
                <tr><td>0x1C</td><td>2</td><td>Extra field length</td></tr>
                <tr><td>0x1E</td><td>Variable</td><td>File name, extra field, then file data</td></tr>
              </tbody>
            </table>
          </div>
        `,
      },
      {
        id: 'directory',
        title: 'Central directory and end records',
        html: `
          <p>Central-directory file headers use <code>50 4B 01 02</code>. The classic End of Central Directory record uses <code>50 4B 05 06</code> and stores the entry count, central-directory size and offset, plus an optional archive comment.</p>
          <p>ZIP64 archives add ZIP64 end records and locators when classic 16- or 32-bit fields cannot represent the actual values. Do not assume a zero or maximum placeholder is the final size without checking ZIP64 metadata.</p>
        `,
      },
      {
        id: 'inspection',
        title: 'Practical ZIP inspection checks',
        html: `
          <ul>
            <li>Interpret fixed numeric fields as little-endian.</li>
            <li>Calculate the payload start as 30 + file-name length + extra-field length from the local header start.</li>
            <li>Check general-purpose bit 3 before relying on CRC and sizes in the local header; a trailing data descriptor may carry them.</li>
            <li>Remember that JAR, APK, DOCX, XLSX, PPTX, EPUB, and other formats can use ZIP as a container.</li>
            <li>Use a hardened archive library before extracting untrusted names or payloads.</li>
          </ul>
        `,
      },
    ],
    faqs: [
      { question: 'Is every file starting with PK a ZIP archive?', answer: 'No. The bytes are a format clue. Confirm the complete record structure and central directory before treating the file as a valid archive.' },
      { question: 'Why can local-header sizes be zero?', answer: 'When general-purpose bit 3 is set, CRC and size values can follow the compressed data in a data descriptor instead of being known when the local header is written.' },
      { question: 'Does ZIP always start at offset 0?', answer: 'Typical archives do, but self-extracting and deliberately prefixed files can place other bytes before the first ZIP record.' },
    ],
    source: { label: 'PKWARE .ZIP Application Note', url: 'https://support.pkware.com/pkzip/appnote' },
    related: [
      { slug: '/tools/file-signature-checker', label: 'File signature checker', note: 'Confirm the local-header signature' },
      { slug: '/tools/binary-viewer', label: 'Binary viewer', note: 'Read little-endian size fields' },
      { slug: '/file-formats/pdf', label: 'PDF header reference', note: 'Compare document container structures' },
    ],
  },
  {
    type: 'format',
    slug: '/file-formats/elf',
    label: 'ELF file format',
    eyebrow: 'File format reference',
    title: 'ELF Header & Magic Bytes Reference | Bitpeek',
    description:
      'Inspect ELF magic bytes, 32-bit and 64-bit class, byte-order encoding, OS ABI, object type, machine field, and variable header offsets in a local hex viewer.',
    h1: 'ELF Header and Magic Bytes',
    lead:
      'Executable and Linkable Format files start with a 16-byte identification array. Its first bytes establish the format, class, byte order, version, and ABI before the remaining header is interpreted.',
    ctaHref: '/?intent=signature#workspace',
    ctaLabel: 'Inspect an ELF file',
    ctaHeading: 'Open an ELF header in Bitpeek',
    ctaText:
      'Verify the magic bytes first, then use EI_CLASS and EI_DATA to choose the correct widths and byte order for later fields.',
    sections: [
      {
        id: 'signature',
        title: 'ELF magic bytes at offset 0',
        html: `
          <div class="code-signature"><code>7F 45 4C 46</code></div>
          <p>The first byte is <code>0x7F</code>, followed by ASCII <code>ELF</code>. These four bytes identify an ELF object before processor-specific fields are read.</p>
        `,
      },
      {
        id: 'identification',
        title: 'The 16-byte e_ident array',
        html: `
          <div class="data-table-wrap">
            <table class="data-table">
              <thead><tr><th>Offset</th><th>Name</th><th>Meaning</th></tr></thead>
              <tbody>
                <tr><td>0x00–0x03</td><td>EI_MAG0–3</td><td><code>7F 45 4C 46</code></td></tr>
                <tr><td>0x04</td><td>EI_CLASS</td><td>1 = ELF32, 2 = ELF64</td></tr>
                <tr><td>0x05</td><td>EI_DATA</td><td>1 = little-endian, 2 = big-endian</td></tr>
                <tr><td>0x06</td><td>EI_VERSION</td><td>ELF identification version</td></tr>
                <tr><td>0x07</td><td>EI_OSABI</td><td>Operating system or ABI identification</td></tr>
                <tr><td>0x08</td><td>EI_ABIVERSION</td><td>ABI-specific version when defined</td></tr>
                <tr><td>0x09–0x0F</td><td>EI_PAD</td><td>Reserved padding bytes</td></tr>
              </tbody>
            </table>
          </div>
        `,
      },
      {
        id: 'header',
        title: 'Fields after e_ident',
        html: `
          <p>At offset <code>0x10</code>, <code>e_type</code> identifies relocatable, executable, shared, core, or processor-specific object types. <code>e_machine</code> follows at <code>0x12</code>, and <code>e_version</code> begins at <code>0x14</code>.</p>
          <p>Later field widths depend on EI_CLASS. For example, <code>e_entry</code> is four bytes in ELF32 and eight bytes in ELF64. The program-header and section-header offsets also move between the two layouts. EI_DATA controls the byte order for all multi-byte values.</p>
        `,
      },
      {
        id: 'inspection',
        title: 'Practical ELF inspection checks',
        html: `
          <ul>
            <li>Read EI_CLASS and EI_DATA before interpreting any multi-byte field.</li>
            <li>Use e_type and e_machine to understand the object role and target architecture.</li>
            <li>Check header sizes and entry counts before following program- or section-table offsets.</li>
            <li>Expect executables and shared objects to have no <code>.elf</code> extension on Unix-like systems.</li>
            <li>Use platform tools such as <code>readelf</code> for complete semantic validation.</li>
          </ul>
        `,
      },
    ],
    faqs: [
      { question: 'How do I tell ELF32 from ELF64?', answer: 'Read byte 4 (EI_CLASS). A value of 1 means ELF32 and 2 means ELF64.' },
      { question: 'How do I know the ELF byte order?', answer: 'Read byte 5 (EI_DATA). A value of 1 selects little-endian encoding and 2 selects big-endian encoding for multi-byte fields.' },
      { question: 'Does an ELF file need an .elf extension?', answer: 'No. Unix executables, shared libraries, object files, core files, and firmware payloads can all use ELF with different names or extensions.' },
    ],
    source: { label: 'System V ABI — ELF Header', url: 'https://www.sco.com/developers/gabi/latest/ch4.eheader.html' },
    related: [
      { slug: '/tools/file-signature-checker', label: 'File signature checker', note: 'Confirm the ELF magic bytes' },
      { slug: '/tools/binary-viewer', label: 'Binary viewer', note: 'Interpret class-dependent fields' },
      { slug: '/tools/binary-diff', label: 'Binary diff', note: 'Compare two compact ELF objects' },
    ],
  },
]

export const allSeoPages = [...toolPages, ...formatPages]
