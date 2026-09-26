# Contributing to Bitpeek

Thank you for contributing to Bitpeek. This project emphasizes correctness, local privacy, strict bounds checking, and deterministic binary reproducibility.

## Architectural Principles
1. **Core Independence**: Code in `packages/core` must remain pure TypeScript. Do not import React, DOM, localStorage, or Node filesystem libraries into the core.
2. **Deterministic Behavior**: The same input bytes must produce identical semantic results across Web, CLI, and MCP.
3. **Bounded Processing**: All file operations, searches, and string scans must enforce memory budgets, chunking, and pagination to prevent out-of-memory crashes.
4. **Zero Server Processing**: Do not introduce server-side file upload endpoints, analytics beacons, or remote telemetry.

## Development Workflow
```sh
npm install
npm run dev
```

## Running Quality Checks
Before submitting a PR, ensure all quality gates pass:
```sh
npm test         # Run all unit, property, and SEO tests
npm run lint     # ESLint validation
npm run build    # Typecheck, production bundle, and budget verification
```

## Issue & PR Guidelines
- **Minimal Reproducers**: Provide synthetic hex strings or minimal binary fixtures rather than proprietary or sensitive files.
- **Regression Tests**: Any bug fix must include a regression unit test demonstrating failure on the previous behavior and success on the fix.
- **Truthful Claims**: Avoid exaggerated descriptions. Technical documentation must accurately describe supported format subsets and known limitations.
