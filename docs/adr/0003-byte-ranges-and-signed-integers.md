# ADR 0003: Strict Byte Ranges and Explicit Numerical Representation

## Status
Accepted

## Context
Binary inspection tools commonly introduce ambiguities around:
- Inclusive versus half-open byte ranges.
- Truncation of 64-bit integers to JavaScript IEEE-754 53-bit `Number`.
- Loss of NaN payloads in floating-point interpretations.
- Ambiguous handling of negative zero, subnormals, and overflow.

## Decision
1. Internal coordinate system across all parsers, recipes, and schemas strictly uses half-open intervals: `[start, endExclusive)`.
2. Offset values and lengths are validated as safe nonnegative integers.
3. In JSON serialization for APIs and reports, 64-bit integers (`u64`, `i64`) are encoded as decimal strings (e.g., `"18446744073709551615"`) to preserve exact bit fidelity.
4. Float interpretations explicitly handle `+0`, `-0`, `Infinity`, `-Infinity`, and `NaN`, displaying raw hex bits alongside interpreted floats so NaN payloads are never discarded.
5. Out-of-bounds ranges immediately trigger explicit structured errors (`INVALID_RANGE`), never silent clamping or truncation during mutations.

## Consequences
- Deterministic behavior across systems and architectures.
- Eliminates off-by-one errors and precision loss when analyzing low-level system structures.
