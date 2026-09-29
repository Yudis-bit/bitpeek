# ADR 0007: Provenance Graph, Cross-Layer Mapping, and Uncertainty

## Context
Security research across raw NAND, memory dumps, compressed streams, disassemblies, and AI tensors requires following evidence across abstraction layers. In traditional tools, transformations detach derived data from original bytes, obscuring how findings were obtained. Furthermore, probabilistic or heuristic results (such as majority-vote reconstruction or ECC correction) are often falsely presented as clean ground truth.

## Decision
1. **Provenance Directed Acyclic Graph (DAG)**:
   - Every artifact node declares its kind (`acquisition`, `snapshot`, `derived`, `parsed_field`, `trace`, `observation`, `finding`).
   - Every derivation records exact input snapshot IDs, operation/tool versions, canonical parameters, and audit metadata. Content identity is strictly separated from event identity.
   - Derivation cycles are mechanically rejected.
2. **Cross-Layer Mapping Relations**:
   - Spans are linked forward and backward via typed relations: `exact-affine`, `exact-piecewise`, `bit-permutation`, `scatter-gather`, `region-dependency`, `inferred`, or `unknown`.
   - UI and CLI queries support both output-to-input and input-to-output queries with bounded pagination.
3. **Explicit Uncertainty Model**:
   - Data quality states: `observed`, `derived-deterministic`, `inferred`, `candidate`, `uncorrectable`, `truncated`, or `missing`.
   - Missing or unread bytes are explicitly represented with validity/sparse maps, never silently zero-filled.
   - Candidate alternatives (e.g. multi-read disagreement or ECC corrections) are preserved alongside an audit ledger of every altered bit.

## Consequences
- Full auditability for vulnerability disclosures and reproducible research reports.
- Elimination of false certainty: heuristic guesses cannot masquerade as observed facts.
