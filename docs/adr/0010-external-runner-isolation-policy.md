# ADR 0010: External Runner and Process Isolation Policy

## Context
Vulnerability reproduction and fuzz minimization often require executing native binaries, compilers, sanitizers, and debuggers. Executing untrusted binaries poses severe security risks if launched with host privileges, inherited environment secrets, or shell interpolation.

## Decision
1. **No Implicit Host Execution**:
   - Untrusted targets require an explicit isolation backend (`test-harness`, `docker-container`, `job-object`, or `mock-runner`).
   - If an isolation backend is absent, Bitpeek reports `missing-dependency` or `unavailable-backend` rather than silently executing native code directly on the host machine.
2. **Execution Discipline**:
   - Executables and arguments are passed as discrete string arrays—never interpolated through shell strings (`sh -c` or `cmd /c`).
   - Child processes receive a stripped environment with no inherited credentials, API keys, or sensitive environment variables.
   - Resource quotas (CPU time, wall clock timeout, memory limit, output bytes limit) are strictly enforced.
   - On timeout or cancellation, the entire process tree is terminated (using Job Objects on Windows or process groups on POSIX).
3. **Reproducible Minimization & Oracles**:
   - Reducer algorithms (delta debugging) require a pinned failure oracle (e.g. specific ASan diagnostic signature, exit code, or invariant failure).
   - Random crash or harness timeout does not count as preserving the original vulnerability.

## Consequences
- Protects researchers and host workstations from hostile binary execution.
- Ensures honest reporting of isolation capabilities and reproducible bug minimization.
