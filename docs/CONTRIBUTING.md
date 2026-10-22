# Contributing to CCK

Thank you for your interest in contributing to CCK! We welcome contributions to the Core Reliability Engine, Connectors, Control Plane, and Testing Lab.

---

## 1. Development Workflow

1. Fork the repository and clone your fork:
   ```bash
   git clone https://github.com/<your-username>/cck.git
   cd cck
   ```

2. Create a virtual environment and install development dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. Run the full test suite:
   ```bash
   pytest -v
   ```

4. Run linting and code formatting checks:
   ```bash
   ruff check src/ tests/
   ```

---

## 2. Core Architectural Invariants

When writing code or pull requests for CCK, you must preserve these design invariants:

- **Decoupled Engine**: Never tightly couple the engine to a single LLM provider. CCK evaluates *actions*, *facts*, *evidence*, and *policies* deterministically.
- **System-Minted Evidence**: Never accept raw LLM-hallucinated evidence IDs as authentic without verification in `EvidenceRegistry`.
- **Zero-Bypass Gate**: External mutating actions must pass through `ActionGate` and `TargetValidator`.
- **Cryptographic Event Chain**: Do not break or bypass `compute_journal_hash` when appending events to `EventJournal`.
- **No Unsafe Auto-Retries**: After a network disconnect during an execution with unknown outcome, do not automatically retry without human inspection.

---

## 3. Submitting Pull Requests

1. Create a feature branch: `git checkout -b feat/my-connector`
2. Add comprehensive unit and integration tests under `tests/unit/` or `tests/integration/`.
3. Ensure 100% test pass rate: `pytest -v`
4. Commit your changes with clear, semantic commit messages.
5. Push to your fork and submit a Pull Request to `main`.
