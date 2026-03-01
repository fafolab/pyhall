# Contributing to PyHall

PyHall is the Python reference implementation of WCP (Worker Class Protocol).
WCP is an open concept — fork it, implement it, improve it.

## What We're Looking For

- Bug fixes with regression tests
- New worker examples in `workers/examples/`
- Improvements to the routing engine that remain WCP-compliant
- Ports of WCP to other languages (link back to this repo)
- Extensions to the WCP spec (open an issue first to discuss)

## Getting Started

```bash
git clone https://github.com/fafolab/pyhall
cd pyhall
pip install -e ".[dev]"
pytest tests/
```

All tests must pass before submitting a PR.

## Code Standards

- Python 3.10+ compatible (no 3.12-specific syntax)
- Pydantic v2 for all models
- Type annotations on all public functions
- Docstrings on all public modules, classes, and functions
- No hardcoded paths or IP addresses
- No secrets or credentials in code

## Testing

Run the full test suite:

```bash
pytest tests/ -v
```

New features require new tests. Bug fixes require a regression test that
fails before the fix and passes after.

## WCP Compliance

Changes to `router.py` must maintain WCP compliance:
- Fail-closed behavior must never be weakened
- Mandatory telemetry must always be emitted on successful dispatch
- Deterministic routing must be preserved
- All deny paths must return a `RouteDecision` (never raise)

## Adding a Worker Example

1. Create `workers/examples/<your_worker>/`
2. Include `worker.py`, `registry_record.json`, `README.md`
3. Worker must implement the WorkerContext / WorkerResult pattern
4. Worker must produce telemetry and evidence receipt
5. Worker must never raise (return error status instead)

## Submitting Changes

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-feature`
3. Make your changes with tests
4. Run `pytest tests/` — all tests must pass
5. Open a pull request with a description of what changed and why

## WCP Spec Changes

The WCP spec is versioned separately from PyHall — see [github.com/fafolab/wcp](https://github.com/fafolab/wcp).

To propose a spec change:
1. Open an issue describing the problem and proposed solution
2. Reference existing agent protocol specs where relevant
3. Include a working implementation in PyHall
4. Mark proposed additions as `x.*` (experimental namespace) until stabilized

## License

By contributing, you agree your contributions will be licensed under the
MIT License. See LICENSE.
