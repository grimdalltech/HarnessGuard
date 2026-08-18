# Contributing

HarnessGuard is intentionally dependency-free at runtime. Contributions should preserve offline operation and deterministic results.

1. Create a focused branch.
2. Add a test that demonstrates the missed unsafe pattern or false positive.
3. Implement the smallest AST-aware detector that fixes it.
4. Run `python -m unittest discover -s tests -v` (no third-party test runner required).
5. Document new rule behavior and remediation.

Rule IDs are stable API. Add new IDs; do not silently change the meaning of released IDs.

For security-sensitive defects, open a private security advisory instead of a public issue containing exploit details.
