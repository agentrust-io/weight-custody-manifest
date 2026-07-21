---
name: Bug report
about: Incorrect behavior in the SDK or test suite
labels: bug
---

## SDK version

<!-- Output of: pip show weight-custody-manifest | grep Version -->

## Python version

<!-- Output of: python --version -->

## What happened

<!-- Describe the behavior you observed. -->

## What you expected

<!-- Describe what you expected instead. Reference the spec section if applicable (e.g. SPEC §3.2). -->

## Reproduction

```python
# Minimal code to reproduce
```

## Error output

```
# Full traceback or incorrect output
```

## Trust-model context

<!-- Which posture does this concern: the semi-trusted operator (default) or the
hostile-owner posture? Note: "a hardware owner can extract the key" is a
documented limitation (see LIMITATIONS.md / SPEC §3.6), not a bug. -->
