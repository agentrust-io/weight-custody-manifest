# Universal dependency-lock review

`python tools/check_lock_delta.py --base <base-sha> requirements/dev.txt`
checks exact pins, SHA-256 hash syntax, and preservation of existing package and
extras and environment-marker pairs. It reports packages whose versions changed. Added
packages and version changes still require ordinary dependency review; the
checker does not decide whether their code is safe.

Add `--resolve` to perform hash-required, isolated-environment dry runs with uv for
Linux x86-64 and Windows x86-64 at Python 3.11. These use network metadata and do
not execute Windows tests or install the resolved packages. The dedicated CI job
checks the four existing locks against the PR base without publishing anything.

A legitimate dependency removal or marker change needs an explicit
`--allow-removed <package>` invocation and reviewer assessment. CI deliberately
supplies no such exception. New locks need their own review: failure to read a
base lock is an error rather than a reason to omit comparison. Other pip input
forms are refused; this tool accepts only the repository's generated pin/hash
format. It does not claim complete PEP 508 semantic equivalence.
