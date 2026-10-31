# Universal dependency-lock review

`python tools/check_lock_delta.py --base <base-sha> requirements/dev.txt`
checks exact pins, SHA-256 hash syntax, and preservation of existing package and
extras and environment-marker pairs. It reports packages whose versions or SHA-256
hash sets changed. Hash order and repeated identical hashes do not count as
changes. Added packages and changes still require ordinary dependency review;
the checker does not decide whether their code is safe.

Add `--resolve` to perform hash-required, isolated-environment dry runs with uv for
Linux x86-64 and Windows x86-64 at Python 3.11. These use network metadata and do
not execute Windows tests or install the resolved packages. The dedicated CI job
uses `--all-locks` to check every current and base `requirements/*.txt` path
without publishing anything. The union preserves deletion/rename detection; it
includes runtime, server and checker dependencies as well as development locks.

A legitimate dependency removal or marker change needs an explicit
`--allow-removed <package>` invocation and reviewer assessment. CI deliberately
supplies no such exception. In inventory mode, a successful Git base listing
identifies new paths explicitly: these are reported as new locks requiring review,
then structurally validated and resolved when requested. Missing current files,
invalid base revisions and unreadable existing base locks fail. Explicit-path mode
still refuses paths absent from the base rather than silently skipping comparison.
Other pip input forms are refused; this tool accepts only the repository's generated pin/hash
format. It does not claim complete PEP 508 semantic equivalence.

Hash options must follow the marker (when present); every trailing token must be
a complete lowercase SHA-256 hash option. Quoted marker literals are retained.
Marker text is compared as an identity, not evaluated or fully validated as
PEP 508 syntax; supported-platform resolution is a separate check.
