# Provider certificate policy

WCM rejects X.509 certificates whose serial number is zero or negative. RFC
5280 requires positive serial numbers, and supporting non-conforming provider
certificates would make behavior dependency-version-specific.

`cryptography` 50 warns while loading these certificates; version 51 rejects
them. WCM isolates both behaviors behind one loader and returns the same
non-sensitive, fail-closed policy error. It does not rewrite the certificate or
skip any chain, signature, validity, or revocation check.

CI exercises the sanitized non-positive-serial case against both dependency
lines. Fixtures contain generated names and keys only—never raw provider tokens,
tenant identifiers, or environment identifiers.
