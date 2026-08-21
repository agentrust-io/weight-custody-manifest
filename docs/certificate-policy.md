# Provider certificate policy

WCM rejects X.509 certificates whose serial number is zero or negative. RFC
5280 requires positive serial numbers, and supporting non-conforming provider
certificates would make behavior dependency-version-specific.

`cryptography` 50 warns while loading these certificates; its announced version
51 behavior is to reject them. WCM isolates both behaviors behind one loader and
returns the same non-sensitive, fail-closed policy error. It does not rewrite
the certificate or skip any chain, signature, validity, or revocation check.

Until version 51 is published, the runtime dependency remains capped below it.
CI exercises the real version-50 warning path and an executable model of the
documented version-51 load-time exception. The cap must not be lifted until CI
can replace that model with the released dependency. Fixtures contain generated
names and keys only—never raw provider tokens, tenant identifiers, or environment
identifiers.
