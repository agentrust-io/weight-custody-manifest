# Provider certificate policy

A short note for implementers on one certificate rule WCM enforces and why. If a hardware or cloud provider's certificate is refused with a policy error, this page explains the cause.

WCM rejects X.509 certificates whose serial number is zero or negative. RFC 5280, the internet standard for these certificates, requires positive serial numbers, and accepting certificates that break it would make WCM's behavior depend on which version of a library is installed.

`cryptography` 50 warns while loading these certificates; its announced version 51 behavior is to reject them. WCM puts both behaviors behind one loader and returns the same policy error, which reveals nothing sensitive and refuses the release (fails closed). It does not rewrite the certificate or skip any chain, signature, validity, or revocation check.

Until version 51 is published, the runtime dependency remains capped below it. CI exercises the real version-50 warning path and an executable model of the documented version-51 load-time exception. The cap must not be lifted until CI can replace that model with the released dependency. Test data contains generated names and keys only, never raw provider tokens, tenant identifiers, or environment identifiers.
