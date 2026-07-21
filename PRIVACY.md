# Privacy

The Weight Custody Manifest reference SDK collects and transmits no personal data.

It runs locally as a Python library, CLI, and optional local server. It processes only the inputs you give it - manifests, keys, evidence - on your own machine, and sends no telemetry, analytics, or usage data to agentrust-io, OPAQUE, or any third party. There is no account, login, or tracking.

Signing, verification, and the KBS gate run locally against the keys and files you provide. The only outbound calls are ones you configure yourself (for example, an attestation provider fetching a certificate chain from a vendor endpoint, or the reference KBS server you choose to run); the SDK makes no background network calls of its own.

Uninstalling removes it completely. Questions or corrections: https://github.com/agentrust-io/weight-custody-manifest/issues
