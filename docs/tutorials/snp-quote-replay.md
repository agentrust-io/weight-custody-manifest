# Replaying a real SEV-SNP quote

Layer 2 releases a key only after a key broker (KBS) verifies a hardware
attestation quote. This tutorial runs that verification yourself, offline,
against a recorded AMD SEV-SNP quote. It is the CPU half of the composite
verification in [the spec](../spec-overview.md) (the GPU half needs H100 quota
and is not covered here).

## What the KBS actually checks

Given a raw SNP report and its certificate chain, the KBS gate is four steps:

1. **Parse** the SNP report (version, launch measurement, chip id, REPORT_DATA).
2. **Chain**: the VCEK leaf chains to a trusted AMD root (ARK), through the ASK.
   AMD's certs are RSASSA-PSS, which the verifier honors per-certificate.
3. **Signature**: the report's own signature verifies under the VCEK.
4. **Freshness**: REPORT_DATA binds the challenge nonce, so a quote captured on
   the wire cannot be replayed for a later key request.

## Run it

The SDK ships a runnable demo and a committed **synthetic** bundle so it works
with no hardware:

```bash
cd python
python examples/snp_replay.py
```

The synthetic bundle is a self-consistent stand-in chain and report. It proves
the verification path end to end, but it is **not** real silicon and is labelled
as such in its output.

## Capture a genuine quote

To replay a real quote, capture one on an Azure SEV-SNP confidential VM
(`Standard_DC2as_v5` is a few cents an hour and needs no special quota):

```bash
# on the CVM
sudo apt-get install -y tpm2-tools
python3 tools/capture_snp_quote.py --out snp_quote_azure.json
# copy the file off, tear the VM down, then anywhere:
python examples/snp_replay.py snp_quote_azure.json
```

### One honest wrinkle: Azure freshness

Azure CVMs do not expose `/dev/sev-guest`, so the guest cannot write the KBS
nonce into the SNP report's `REPORT_DATA`. The paravisor binds `REPORT_DATA` to
the vTPM attestation key instead, and freshness for a live exchange comes from a
separate vTPM quote over that key. The captured Azure bundle therefore sets
`expected_nonce: null`, and the replay verifies the chain and report signature
(both genuine on Azure) while stating plainly that the SNP report does not bind
our nonce on this platform. A bare-metal `/dev/sev-guest` capture, where the
guest controls `REPORT_DATA`, would set a real nonce and exercise step 4
directly.

This is the same distinction the spec draws between the semi-trusted and
hostile-owner postures: the tooling never claims a binding the platform does not
provide.
