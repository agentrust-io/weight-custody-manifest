# End-to-end on an open-weight model

This tutorial runs the whole flow against an **open-weight** model (Llama,
Mistral, SmolLM, ...) and is honest about what changes when the base weights are
public. The runnable version is
[`python/examples/open_model_e2e.py`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/python/examples/open_model_e2e.py):

```bash
cd python && pip install -e . && python examples/open_model_e2e.py
```

It uses a **software (mock) attestation provider**, so it runs anywhere with no
hardware. A real-hardware variant (live enclave + real SEV-SNP/GPU quotes) is
follow-up work, gated on confidential-GPU access.

## What flips when the base is public

If the weights are downloadable from HuggingFace, encrypting them at rest and
gating decryption behind attestation **protects nothing** - anyone can download
the same checkpoint and skip the enclave. Saying that plainly is the point.
Half the six steps change purpose:

| Step | Closed model | Open-weight model |
|---|---|---|
| 0 Certify | secrecy of the weights | **integrity + license** - prove this is the certified checkpoint, under a conforming license |
| 1 Verify | authorship | **provenance** - not a silently tampered fork |
| 2 Gate | don't leak the secret | **load only the certified serving stack** (tamper-evidence, not secrecy) |
| 3 Custody | contain a leak | **kill switch** for a recall / license breach |
| 4 Terms | usually N/A | **license as a technical release condition** |
| 5 Derive | secondary | **the primary asset** - the fine-tune is novel IP that never existed publicly |
| 6 Revoke | theft response | recall / license / governance response |

The base's own confidentiality is theater; the **derivative** is the reason to
run the stack at all.

## Who is the "builder"?

For a closed frontier model there is one clear builder. For an open-weight model
nobody operates a KBS on Meta's behalf for every downstream deployment. In
practice the **enterprise's own model-governance function** plays both roles:
"builder" (certifying which checkpoint and serving image are approved
internally) and "customer" (running it). That symmetric case is design principle
4 (bring-your-own-model), and this demo is where it gets built rather than
deferred. In the example, one governance org holds both the builder and
custodian keys.

## The walkthrough

- **Step 0-1** build and jointly sign the base manifest and verify it. The
  manifest binds the public `weights_hash`, the certified serving-image
  measurement, and the Llama license. The signature proves *provenance*, not
  secrecy.
- **Step 2** runs the attestation gate. The "loading key" protects no secret, but
  the gate still enforces that you are running the approved platform and the
  exact serving stack the governance team signed - a silently modified fork of
  the public weights would not load.
- **Step 3** takes custody with wipe-on-lapse. The kill switch is now for a
  safety recall or license violation, not theft.
- **Step 4** shows the license bound into the manifest as a release condition.
- **Step 5** fine-tunes on proprietary data and issues a **derivative manifest**
  (`derived_from` the public base, `rights_holder` = the enterprise). This is the
  real IP.
- **Step 6** verifies the lineage chain (derivative → public base root). The
  derivative manifest sets `derivatives: none`, so the enterprise's own fine-tune
  cannot itself be re-derived without violating its policy.

## The takeaway

Same six steps as the closed-model flow, same attestation gate and wipe-on-lapse
floor - but for open weights the base-secrecy mechanism is theater, and the work
that actually matters is integrity, license enforcement, and derivative custody.
A deployment that kept the encrypt-the-base mechanism and implied it protected
the public base would be overclaiming; WCM says so out loud.
