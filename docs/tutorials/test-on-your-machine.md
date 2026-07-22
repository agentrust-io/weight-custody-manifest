# Test WCM on your machine with a real open model

You do not need confidential-computing hardware to exercise Weight Custody
Manifest end to end. This runs the whole flow over a **real open-weight model's
actual weights** on any laptop.

## What is real vs mocked

The only mocked part is the hardware attestation evidence: your machine has no
SEV-SNP / TDX / H100, so the demo uses the `SoftwareProvider` (no hardware root
of trust). That hardware-rooted step is validated separately on real cloud
silicon (see [Replaying a real SEV-SNP quote](snp-quote-replay.md); TDX is
validated on GCP and Azure). Everything else is real WCM code over real weights:

- **integrity / provenance** - the manifest binds a `weights_hash` computed over
  the model's actual safetensors bytes;
- **joint signing** - real Ed25519 builder + custodian signatures;
- the **release gate** logic, **wipe-on-lapse** kill switch, **license** as a
  release condition, and **derivative custody + lineage**.

## Run it

```bash
pip install huggingface_hub safetensors
cd python
python examples/real_open_model.py                       # SmolLM2-135M (~270 MB)
```

First run downloads and caches the model; later runs are instant. Options:

```bash
python examples/real_open_model.py --model Qwen/Qwen2.5-0.5B --license Apache-2.0
python examples/real_open_model.py --local path/to/model.safetensors
python examples/real_open_model.py --infer      # also load + generate (needs transformers)
```

## What you will see

1. A **real `weights_hash`** over the downloaded model's bytes, bound into a
   signed manifest, verified, with the `open` / `byom-symmetric` consistency
   notes printed (the open-weight reframe: this protects integrity, license, and
   derivative custody, not secrecy).
2. The attestation gate releasing, wipe-on-lapse custody active, the license
   bound as a release condition.
3. A fine-tune's derivative getting its own manifest and a verified **lineage**
   back to the real base.
4. **Integrity made concrete**: the script re-hashes the weights as if one byte
   were flipped (a silently poisoned fork) and shows that hash no longer matches
   the manifest, so such weights never load.

With `--infer`, the certified serving stack is a real model that actually loads
and generates a few tokens, rather than a placeholder.

## The honest caveat

A software-mock attestation carries no hardware root of trust, so this proves
the *protocol* end to end, not a hardware guarantee. And even the real hardware
path does not defeat a physically-extracted attestation key (open question 8.8);
that is the reason publication is staged. What this local run gives you is the
full custody, licensing, and lineage machinery, exercised on weights you can
download and hash yourself.
