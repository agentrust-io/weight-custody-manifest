# Sovereign self-custody with threshold release

A sovereign customer wants to run the model in its own jurisdiction, on hardware
it owns, and operate the key release service (KBS) itself, with no foreign party
in the release path. That is the hostile-owner posture, and it breaks a
convenient assumption: the owner can forge its own KBS attestation quote (open
question 8.8, key-extraction half). So single-key self-custody is unsound for a
sovereign, because one forged quote would self-release the key.

[Decision 15](../spec-overview.md) resolves this with **threshold split-key
release**: the key is split so no single party, the sovereign included, holds it.
The attested KBS enclave reconstructs the key only from a quorum of shares from
independent parties. One forged quote is then not enough, because it still yields
only one share.

## Run it

```bash
cd python
python examples/sovereign_self_custody.py
```

The demo uses a 2-of-3 split across the builder, the sovereign, and the
custodian, and walks the whole flow:

1. A sovereign manifest: `sovereign_profile.enabled` (quorum revocation),
   `customer-self-custody`, mandatory `physical_hardening` and
   `memory_fingerprint_challenge` for the hostile-owner posture, signed by all
   three parties.
2. The manifest verifies only with the sovereign quorum present.
3. The key is split 2-of-3. No party holds the whole key.
4. The attested KBS gate passes. Each party checks that attestation before
   contributing its share.
5. Any two shares reconstruct the key (so losing one party does not lose it);
   this happens inside the measured enclave, so no party sees the assembled key.
6. A single share, the sovereign's own, does **not** reconstruct the key. Even a
   forged KBS quote yields only that one share, so it cannot release.

## What carries the guarantee

In this posture the bound is **not** wipe-on-lapse (an owner who forges
attestation can defeat the enclave clock). It comes from threshold (no single
party assembles the key), the sovereign revocation quorum, mandatory physical
hardening on the KBS host, and the transparency log. The demo says so at the end
rather than implying a floor it does not have.

## What is real vs modelled

The split, the reconstruction, the attestation gate, and the manifest's
sovereign quorum are all real SDK code (`split_secret`, `combine_shares`,
`KeyBrokerService`, `verify_manifest`). The share contribution "into the enclave"
is narrated: a real deployment runs the combine inside the builder-measured KBS
enclave so the assembled key never leaves it. And the software attestation
provider carries no hardware root of trust; it exercises the gate logic, not real
silicon (see [Replaying a real SEV-SNP quote](snp-quote-replay.md) for that).
