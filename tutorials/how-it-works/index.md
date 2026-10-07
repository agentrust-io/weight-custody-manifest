# How WCM works (the six steps)

A plain-language tour of WCM from start to finish, for anyone who wants to understand the idea before reading the specification. No cryptography background is needed. The [runnable examples](https://github.com/agentrust-io/integrations/tree/main/examples/weight-custody-manifest) then show it working.

## The problem, in one sentence

When a model builder installs its weights in **someone else's** infrastructure (their own data center, a national cloud, or an offline network), the usual worry is reversed: the party at risk is the **builder**, whose weights now sit on hardware and with staff it does not control. WCM is the protocol for that case.

## The cast

- **Builder.** Approves which model files and which serving software may be used.
- **Custodian.** Runs the key broker service (KBS) that decides whether to release the key. Signs the manifest together with the builder, so neither acts alone.
- **Customer or operator.** Runs the protected environment (the enclave) on their own hardware. They are the party being limited, so they never sign the manifest alone.
- **KBS.** The key broker. It sends a one-time challenge, checks the hardware evidence that comes back (the attestation), and releases the decryption key only into an enclave that passes.

For an open model these roles often belong to one team inside one company (see the [runnable examples](https://github.com/agentrust-io/integrations/tree/main/examples/weight-custody-manifest)).

## The six steps

These steps assume the builder trusts whoever runs the key service. If the customer controls the broker's keys and checking settings, signing a manifest together does not stop that customer from going around it. A design for a customer-hosted, hardware-checked KBS is written down, but the reference server does not build its protected setup step. See [who controls key release](https://wcm.agentrust-io.com/deployment-trust/index.md).

**0. Certify: the manifest.** The builder writes a signed manifest. It records the `weights_hash` (a fingerprint of the exact model files), the release terms (license, whether fine-tuning is allowed) and the release policy (which hardware, which serving software fingerprint, which trusted clock). The builder and the custodian sign it **together**. It is the deployment agreement in a form a machine can check and enforce.

**1. Verify: is this the real manifest?** Anyone can check the joint signature. Both the builder and the custodian (and a national signer, under the sovereign profile) must have signed the exact same bytes. A changed manifest fails the check.

**2. Gate: release only after a hardware check.** The KBS sends a one-time number (a nonce). The enclave answers with evidence: a signed report from the CPU and a *separate* signed report from the GPU, both repeating that number. The KBS checks that the hardware is genuine, that it is the platform the manifest requires, and that the serving software's fingerprint matches what the builder signed. Only then does it release the decryption key into the enclave. The key works **only** inside the serving software the builder approved, which is how "no way to copy the raw weights out" becomes something the system enforces.

**3. Custody: wipe when approval lapses.** The enclave keeps the key only for a set window. If it does not pass the hardware check again in time, it **erases** the key from its own memory and stops answering requests. The key is gone, not paused. It also calls the shutdown hook the deployment supplied to stop the serving process. This limits the worst case to one window, even if a compromised host blocks every revoke message, *as long as the clock cannot be stalled* (`trusted_time_source`).

**4. Terms: license and permitted use.** The manifest's `release_terms` carry the license and any limits on use, and the key is released only to a setup that matches them. Contract text becomes a technical condition for release.

**5. Derive: fine-tune history.** If the customer may fine-tune the model inside the enclave, the result gets its own manifest. Its `derived_from` field points at the original, and `rights_holder` records who owns what, giving a chain back to the original model.

**6. Revoke: the off switch.** Either party (or the national signers, under the sovereign profile) can revoke. The enclave ends custody and shuts serving down at the next window at the latest. Wipe-on-lapse is the safety net underneath revoking.

## The honest limit

WCM never claims that the chip alone keeps the key safe from an operator who **physically owns the hardware**. Cheap published attacks (TEE.fail, BadRAM) defeat current confidential-computing chips. Against that operator WCM offers higher cost, detection, containment, legal recourse and required physical hardening, not cryptographic custody. See [Limitations](https://wcm.agentrust-io.com/limitations/index.md) and `SPEC.md` §3.6.

## Closed vs open weights

For a **closed** model, steps 0 to 2 keep the weights secret. For an **open** model the base weights are already public, so secrecy adds nothing. The same steps still prove the files are intact, enforce the license, and above all keep track of fine-tuned copies. The [runnable open-model example](https://github.com/agentrust-io/integrations/tree/main/examples/weight-custody-manifest) shows this difference.
