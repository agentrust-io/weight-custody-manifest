# Broker deployment identity: approval contract

This is the software contract and provisional SNP adapter specification for
[#144](https://github.com/agentrust-io/weight-custody-manifest/issues/144).
It derives a deterministic owner-side approval record from local build inputs
and constrains provisioning to the approved policy. It does **not** establish
that a running broker executes those inputs. No live hardware validation of this
profile has been performed, and the repository does not yet build its immutable
boot image.

## Platform-neutral requirements

A deployment identity has three independent obligations:

1. **Approval before deployment.** An independent owner approves the code,
   configuration, boot/loading chain, dependencies and platform policy. The
   expected identity must be derivable without asking the target what to trust.
2. **Evidence-to-execution binding.** An authenticated platform measurement must
   cover an approved loader that enforces those inputs. A signed guest assertion
   or a digest supplied by an untrusted host is insufficient on its own.
3. **Instance binding and continuity.** Fresh evidence must bind the provisioning
   recipient key and effective policy to this instance. Post-appraisal mutation,
   administrative entry points, key export and restart must obey the deployment
   contract. Approval hashes cannot enforce these properties.

Each platform adapter must state its measurement semantics, independently
derivable inputs, trusted computing base and unsupported cases. The first record
format supports only `wcm/snp-direct-boot-initrd/v1`; unknown profiles are rejected.
It does not reinterpret OCI digests, Azure PCR events, TDX measurements or
self-reported configuration hashes as native-SNP launch measurements.

## What each identifier means

| Identifier | Meaning | What it does not establish |
| --- | --- | --- |
| OCI digest | Identity of an OCI object | Guest launch identity or effective mounted configuration |
| Existing image comparison snapshot | Equality of selected filesystem/configuration build outputs | A hardware measurement |
| Artifact SHA-256 and size | Exact independently supplied build input bytes | That the artifact is present or enforced in a running guest |
| Native-SNP measurement, 48 raw bytes | Expected signed launch digest from the reviewed measurement procedure | Code loaded afterward unless the measured loader authenticates it |
| Effective configuration SHA-256 | Exact receiver constructor inputs and fixed profile | Protection against modified code that lies about those inputs |
| Provisioning-policy SHA-256 | Exact existing domain-separated policy context, including epoch and platform controls | Authorization to change that policy |
| Deployment approval identity | Domain-separated SHA-256 of the canonical approval record | Hardware validation, key installation or model execution |

The record commits to seven artifact roles: `application`, `command_line`,
`configuration`, `firmware`, `initrd`, `kernel`, and `measurement_tool`, in that
order. Each role has a SHA-256 digest and nonzero size. The application artifact
must identify the complete approved application/dependency bundle. The tool
artifact should identify the reviewed measurement-tool distribution and its
reproducible environment. The separate initrd must actually contain the approved
runtime bundle; the record generator does not inspect or prove that relationship.
An independent packaging review must establish it before a hardware claim.

Records omit local filenames and timestamps. Identity is
`SHA256(domain || canonical_json)`, where the domain is the ASCII string
`wcm/deployment-approval/v1` followed by one NUL byte. It is serialized as a
`sha256:` value. Canonical JSON sorts object keys,
uses compact separators and ASCII escapes, and preserves the required artifact
order. Duplicate JSON members, extra fields, malformed digests, missing/repeated
roles and unsupported profiles fail validation. Nested records are immutable.

## Derive and check an owner approval

On the trusted owner/build host, first derive the expected launch measurement
with the independently reviewed tool, using the actual firmware, kernel,
initrd, command line and vCPU parameters. **Do not copy the measurement from a
target report.** The WCM command below hashes the inputs and checks consistency;
it does not calculate the SNP launch digest or approve the measurement tool.

Create `identity-inputs.json`:

```json
{
  "artifacts": {
    "application": "broker-runtime.tar",
    "command_line": "kernel-command-line.txt",
    "configuration": "approved-broker.json",
    "firmware": "OVMF.fd",
    "initrd": "broker-initrd.img",
    "kernel": "vmlinuz",
    "measurement_tool": "reviewed-measurement-tool.tar"
  },
  "launch": {
    "vmm_type": "QEMU", "vcpus": 1,
    "vcpu_type": "EPYC-v4", "guest_features": "0x1"
  },
  "expected_measurement_hex": "<96 lowercase hex characters from independent prediction>",
  "policy_file": "approved-policy.json"
}
```

Replace the placeholder with the independently derived result. The approved
policy must contain that measurement and the reviewed effective configuration
digest. See [the owner client](owner-provisioning-client.md) for deriving the
effective digest from actual configuration inputs.

```sh
python -m wcm.deployment_identity identity-inputs.json > approved-identity.json
python -m wcm.deployment_identity identity-inputs.json --identity-only
python -m wcm.deployment_identity identity-inputs.json \
  --verify-approval approved-identity.json --expected-identity sha256:<owner-pin>
```

The last command re-derives the candidate from files and compares it to the
independently pinned approval. Changed application/configuration bytes, launch
parameters, tool inputs or policy produce a different identity. Protect the
approval and its pin independently from the deployment. An attacker who can
replace both on the owner host can change what is approved. Read and hash inputs
from a frozen build snapshot; this command is not a concurrent filesystem-mutation
guard or a launcher.

Opt in on the owner provisioning client with both fields:

```json
{
  "deployment_approval_file": "approved-identity.json",
  "deployment_approval_identity": "sha256:<independently approved identity>"
}
```

These fields extend the existing owner configuration. A missing half, changed
record, wrong pin or policy mismatch fails before contacting the broker. The
library `OwnerProvisioner` also accepts `deployment_approval`; this object must
come from trusted owner inputs. Its policy checks apply at construction, update
and release. The existing signed-report verifier still authenticates the nonce,
raw measurement, configuration/policy binding, platform fields and recipient key
before sealing anything. No verifier is replaced by an artifact hash check.
The wire report binds the policy referenced by the approval; it does not gain a
new field containing the approval record or its artifact list. Their relationship
depends on the independently reviewed measurement and packaging procedure.

The approval commits to the full provisioning policy, so even an epoch-only
update needs a newly reviewed record and a new owner instance. The existing
durable epoch store rejects stale owners once the new policy is admitted. It
still requires protected, nonsnapshot owner storage.

Receipts include the approval identity when configured and always report
`application_identity_established: false` in this software slice. Legacy clients
without the optional fields retain their existing native-SNP policy behavior.
Neither mode proves installation or protected execution.

## Provisional adapter: SNP direct boot with an initrd-contained broker

The intended chain is AMD-rooted SNP evidence → measured OVMF/initial vCPU state
and kernel-hash metadata → approved kernel/initrd/command line → fixed broker
entry point and complete runtime dependencies. The approved image must have no
unmeasured executable filesystem, network package installation, interactive
console, debug/admin shell or host-controlled interpreter/import override.

VirTEE's [measurement tool](https://github.com/virtee/sev-snp-measure) accepts
firmware, kernel, initrd, command-line and vCPU inputs for offline prediction.
Its output depends on these launch choices; firmware support for kernel hashes
is required for this profile. Pin the tool and environment rather than relying
on a moving default. This procedure specifies inputs, not a claim that WCM has
validated a particular firmware/QEMU/kernel combination.

The broker's effective configuration can be provided as untrusted **data** to
the measured loader. The loader must instantiate only the fixed approved code,
compute the digest of the actual loaded constructor inputs, and bind that digest
and the exact provisioning policy to its freshly generated in-boundary transport
key. The owner's existing nonce-bound report verification then checks that
binding. [Linux's SEV guest API](https://docs.kernel.org/virt/coco/sev-guest.html)
allows guest-supplied report data; that field is meaningful only when the
measurement identifies code that computes it honestly.

This distinction also avoids a circular build dependency: do not embed a policy
containing the final launch measurement into the initrd whose measurement is
being calculated. Treat the later policy as untrusted data, enforce the measured
loader's fixed behavior, and verify its full context from independent owner
inputs. A mutable image or generic guest that lets arbitrary code request reports
cannot satisfy this adapter merely by echoing the approved configuration hash.

The current Python receiver and report-binding checks are reusable components.
The immutable image builder, loader restrictions, guest privilege/device policy
and their live evidence remain required work. Unsupported deployment layouts
must report the property as not established.

## Required hardware validation, separately authorized

Freeze and retain the source revision, build/dependency inputs, tool distribution,
launch parameters, expected digest, approval record and independently obtained
AMD trust inputs **before** launching the target. Then run:

| Case | Required observation |
| --- | --- |
| Approved image/configuration, fresh key and challenge | Authenticated report matches independent prediction; only the recipient opens the sealed envelope |
| Substituted application/dependency in initrd | Re-derived digest/approval changes; owner rejects the actual mismatched report |
| Substituted firmware/kernel/initrd/command line or vCPU state | Prediction/report mismatch denies provisioning |
| Changed runtime configuration or policy with unchanged boot image | Effective-input check or signed policy binding denies before envelope creation |
| Replaced transport key, replayed challenge or old-boot envelope | Authentication/freshness fails; no successful installation in the new instance |
| Post-appraisal file mutation or executable injection | Image/loader refuses the mutation or stops admission; unchanged attestation alone is not a pass |
| Debug/admin path, report-device access or key export attempt | Denied by the deployed boundary; a Python private attribute is not protection |
| Restart and update | Fresh in-boundary key, new challenge and owner-approved policy; no inherited plaintext key or stale owner admission |

Record actual recipient/sink observations, not only reported errors. Include
negative controls that remove the relevant restriction and cause the oracle to
fail. Retain sanitized outcomes, exact verifier commands and limitations; raw
reports and device-linked certificates require private handling. Software tests
use synthetic signed SNP reports and cannot replace this run.

This profile does not establish side-channel resistance, host-wide recovery,
secure erasure, rollback-resistant runtime state or protected GPU execution.
Issue #144 remains open until the measured loader and live substitution/runtime
tests provide evidence for its stated deployment claim.
