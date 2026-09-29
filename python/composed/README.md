# Composed software acceptance slice

This development harness extends the provisioning lifecycle work in #145 and
starts integrations#199. It belongs in the core repository while the required
cMCP disclosure and cA2A response APIs are unreleased. It is not a published
integration or completion of the live acceptance issue.

## Run

Use Python 3.12 and clean source checkouts:

- cMCP: `2cdb168ce52020406ff0ef6cbc34447f0ea55aee`
- cA2A: `fc22c644846111c7f375446399e9097a73f93214`
- WCM: this PR's tested head (recorded by the runner).

From the directory containing the three checkouts:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r wcm/requirements/composed.txt
python -m pip install --no-deps -e ./wcm/python -e ./cmcp -e ./ca2a
python wcm/python/composed/run.py --cmcp-source cmcp --ca2a-source ca2a --output evidence
```

Use a fresh evidence directory. The runner rejects changed dependency revisions
and tracked edits, records the WCM revision/diff and harness hashes, and exports
installed package versions. Third-party dependencies come from the hash-locked
`requirements/composed.txt`, which covers the pinned cMCP and cA2A revisions
above; recompile it when either revision moves. The hosted workflow repeats
these commands on native Linux.

## Standalone research bundle

The `composed-software` workflow now builds `composed-reproduction.zip` after
successful evaluation, then extracts it and repeats all 36 cases in a fresh
workspace and virtual environment. Download the `composed-reproduction-bundle`
artifact from the reviewed run. Its ZIP contains a Python launcher, the source
revision manifest, evaluated runtime dependency versions and usage instructions.
See [BUNDLE.md](BUNDLE.md) for prerequisites and limitations.

To build the same ZIP from a clean committed checkout, in the environment that
produced the successful evidence:

```sh
python wcm/python/composed/package.py --evidence evidence --output bundle/composed-reproduction.zip
```

This removes manual checkout/setup steps for reviewers. It still consumes
source snapshots and retains the fixture dependencies in their owning core
repository. A released-package integration remains waiting on the required API
releases and a separate package-only evaluation.

## Actual path and transaction binding

The existing WCM fixtures generate synthetic SNP signatures against test-owned
roots. Real owner provisioning, receiver installation, workload appraisal,
sealed release and key opening precede AES-GCM decryption of a diagnostic affine
model. The actual CPU computation is `3 * 7 + 2`, not an LLM or protected backend.

A fresh transaction is inside the approved model plaintext and AES-GCM associated
data. Its model digest enters the allowlisted manifest and owner provisioning
policy. The derived value and transaction enter a real cMCP/Cedar gateway and
JSON-RPC subprocess tool. The controller checks the returned transaction and
sends the actual tool return as a sealed cA2A payload. A real loopback HTTP peer
checks the scoped delegation and emits a request-bound response MAC. The response
record identifier must match the transaction. Exact-output owner approval then
binds the returned bytes, transaction source scope, recipient and policy before
release through the registered callback.

The controller's cross-stage checks are part of the trusted base; this is not a
new interoperable transcript schema. The model manifest fixture is owner-pinned,
not a demonstration of model publisher signatures. Trust roots, owners, peers,
workload, tool and recipient all share one operator and test host.

## Observations and controls

The positive oracle independently reads the tool's subprocess receipt and checks
peer-side decrypted bytes and recipient-callback bytes against the expected
transaction and value 23. These are distinct observation points, not independently
operated or cryptographically independent observers. Provisioning and key-release
states are local API observations, not remote installation proofs. The original
lifecycle suite separately covers HTTP installation ambiguity.

The suite tests substituted workload, recipient key, manifest policy, encrypted
model and transaction; missing quote or disclosure approval; forbidden tool,
delegation scope and software downgrade; changed response MAC; revoked release
authority; changed approved output; reopened replay storage; and callback failure
before versus after receipt. Both callback failures preserve unknown delivery and
consume the request before the attempt. Neither retries.

Sixteen portable test-only weakenings cover each named refusal, replay and
unknown-outcome case. Each must change its required observation: unsafe delivery,
replay or an acknowledged outcome where delivery must remain unknown. The runner
checks that the named scenario set and mutation-target set are equal. This is
coverage of these scenarios, not every protocol gate or input shape.

The manifest-policy case changes an allowed-environment term while retaining the
model digest and key label, avoiding unrelated missing-key checks. The key case
substitutes an attacker-owned key, so removing quote binding exposes actual key
opening and downstream delivery. The model control removes GCM finalization while
retaining real decryption, exposing unauthenticated plaintext from a changed tag.

## Native confined-agent profile

The hosted job also checks out cMCP confinement source
`bad751becca0ec5c42d70062e5c9fe5ee1380e85`, including the bounded-ack watchdog fix.
It builds `python/composed/Dockerfile` against its pinned base image and supplies
the immutable local image ID in `COMPOSED_AGENT_IMAGE`. Run the same command above
with `--confinement-source confinement` to include this profile. It requires a
native Linux Docker daemon and a non-piped host core-dump policy; the workflow
changes/restores that policy only on its disposable runner. The harness refuses
unsupported hosts instead of treating skipped Linux probes as a confined result.

The agent receives the already computed model-derived bytes inside the checked
container, tries IPv4/IPv6 TCP, UDP, a filesystem export and stderr, then asks for
one permitted and one forbidden tool. The host bridge routes those calls through
real cMCP. The actual permitted tool return continues through the same cA2A and
disclosure stages. The host observes network sockets, the stopped container's
filesystem/logs, process state, the tool subprocess, peer and final recipient.

Three native mutations enable host networking, writable filesystem or persistent
logging. Normal profile inspection must first reject each weakening. Only then
does the test disable that inspection and require the independent sink to detect
the resulting leak. No mutant is offered as a runnable production configuration.
The allowed final disclosure remains successful in these controls: a final
success cannot hide an earlier forbidden exit. No container remains running
when the composed run proceeds beyond this mediation adapter.

## Evidence and limits

`manifest.json` records sources, harness hashes, installed dependencies, command,
policy/trust descriptions and limitations. `observations.jsonl` records only
transaction IDs, stage outcomes, fixed exception classes, receipt counts and
expected oracle outcomes. It excludes payloads, model keys, raw reports and their
content digests. Test failures may print synthetic fixtures in `pytest.log`;
never replace these fixtures with confidential production material.

The portable profile has no agent isolation. The native profile establishes only
the listed agent egress controls with a trusted host, kernel, Docker daemon,
bridge, broker, model computation, tool and peer. It does not hide plaintext from
the operator or establish confinement of those other processes. The affine model
runs on the host before its output reaches the agent. The native suite does not
repeat every watchdog/bridge crash scenario from cMCP's separate lifecycle suite.
Attestation remains synthetic; no independently operated peer, hardware/GPU
execution, erasure or unrestricted leakage claim follows. Released-package
integration and controlled-host hardware acceptance remain open.
