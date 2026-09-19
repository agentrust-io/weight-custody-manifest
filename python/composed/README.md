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
python -m pip install -e './wcm/python[dev]' -e ./cmcp -e ./ca2a
python wcm/python/composed/run.py --cmcp-source cmcp --ca2a-source ca2a --output evidence
```

Use a fresh evidence directory. The runner rejects changed dependency revisions
and tracked edits, records the WCM revision/diff and harness hashes, and exports
installed package versions. Dependencies are recorded per run, not a complete
hash-locked environment. The hosted workflow repeats this command on native Linux.

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

Six test-only weakenings must expose delivery that the normal oracle forbids:
workload measurement appraisal, tool ceiling, response MAC, output commitment,
transaction check and replay consumption. They modify functions only within
pytest's monkeypatch scope; production source bytes are unchanged. Other refusal
cases are regression controls and do not yet have their own causal mutation.

## Evidence and limits

`manifest.json` records sources, harness hashes, installed dependencies, command,
policy/trust descriptions and limitations. `observations.jsonl` records only
transaction IDs, stage outcomes, fixed exception classes, receipt counts and
expected oracle outcomes. It excludes payloads, model keys, raw reports and their
content digests. Test failures may print synthetic fixtures in `pytest.log`;
never replace these fixtures with confidential production material.

There is no agent process confinement in this composition. Direct network or
filesystem bypass remains untested here; cMCP's separate confinement suite does
not automatically compose with these observations. Attestation is synthetic,
keys and model plaintext reside in ordinary host Python, peer evidence has no
hardware assurance, and no independent-operator/hardware/GPU/erasure claim follows.
Future work is a confined agent adapter, complete per-gate mutation coverage,
released-package packaging and the controlled-host live milestone.
