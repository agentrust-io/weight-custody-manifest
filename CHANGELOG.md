# Changelog

Notable changes to the Weight Custody Manifest specification and Python SDK.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/); the SDK
uses semantic-ish versioning while pre-1.0.

## 0.28.0 - 2026-09-01

**[security/packaging]** Removed internal infrastructure identifiers from two
test-fixture documents under `python/tests/fixtures/live-validation/`, and added
`tools/leak_scan.py` plus a `leak-scan` workflow that runs on every push, pull
request and published release.

The scan matches identifier *shapes* rather than a list of known-bad strings:
bare GUIDs, cloud resource names, X.509 `serialNumber` attributes, private-key
blocks and cloud access-key IDs. The control it replaces was a manual denylist of
named entities, which by construction could not match an identifier it had never
been told about, and which only ran when someone remembered to run it. Running in
CI also closes the gap that every previous control guarded the repository's
visibility, while a package index is reached by `twine upload` regardless of what
that visibility says.

The allowlist carries six documented exceptions, each with a reason. One is open
debt rather than a decision: `paired-2026-08-20/paired-release.json` is SHA-256
pinned by `tests/test_paired_hardware_receipt.py`, so editing it would break the
integrity pin that shows the receipt is the one the hardware produced. It carries
a classification label and no identifiers.

**[ci]** The public demos now run against the wheel the branch would actually
ship rather than an editable checkout, so a packaging regression fails before a
release instead of after one.

**[ci]** The leak scan matched its `ALLOWLIST` keys against native path strings,
so on Windows every exemption missed and a clean tree failed with eleven false
findings. CI is Linux and stayed green throughout. It now compares POSIX paths,
and `tests/test_leak_scan.py` pins the separator contract, the exemption
behaviour, and that no allowlist key has gone stale against the tree.


**[evidence/hardware]** Captured protected-runtime evidence on a real Azure
SEV-SNP confidential VM (`Standard_DC2ads_v5`, AMD EPYC 7763), closing the two
things issues #78 and #79 said a unit test could not settle.

The memory-fingerprint sweep ran over 256 MB of SEV-SNP-encrypted guest DRAM,
mlock'd so the region could not page out under the write pressure the sweep
creates, at 65536 pages rather than the 64 a unit test uses. The challenge nonce
was derived from a live vTPM attestation report read from NV index
`0x01400001`, so the sweep is bound to that guest rather than to an invented
string. Both negatives were exercised on the same hardware: a tampered readback
and a wrong verifying key are rejected.

The custody lease lapsed because time passed, not because a test called
`zeroize`, and the runtime then refused the next operation with `KeyWipedError`
on its own. The result is a five-record signed chain that verifies as terminal.

`tests/test_protected_runtime_receipt.py` re-runs the signature and chain
verification offline from the committed records rather than reading a boolean
the capture wrote, and re-checks the truncated, gapped and wrong-key negatives
here. The raw attestation report is deliberately not committed: it carries
platform identifiers, and only its digest is needed to show the binding.

None of this touches the guarantee scope. A sweep running inside the guest
cannot observe a DDR interposer outside it; TEE.fail and BadRAM are unaffected
and `SPEC.md` section 3.6 is unchanged. The receipt carries that caveat in its
own text.

## 0.27.0 - 2026-08-27

**[sdk]** Added `wcm.artifact_digest`, the deterministic content digest for a
model artifact on disk, named `wcm-artifact-digest/v1`. `SPEC.md` takes
`weights_hash` as given and says nothing about how a directory of shards,
indexes and tokenizer assets collapses into one value, so every consumer
invented it: the same construction already existed in three places outside this
repository with nothing keeping them in step. A recipe that exists several times
does not stay one recipe, and when the copies drift the mismatch presents as
`weights_hash` not matching, which reads as tampered weights.

This is a convention rather than specification, and `RECIPE_ID` says so: a
deployment computing `weights_hash` another way is not non-conforming, it simply
must not expect this function to agree. Symlinks are refused by default, which
the prior copies did not do, because following one lets a digest cover bytes
outside the artifact and lets those bytes change without anything in the
artifact changing.


**[hardware/azure]** Corrected Azure vTPM measured-launch verification against
real `Standard_DC2as_v5` hardware. TPM quote `pcrDigest` is the SHA-256 of the
selected PCR values, so the single-PCR policy requires a second hash over PCR
23's reset-and-extend value. Added a sanitized, reproducible capture tool.

**[compatibility/azure]** Kept the positive-serial certificate policy as the
default while allowing Azure's THIM-provided AMD VCEK leaf through an explicit,
provider-local compatibility path. Other provider certificates still fail
closed on non-positive serial numbers.

**[security/kbs]** Key release now requires the complete authority-layer manifest
identity to be pinned out of band. Without it a caller could present an
attacker-authored policy that reused a weights hash the broker already held, and
be released against terms nobody agreed. Servers built from the environment must
load explicit trusted manifest identities, and the gate is carried into signed
renewal decisions rather than being a release-time check a renewal could route
around. (#98)

**[sdk/runtime]** Added `wcm.runtime_records`: Ed25519-signed, hash-chained
custody records with contiguous sequence enforcement, so a protected runtime can
produce a portable receipt for its own lease lifecycle rather than a log line
anybody could write. `RuntimeEvent` covers lease start, renewal, lapse,
revocation, wipe request, wipe completion and process termination. (#94)

**[sdk/runtime]** Added `wcm.memory_sweep`: a signed protected-memory sweep that
writes unpredictable nonce-derived data across every page of a declared range and
reads them back in a distinct nonce-derived order, so a controlled alias mapping
of the kind a BadRAM-class attack produces is detectable. The algorithm is
implemented and tested; protected-boundary hardware evidence remains open
(issue #79), and `LIMITATIONS.md` is unchanged on that point. (#95)

**[hardware/azure]** The Azure provider now resets application-owned PCR 23 and
extends it exactly once with the canonical manifest-approved SHA-256
serving-image digest before each release attempt, closing the repository-side
half of measured launch. (#93)

**[security/attestation]** Bound the Azure vTPM SHA-256 PCR 23 value to the
manifest-approved workload measurement, with coverage for wrong state, wrong
measurement, malformed digest and absent policy. Defined a deterministic
fail-closed RFC 5280 policy for non-positive certificate serial numbers; CI
exercises both cryptography 50's real warning path and a simulated cryptography
51 load-time exception, and the runtime dependency stays capped below the
unreleased 51. (#92)

**[packaging]** Every project URL on PyPI now resolves for an anonymous reader.
0.26.0 shipped four links that 404 while this repository is private, which PyPI
renders as live regardless. (#100)

**[tests]** TDX missing-device coverage no longer depends on the host running the
suite, so the fail-closed assertion still holds on a machine with real Intel TDX
hardware. (#102)

## 0.26.0 - 2026-08-21

**[security/sdk]** Added `EnclaveSession.authorize_operation()` for long-lived
confidential runtimes to enforce the existing lease and operation budget without
exporting another key copy on every inference. `use_key()` now delegates to the
same authorization path, preserving its existing operation-count semantics.

**[security/renewal]** Added short-lived signed KBS renewal decisions. The
initial release pins the renewal signer; a fresh decision binds the model,
signed manifest, consumed challenge, complete evidence, gate results, and
validity window without returning a model key. `EnclaveSession.apply_renewal()`
verifies and consumes the decision once before resetting cadence and operation
budgets.

**[hardware/validation]** Added a sanitized paired CPU/GPU validation record and
reproducible release runner covering Azure SEV-SNP/vTPM and NVIDIA H100 evidence.
The record is portable and offline-verifiable; it does not include provider
tokens or raw attestation secrets.

**[security/verification]** Bound Azure vTPM provider selection and paired
hardware receipts to the validated evidence path, with negative coverage for
changed workload state, substituted transport, and missing GPU evidence.

**[release]** Added the guarded public-release preflight, public launch checklist,
reproducible release BOM tooling, current package metadata, and refreshed KBS
dependency locks.

## 0.25.0 - 2026-08-12

**[security/kbs]** The environment-built network KBS now fails closed when a
cryptographic CPU quote verifier/trust root is not configured. Health and
challenge issuance remain available, but release cannot silently downgrade to
structural CPU evidence. A private GCP boundary validation caught the gap and
confirmed replay, transport-key substitution, and unapproved-image refusal after
the fix.

**[hardware/sdk]** Added live-derived Linux SEV-SNP and TDX provider fixes,
fail-closed NVIDIA NVAT evidence adaptation, and Azure SNP→HCL runtime→HCL
attestation-key→fresh vTPM quote verification with nonce/transport binding.

**[operations]** Added read-only partner-node preflight, unified happy/negative
readiness receipts, and a single fail-closed final-launch command with evidence
redaction, JSON validation, deterministic inventory hashing, and explicit
hardware-claim boundaries.

**[security/sdk]** Raised the runtime `cryptography` floor to `50.0`, excluding
the vulnerable 49.x releases reported by `pip-audit` while retaining the
existing upper bound for the current major-version compatibility contract.

**[security/ci]** Pinned every GitHub Actions dependency, including the PyPI
trusted-publishing action, to an immutable commit. This prevents a mutable tag
from changing the code executed by the release or documentation deployment
workflow without a reviewable repository change.

**[spec/sdk]** Normative manifest **JSON Schema, frozen at v1**
(`schema/wcm-manifest-v1.schema.json`, `$id`
`https://wcm.agentrust-io.com/schema/manifest/v1.json`). Until now the manifest
existed only as prose in SPEC.md §3.1 plus the Pydantic reference model, so a
third-party implementer had nothing machine-readable to validate against. The
structural half is generated from the model (`python/tools/gen_schema.py`, with a
`--check` mode CI runs, so the committed file cannot drift); the four cross-field
rules the model enforces in validators are hand-carried as `if`/`then` blocks.
Ships inside the wheel, so `wcm.schema.manifest_schema()` works from an installed
package. Adds a shared vector corpus at `conformance/vectors/manifest/` (24
language-neutral accept/reject cases) that `tests/test_schema.py` runs against
both the schema and the model, asserting they agree.

Frozen means additive-only: fields and enum values may be added, but nothing is
removed, renamed, made required, narrowed, or repurposed inside v1, and a
breaking change would publish `.../manifest/v2.json` alongside rather than edit
v1. That is a deliberate trade, since the spec itself is still pre-1.0: an
implementer gets a stable target now, and anything the spec grows into arrives as
an addition. `manifest_version` stays unconstrained; it versions the manifest
instance under the issuing builder's scheme, not the schema.

**Honest gap, documented not papered over:** one model constraint,
`derived_from != weights_hash`, is not expressible in standard JSON Schema, which
cannot compare the values at two instance locations. It stays a verifier-side
check. It is recorded in `schema/README.md`, carried as a negative vector marked
`schema_expressible: false`, and asserted directly in the tests, so a
schema-only implementation cannot pass by delegating everything to the schema and
removing the model validator cannot make the parity test go quietly green. No new
runtime dependency: `wcm.schema` returns the schema document and leaves
validation to the caller (`jsonschema` is a dev-only test dependency).

**[build]** The reference KBS image is now **bit-for-bit reproducible, and CI
tests it** rather than documenting it as an operator step. `kbs_image.measurement`
is only worth pinning in a manifest if an independent party can arrive at the same
value, and until now the Dockerfile took the base image by tag and pinned only
direct dependencies, so it could not.

- **Base image pinned by digest** (`BASE_DIGEST`), with a new Dependabot `docker`
  ecosystem entry to move it, since a digest pin does not pick up security updates
  on its own.
- **Fully hash-locked dependencies.** `docker/constraints.txt` (3 direct pins) is
  replaced by `docker/requirements.lock` (22 pins, the full transitive closure)
  and `docker/requirements-build.lock`, both installed with
  `pip --require-hashes`. Each pin lists *every* artifact PyPI publishes for that
  version, so the lock is not tied to one wheel tag. Regenerate with
  `python tools/gen_kbs_lock.py` (`--check` for staleness), which resolves for the
  image's platform rather than the host's, and from `pyproject.toml`'s own declared
  requirements, so a pin cannot violate what the package says it supports.
- **No unpinned fetch anywhere in the build.** The wheel is built in a discarded
  builder stage with `--no-build-isolation` against the locked build set, then
  installed `--no-deps --no-index`. CI asserts `import hatchling` fails in the
  runtime image.
- **mtimes normalized to `SOURCE_DATE_EPOCH`** inside each layer that writes
  files, because pip and hatchling stamp build time into what they write. Scoped
  to the paths the build touches; a blanket `find /` would copy every base-image
  file up into the final layer.
- **`pip --no-compile`.** pip byte-compiles by default and a `.pyc` embeds the
  source mtime, so normalizing mtimes afterwards leaves bytecode holding the old
  value: reproducible-looking sources over irreproducible bytecode.
  `PYTHONDONTWRITEBYTECODE` does not cover it, since it governs the interpreter
  rather than pip's compile pass.
- **`docker/verify-reproducible.sh`**, run by CI and runnable locally: builds
  twice (the second with `--no-cache`) and compares the two images' **exported
  filesystem content**, every entry's type, permissions and path plus a sha256 of
  every regular file, then prints a stable content digest. Content rather than
  layer digests, because BuildKit stamps a build-time mtime onto the destination
  directory entry a `COPY` creates, which no in-image normalization can reach, so
  layer comparison fails on metadata noise that says nothing about what the image
  contains. Verified: two independent builds produce byte-identical content across
  5,948 files.

**Scope stated precisely** in `python/docs/reproducible-kbs-image.md`: this proves
the build does not depend on when it ran, on cached layers, or on what a resolver
would have picked that day. All three of those actually broke the check while it
was being written, which is the argument for having it. It does **not** prove
cross-machine reproducibility, since both builds share one runner, one Docker
version, and one checkout. The honest claim is reproducible under a fixed builder
with every content input pinned; verifying across independent builders belongs to
whoever certifies a deployment.

**[spec/sdk]** **Conformance suite** (`conformance/`) so an independent
implementation can be checked against the same inputs the reference is, in any
language. Four levels matching the four layers, `WCM-*` error codes
(`conformance/codes.md`), 91 language-neutral JSON vectors, and a runner exposed
as `wcm conformance` that both self-tests this SDK and scores another
implementation's results file. Ships in the wheel, so it works from
`pip install weight-custody-manifest`.

Three rules make a pass mean something: every valid input must be accepted (an
over-strict implementation fails too), every invalid one must be rejected **for
the declared code** (so "reject everything" cannot pass), and a vector with no
reported result counts as a failure (so a partial submission cannot claim a
level). All three are tested directly, with deliberate cheating attempts.

**All four levels are vectored, 91 vectors.** L1 (manifest and joint signature,
32) and L4 (derivative lineage, 10) ask questions about documents. L2
(attestation-gated release, 37) and L3 (runtime custody, 12) ask what a system does
over *time*, so their vectors are ordered **scenarios**: the clock is supplied by
the vector and moves only on an explicit `advance_clock` step, and nonces are
generated by the implementation and bound to names that later steps reference, since
a nonce must be unpredictable and cannot be hardcoded. That keeps a scenario
meaning the same thing in any language, and keeps "the lease lapsed" a fact about
the vector rather than about how long the test took to run.

L2 covers the policy gate in full: nonce freshness and single use (including that a
*failed* attempt still spends its nonce, or one challenge buys unlimited tries),
platform, assurance tier, serving-image status with prefer-current and
past-`retire_after`, composite CPU-to-GPU nonce binding and RIM match,
memory-fingerprint presence and binding and aliasing detection, attestation-key
revocation and cache freshness, channel binding including that a channel-bound
release returns the key **sealed**, and key availability. L3 covers the wipe-on-lapse
floor, and specifically the distinction implementations get wrong: an exhausted
operation budget requires re-attestation and the key **survives**, while a lapsed
wall-clock lease **zeroizes** it. Wiping on the former is needlessly destructive;
suspending on the latter is not a wipe at all.

L2 also covers **cryptographic quote verification**: the certificate chain reaching
a pinned trusted root, the report signature under the leaf key, an expired leaf
refused, `REPORT_DATA` binding the presented nonce, and, under channel binding,
binding `sha256(nonce || transport_key)` so a **relay substituting its own transport
key is detected** (CVE-2026-33697). A configured verifier is also shown not to fall
back to structural trust when the evidence carries no raw quote, which would turn it
into a no-op.

Those vectors carry a **recipe** rather than a finished quote, because `REPORT_DATA`
must bind a nonce that is generated at scenario time (it has to be unpredictable), so
a pre-baked quote could only ever demonstrate a mismatch. The vector supplies the
chain, a committed test signing key, and a description of what `REPORT_DATA` should
bind; the implementation assembles and signs the report. The container is the
documented `JsonQuoteParser` shape, so nothing about it is Python-specific.

**Every reportable error code is now exercised by at least one vector**, enforced by
a test, and `NOT_YET_VECTORED_CODES` is empty. That is exactly when a green run gets
over-read, so two limits are stated in `COVERAGE_NOTES` and printed by
`wcm conformance` on every full run: the quote vectors use a **synthetic PKI rather
than vendor roots**, so they do not establish that an implementation can parse a real
AMD, Intel or NVIDIA quote (the SDK covers that with committed real-silicon
fixtures); and **GPU-side cryptographic verification is not vectored**, the NVIDIA
device chain being covered by the SDK's H100 fixture instead. `WCM-L3-0003` and
`WCM-L3-0004` stay marked diagnostic-only, since nothing raises them; the suite
concludes them when a step that should have succeeded did not. A test asserts that
marker list does not grow, so "add it to the exempt set" cannot become the way a
failing code disappears.

**[fix]** `retire_after` without a timezone offset crashed the release gate.
`_check_serving_image` parsed the value with `datetime.fromisoformat` and compared
it against a timezone-aware clock, so a naive timestamp raised `TypeError` out of
`verify_and_release` and aborted the whole release path. The value arrives in a
manifest, so it cannot be assumed well formed. A naive value is now read as UTC, an
explicit offset is honoured rather than overwritten, and an unparseable one fails
closed with a clear reason: a deadline you cannot read is not a deadline that has
not passed. Found by the new L2 vectors, and covered by both a vector pair and
direct unit tests.

Three interop details surfaced while building the vectors, all now stated as
requirements rather than left as traps: an implementation must **materialize
schema defaults before computing the signing pre-image** (the verifier
canonicalizes the parsed manifest, so canonicalizing the raw document as received
yields a different pre-image and rejects valid signatures), and the
self-derivation check must live **outside** the JSON Schema, so an implementation
that delegates all structural validation to the schema fails
`reject-self-derivation`. The third is the `retire_after` parsing above: a manifest
field that reaches a comparison must be parsed defensively, because a crash in the
release path is worse than a denial.

Also: `python/docker/Dockerfile` now copies the repo-root `schema/` and
`conformance/` into the build context, which the wheel build force-includes, and
the KBS image should carry the schema it validates against anyway. `docs/` gains a
schema-and-conformance page, and `docs/spec-overview.md` was corrected from v0.13
to the current v0.15.

**[docs]** Synced the README `Status` section to the v0.12 publication posture. It
still said publication was gated on the key-extraction half of open question 8.8,
which v0.12 explicitly reversed and which `SPEC.md` §3.6, `ROADMAP.md`, `CHARTER.md`,
`CONTRIBUTING.md`, `SECURITY.md`, `ADOPTERS.md` and the `docs/` site had all already
corrected. The README was the only file left claiming the document was being withheld.
No change to the spec or to any security claim.

**[repo]** Moved the runnable examples and demos out of this repo into the public
[agentrust-io/examples](https://github.com/agentrust-io/examples/tree/main/weight-custody-manifest)
(per-product catalog) and [agentrust-io/demos](https://github.com/agentrust-io/demos)
(talk track), where they depend on the published `weight-custody-manifest` PyPI
package rather than an in-repo checkout. The SDK keeps `examples/manifest.example.json`
as a CLI docs fixture. The demo notes below describe those examples as originally
added here.

**[demo]** Run WCM on a real open model, locally (`examples/real_open_model.py`):
downloads a real open-weight model (default SmolLM2-135M), hashes its ACTUAL
safetensors into the manifest, and runs the whole flow (sign, gate, wipe-on-lapse,
license, derivative + lineage) with the software attestation mock. Includes a
tamper demo (a one-byte-flipped fork no longer matches the manifest) and an
optional `--infer` that loads the model and generates so the certified serving
stack is a real running model. Adds a "Test on your machine" tutorial. No library
change; download/inference deps are imported lazily and CI does not download.

**[demo/tools]** Offline SEV-SNP quote replay: `examples/snp_replay.py` runs the
KBS's Layer 2 CPU gate (parse, VCEK->ASK->ARK chain, report signature, nonce
binding) against a recorded quote, with a committed synthetic bundle so it runs
anywhere. `tools/capture_snp_quote.py` captures a genuine bundle on an Azure
SEV-SNP CVM; the replay handles both the guest-nonce (bare-metal) and the Azure
vTPM freshness topologies honestly (on Azure, REPORT_DATA binds the vTPM AK, not
our nonce). Ships a **genuine** quote captured from a live Azure SEV-SNP CVM
(`tests/fixtures/snp_quote_azure.json`, real VCEK->ASK->ARK) that the replay
verifies offline, alongside the synthetic one. Adds a "Replaying a real SEV-SNP
quote" tutorial and wires the tutorials into the docs nav. No library API change.

**[demo]** Sovereign self-custody with threshold release
(`examples/sovereign_self_custody.py`, SPEC 3.5 / decision 15): a 2-of-3 split
across builder, sovereign, and custodian, gated by an attested KBS, showing that
no single party (and no single forged KBS quote) can assemble the key, so
threshold is a prerequisite for sovereign self-custody, not optional hardening.
Composes the shipped `split_secret`/`combine_shares` with `KeyBrokerService`; no
new library API. Adds a "Sovereign self-custody (threshold)" tutorial.

## SDK

### 0.24.1
- **Packaging fix; 0.24.0 was never published.** `python -m build` builds the sdist,
  unpacks it, and builds the wheel from that, and in an unpacked sdist
  `pyproject.toml` sits at the sdist root (PEP 517 requires it there), so the static
  `../schema` and `../conformance/vectors` force-includes pointed outside it and the
  build raised `FileNotFoundError`. `pip install <sdist>` would have failed for
  anyone, not only the release job. Resolved by a build hook
  (`python/hatch_build.py`) that finds the artifacts at build time: at the repo root
  from a source tree, beside `pyproject.toml` from an unpacked sdist.
- **The regression test that should have existed.** Nothing before a Release ran
  `python -m build`: `publish.yml` only fires on a Release, and every other job
  installs editable or invokes hatchling directly, neither of which goes through the
  sdist round-trip. The `python` workflow now has a `packaging` job that builds the
  way the release does, runs `twine check`, then installs **from the sdist** into a
  fresh venv and runs the shipped conformance suite, proving the packaged schema and
  vectors are reachable from an installed package.
- No library changes. Everything listed under 0.24.0 ships here.

### 0.24.0

> Tagged but **never published to PyPI**: the release build failed on the packaging
> bug fixed in 0.24.1. Install 0.24.1 for everything below.

- **Normative manifest JSON Schema, frozen at v1** (`schema/`, `$id`
  `https://wcm.agentrust-io.com/schema/manifest/v1.json`). Generated from the
  reference model and augmented with the cross-field rules Pydantic does not
  export; `wcm.schema.manifest_schema()` reads it from the installed wheel.
  Additive-only from here. One constraint (`derived_from` != `weights_hash`) is not
  expressible in JSON Schema and stays verifier-side, documented rather than
  glossed.
- **Conformance suite** (`conformance/`, `wcm conformance`): 91 language-neutral
  vectors across all four levels, a `WCM-*` error-code registry, and a scoring
  contract for other implementations. L1 and L4 over documents; L2 (the release
  gate, policy *and* cryptographic quote verification) and L3 (runtime custody) as
  time-ordered scenarios with an injected clock. Every reportable code is exercised
  by a vector; the two remaining limits are printed on every run.
- **`retire_after` parsing fixed** (`kbs.py`): a value without a timezone offset
  raised `TypeError` out of `verify_and_release` and aborted the release path. Naive
  is now read as UTC, an explicit offset is honoured, and an unparseable value fails
  closed. Found by the new L2 vectors.
- **Bit-for-bit reproducible KBS image**: base pinned by digest, 22 hash-locked
  dependencies replacing 3 direct pins, no unpinned network fetch in the build,
  normalized mtimes, `pip --no-compile`, and `docker/verify-reproducible.sh` which
  CI runs to compare two builds' filesystem content.
- No breaking API changes. New modules `wcm.schema` and `wcm.conformance`; new CLI
  verb `wcm conformance`; new dev-only dependency `jsonschema`.

### 0.23.0
- **CLI reaches the whole protocol.** `wcm` gained four verbs beyond
  keygen/sign/verify: `wcm inspect` (summarize a manifest's fields and release
  policy), `wcm gate` (a release-policy diagnostic using a mock software
  attestation, prints every gate check and the release verdict, for authoring
  and debugging a policy), `wcm verify-quote --kind {snp,tdx,gpu}` (verify a
  captured SEV-SNP / TDX / NVIDIA H100 CC quote bundle, pinning the vendor root
  by fingerprint where the root travels in the evidence), and `wcm verify-provenance`
  (cross-verify an OpenSSF model-signing signature against the manifest; needs
  the `[model-signing]` extra). No library changes; the CLI wires up the existing
  `snp`/`tdx`/`nvidia`/`kbs`/`provenance` machinery.

### 0.22.1
- **Packaging:** repoint the PyPI project URLs (Homepage / Documentation) to
  public, live surfaces (the runnable examples catalog) while the spec/SDK repo
  is private and Pages is not served, so the PyPI page has no dead links. No code
  change. Restore to the repo + docs site when it goes public.

### 0.22.0
- **NVIDIA H100 GPU CC verification validated on real silicon.** `wcm.nvidia` is
  rewritten around the real on-wire format, confirmed against a live
  `Standard_NCC40ads_H100_v5` attestation (cross-checked with NVIDIA's own local
  verifier) and committed as a fixture: the report echoes the RAW 32-byte nonce
  at offset 4 (not `sha256(nonce)` like the CPU SEV-SNP / TDX path), the signature
  is the last 96 bytes (ECDSA P-384 raw `r||s` over `report[:-96]`, SHA-384) by
  the leaf key, and the device cert chain roots in the self-signed NVIDIA Device
  Identity CA. New `NvidiaGpuVerifier` / `build_gpu_verifier` verify the cert
  chain to the pinned NVIDIA root, the report signature, and the raw-nonce
  binding; `parse_gpu_report` + `verify_gpu_report_signature` are the primitives.
  `KeyBrokerService`'s `gpu_report_verifier` now takes this verifier, with the GPU
  evidence bundling the report plus its device cert chain in `GpuReport.quote_b64`
  (no manifest-schema change). This replaces the 0.20.0 PROVISIONAL placeholder
  (which reused the generic `QuoteVerifier` and the CPU sha256-nonce / DER-signature
  conventions that do not fit NVIDIA). WCM ships only the public NVIDIA device
  root. Completes the real-silicon matrix: SEV-SNP + TDX + H100 CC.

### 0.21.0
- **OpenSSF model-signing provenance interop** (SPEC 3.9): a manifest can carry an
  optional, signed `provenance.model_signing` reference to an OpenSSF model-signing
  signature over the base weights (`Provenance` / `ModelSigningProvenance`, added to
  `WCM_SIGNED_FIELDS`). `verify_manifest` records it as a non-blocking note; new
  `verify_provenance(manifest, model_path, signature_path, public_key)` (module
  `wcm.provenance`) cryptographically verifies the model-signing signature over the
  model files and binds it to the manifest by re-deriving `signed_digest`
  (`model_signing_digest`). Positions WCM as the custody-and-release layer on top of
  model signing, not a competitor. `model-signing` is an optional dependency
  (`pip install "weight-custody-manifest[model-signing]"`). Backward-compatible: the
  field defaults absent, so existing manifests and pre-images are unchanged.

### 0.20.0
- **NVIDIA CC GPU-report verification** (SPEC 3.2 composite attestation): new
  `wcm.nvidia` (`build_gpu_verifier`, `NvidiaCcReportParser`) verifies the H100
  CC GPU report with the same machinery as the CPU quote (cert chain to NVIDIA's
  device root, report signature, nonce binding), reusing `QuoteVerifier`.
  `KeyBrokerService` gains `gpu_report_verifier`: when set, a new
  `gpu_report_verified` gate cryptographically checks the GPU chain; when unset
  it stays structural-only and says so, so default behaviour is unchanged. The
  GPU report is bound to the CPU quote by the shared KBS nonce. Honest scope: it
  ships no NVIDIA root, and the binary SPDM report offsets are PROVISIONAL until
  validated against a real H100 capture (`NCC40ads_H100_v5`); the reused
  verification machinery is tested against a synthetic device PKI.
  Backward-compatible.

### 0.19.0
- **Channel binding for Layer 2 key release** (SPEC 3.2, CVE-2026-33697): closes
  the quote-relay / key-diversion gap that nonce binding alone left open. New
  `wcm._seal` (`generate_transport_keypair`, `seal_to_public_key`, `open_sealed`,
  `SealError`) object-seals a released key to the enclave's attested transport key
  (ephemeral-static X25519 + HKDF-SHA256 + ChaCha20-Poly1305, stdlib crypto, no
  new dependency), mirroring cA2A's sealed-channel scheme. `CpuQuote` gains
  `transport_public_key`; providers fold it into REPORT_DATA under the nonce
  (`sha256(nonce || transport_pubkey)`), so a relay cannot substitute its own key
  without failing verification. `QuoteVerifier.verify` and `verify_tdx_quote` take
  a `channel_binding` kwarg; `KeyBrokerService` takes `require_channel_binding`
  (default False) and adds a `channel_binding` gate check, and `ReleaseDecision`
  gains `sealed_key`. When channel binding is required the raw key is never
  returned, only the sealed blob, so a relayed release yields ciphertext the relay
  cannot open. The reference server (`wcm.server`) now requires channel binding
  and returns `sealed_key_b64` instead of a plaintext key. Backward-compatible:
  `channel_binding` defaults empty (reduces to `sha256(nonce)`) and
  `require_channel_binding` defaults off, so existing evidence and flows are
  unchanged.

### 0.18.0
- **Multi-stage BYOM enforcement in `verify_lineage`** (SPEC 3.8): monotone rights
  (a derivative may narrow but never widen the structured `derivatives` policy or
  `permitted_environments` relative to its parent), plus optional `logged=` (every
  manifest in the chain must be present and in-force in the transparency log) and
  `revoked=` (a revocation anywhere in the chain cascades to invalidate the leaf)
  gates. `verify_lineage` stays pure, no crypto: the caller supplies the
  logged/revoked hash sets from already-verified inclusion proofs. Backward-
  compatible, the gates default off; monotone-rights is always on (structural).

### 0.17.0
- **Azure Intel TDX provider** (`AzureTdxVtpmProvider`): Azure TDX CVMs have no
  `/dev/tdx-guest`; the paravisor exposes a TD report in the same vTPM NV index
  SNP uses (`0x01400001`), and since a TD report is not self-verifiable this
  provider exchanges it for a DCAP quote at the Azure IMDS `/acc/tdquote` service.
  Validated on a live Azure `DCes_v6` host in westeurope; the captured quote
  (`tests/fixtures/tdx_quote_azure.json`) verifies through `tdx.py` and chains to
  Intel's real SGX Root CA. `select_cpu_provider` prefers it over the Azure SNP
  catch-all by reading the HCL's TD-report type byte.
- **`verify_tdx_quote(expected_nonce=...)` is now optional.** Pass `None` on the
  Azure vTPM path, where REPORT_DATA is paravisor-bound to the vTPM AK rather than
  a caller nonce (freshness comes from the enclosing vTPM quote); bare-metal /
  configfs-tsm guests still pass the nonce.

### 0.16.0
- **Intel TDX quote verification** (`tdx.py`): `parse_tdx_quote` and
  `verify_tdx_quote` for the DCAP v4 ECDSA quote. The two-level Intel structure
  (attestation key signs the quote; the QE report binds that key; the PCK leaf
  signs the QE report; PCK chains to the Intel SGX Root CA) plus the nonce
  binding, so TDX reaches SEV-SNP parity on the verify side. Exercised against a
  synthetic DCAP quote AND a genuine GCP c3-standard-4 TDX capture
  (`tests/fixtures/tdx_quote_gcp.json`), which verifies offline and chains to
  Intel's real published SGX Root CA (fingerprint pinned in the test).

### 0.15.0
- **Explicit `base_confidentiality`** (`confidential` | `gated-open` | `open`)
  and **`deployment_model`** (`builder-to-customer` | `byom-symmetric`) on the
  manifest, both under the joint signature (added to `WCM_SIGNED_FIELDS`). A
  manifest that omits them reads as the original confidential, builder-to-customer
  posture, so this is backward-compatible for parsing.
- `verify_manifest` now returns non-blocking `notes`: it discloses that an `open`
  base is not protected for secrecy (the layers still enforce integrity, license,
  derivative custody, and the kill switch), flags secrecy-only controls on an open
  base, and confirms symmetric self-custody. `notes` never change `ok`.
- `byom-symmetric` structurally requires `customer-self-custody`.
- **Spec**: SPEC.md v0.10 documents both fields and reframes BYOM from
  "out of scope" to a named posture (multi-stage pipeline stays out of scope).

### 0.11.x
- **RFC 8785 conformance fix**: canonicalizer sorts object keys by UTF-16 code
  units (not code points), so the interop claim holds for non-BMP keys.
- **AMD SEV-SNP quote verification** (`snp.py`): real v3 report parser, VCEK
  report-signature verification, Azure vTPM HCL extraction, and `SnpQuoteParser`.
  Validated against a live Azure SEV-SNP report and the real AMD Milan chain.
- **RSA-PSS cert-chain fix** (`_quote_verify`): honor each cert's own signature
  parameters - found by validating against real AMD VCEK/ASK/ARK certificates.
- Parser fuzzing and a threat-model → implementation audit.

### 0.10.0
- **Post-quantum profile**: ML-DSA-65 (FIPS 204, via cryptography's native
  support) and an Ed25519 + ML-DSA-65 hybrid; `verify_manifest` dispatches per
  signature by algorithm.

### 0.7.0 – 0.9.0
- **Layer 4 derivative lineage** (`derived_from` / `rights_holder`, structured
  `derivatives` policy); **transparency log** (RFC 9162 Merkle, signed tree
  heads, inclusion/consistency proofs); **threshold split-key** (Shamir/GF(256)).

### 0.2.0 – 0.6.0
- **Layer 2 attestation-gated release gate** (composite CPU+GPU verification,
  single-use nonces); **wipe-on-lapse custody** with trusted-time honesty and
  operation-count renewal; hardware provider scaffolding; quote-verification
  machinery (X.509 chain + report signature + nonce binding).

### 0.1.0
- **Layer 1 reference SDK**: manifest Pydantic model, RFC 8785 canonicalization,
  Ed25519 joint (builder + custodian) signing and verification, `wcm` CLI.

## Specification

- **v0.15** - records that the reference SDK's NVIDIA H100 GPU CC verification is
  now validated against a real confidential-compute attestation captured on live
  silicon (device cert chain to the NVIDIA Device Identity CA, ECDSA-P384/SHA384
  report signature, raw-nonce binding). A maturity/assurance note; no normative
  protocol change.
- **v0.14** - added provenance interop (section 3.9): an optional `provenance`
  field, under the joint signature, references an OpenSSF model-signing signature
  over the base weights, and `verify_provenance` cryptographically checks that
  signature and binds it to the manifest by re-deriving the signed digest. WCM
  composes with model signing (the provenance layer) rather than replacing it, and
  does not re-sign the model files. No change to release, attestation, or custody
  semantics.
- **v0.13** - added channel binding to the Layer 2 release handshake (section
  3.2). The enclave folds a transport public key into the quote's REPORT_DATA
  under the nonce, and the KBS seals the released key to that transport key rather
  than returning it on the channel. Closes the quote-relay / key-diversion gap
  (the intra-handshake binding gap, CVE-2026-33697) that nonce binding alone left
  open: a relayed quote yields only ciphertext the relay cannot open, and
  substituting a transport key breaks quote verification. New threat T4.4 in the
  threat model (v0.5). No new manifest fields.
- **v0.12** - reframed the publication posture: closing the key-extraction half
  of open question 8.8 is no longer a precondition for publishing the open spec
  and SDK. That half is disclosed as a scoped limit against a hardware owner
  outside the operator-trust model (a party a builder self-selects against),
  addressed by physical hardening + accountability today and extraction-resistant
  silicon on the vendor roadmap. Security claims unchanged; only the "therefore
  withhold" logic is dropped, in favour of leading with the limit.
- **v0.11** - specified the KBS enclave image contents and threat model to
  implementable detail (resolving open question 8.2, so self-custody moves from
  described to specified), and added multi-stage BYOM as a sequential re-custody
  protocol over the existing lineage and transparency-log primitives (section
  3.8: chained `derived_from`, release gated on upstream being logged, monotone
  rights, cascading revocation). No new manifest fields; broad multi-party
  co-governance stays the one deliberately-open BYOM piece.
- **v0.10** - `base_confidentiality` (`confidential` | `gated-open` | `open`) and
  `deployment_model` (`builder-to-customer` | `byom-symmetric`) added to the
  manifest, both under the joint signature; the verifier reports non-blocking
  consistency notes rather than blocking.
- **v0.9** - Layer 4 fields (`derived_from`, `rights_holder`, structured
  `derivatives`) synced into the manifest examples.
- **v0.8** - resolved trusted time (`trusted_time_source`, three tiers) and split
  forged attestation into a closed half (measurement forgery →
  `memory_fingerprint_challenge`) and the honestly-open key-extraction half.
- **v0.7** - resolved standards home (SCITT + CoSAI), the profile-list `required_hw_platform`, and sovereign dual-protection framing.
- **v0.6** - external-panel corrections: hypervisor ciphertext side channel,
  trusted-time requirement, transparency log, cryptographic-custody vs
  accountability-grade distinction.
- **v0.1 – v0.5** - initial four-layer design, wipe-on-lapse, sovereign
  revocation profile, attested-KBS self-custody, confidential-GPU and CPU-CVM
  assessments, open-core model.
