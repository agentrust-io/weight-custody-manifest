# Platform-integrity evidence mapping for issue #121

Status: informative research for [#121](https://github.com/agentrust-io/weight-custody-manifest/issues/121), reviewed against WCM commit `9153f39b5dfba13217dd809fe326b63e4b9fdef0` on 20 October 2026. This note proposes no schema, verifier, or release-policy change. No hardware experiment was performed.

## Existing gate

The [release policy](../../SPEC.md) expresses `alias_check_complete` and `ciphertext_hiding`. The [KBS gate](../src/wcm/kbs.py) reads these from the authenticated SNP report retained by [quote verification](../src/wcm/_quote_verify.py). A required property on another CPU platform currently denies release. An absent authenticated report, an older report without the alias bit, and a clear bit also deny release, with different reasons. Denial does not establish that the physical property is false: evidence can be unsupported or unavailable.

## What the primary sources establish

| Evidence | Authenticated statement or documented facility | Remaining appraisal work |
| --- | --- | --- |
| SNP guest attestation report | WCM consumes guest `PLATFORM_INFO` bits 5 and 4. AMD's alias bulletin identifies bit 5 as the guest report's alias-check completion indicator. | Verify report version, signature, freshness and exact guest-field interpretation. Host platform-status fields are a different structure and cannot substitute. |
| Intel Platform Ownership Endorsements | A signed endorsement associates a platform identity with an endorsed owner. The relying party independently decides whether to trust that owner. | Ownership and an owner's physical-security responsibility do not measure a completed alias check or enabled ciphertext hiding. No bit-equivalent mapping is established here. |
| IBM `pvattest` | The documented additional-data options include firmware state and secret-store hash, covered by the attestation measurement. | A profile needs the relevant machine/firmware version, exact encoding and reference values. These measurements do not by themselves establish SNP property equivalence. |
| Arm CCA token draft -04, section 4.5.3 | Platform Config can describe implementation options including memory protection levels: encryption, integrity and anti-replay capabilities. Its byte-string encoding is implementation-defined. | Obtain the vendor's implementation profile and reference values, then bind decoding to the authenticated implementation identity. Capability names alone do not establish equivalent threats, coverage or activation semantics. |

The Arm finding prevents a blanket claim that CCA provides no platform-property evidence. It does not justify accepting an arbitrary Platform Config blob. Memory anti-replay capability is also distinct from freshness of the attestation token itself.

## Proposed evidence packet and acceptance pairs

A future mapping can be reviewed one platform/profile at a time. Its packet would identify the exact vendor specification/version, authenticated claim path, verifier trust roots, implementation identity, decoder, reference values, threat coverage and evidence freshness. It would retain original evidence and independently reproducible appraisal inputs. Report failures separately as authenticated negative, unsupported interpretation, missing evidence or verification failure, even where all prevent release.

The following are planned review pairs, not executed tests or a new release contract. Semantic negatives need separately authenticated evidence that reaches appraisal: flipping a signed report bit without re-authentication only tests signature failure. Synthetic fixtures injected at the verified-report gate can test its branching, but do not count as captured vendor evidence or hardware validation.

| ID | Valid control | Perturbation and expected distinction |
| --- | --- | --- |
| PI-01 | Authenticated SNP report satisfies both configured properties. | Use separately authenticated reports with each required bit clear; release remains denied for the corresponding negative evidence. Availability of those captures is a prerequisite, not assumed. |
| PI-02 | Supported authenticated report version exposes the alias field. | Older version lacks it; report unsupported evidence rather than an observed clear bit. |
| PI-03 | Claim bytes come from the verified report. | Put positive values only in an unauthenticated wrapper; they cannot satisfy the gate. |
| PI-04 | Matching CCA implementation profile decodes an authenticated configuration. | Unknown profile or changed encoding remains uninterpretable, not a default positive. |
| PI-05 | Endorsement is authenticated and its owner independently trusted. | Substitute an owner or platform identity; reject that binding. Even the valid control establishes ownership only. |
| PI-06 | IBM additional data authenticates and matches pinned reference inputs. | Change data or omit reference inputs; distinguish verification failure from unavailable appraisal. |
| PI-07 | Fresh evidence and the correct platform/profile are evaluated. | Replay stale evidence or apply another platform's decoder; no property acceptance follows. |

An executable extension still needs maintainer agreement on policy vocabulary and cross-platform equivalence, a versioned vendor profile, and captured vectors or suitable hardware. This note leaves the existing gate intact and does not close #121.

## References and limits

1. [AMD-SB-3015, alias-check guidance](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3015.html): supports the guest alias indicator and distinguishes host status. The other bit's mapping here is the pinned WCM contract, not a new independent ABI validation.
2. [Intel, Platform Ownership Endorsements](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/platform-ownership-endorsements.html): owner/platform binding and trust assumptions; not proof of physical tamper resistance or deployed-tool availability.
3. [IBM, pvattest command](https://www.ibm.com/docs/en/linux-on-systems?topic=commands-pvattest): additional-data choices and attestation coverage. Indexed primary command text was inspected; full-page/PDF retrieval was unavailable. No binary layout or hardware-version compatibility is certified.
4. [Arm CCA token, draft-ffm-rats-cca-token-04, section 4.5.3](https://datatracker.ietf.org/doc/html/draft-ffm-rats-cca-token-04#section-4.5.3): version-pinned draft, implementation-defined configuration. It is neither a final standard nor a validated decoder.
5. [Maintainer interpretation on #121](https://github.com/agentrust-io/weight-custody-manifest/issues/121#issuecomment-5805003101): preserves fail-closed behavior while requesting precise mappings. Literature findings do not replace that decision process.
