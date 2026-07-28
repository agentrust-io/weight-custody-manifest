"""The Layer 2 key broker service: composite verification and gated release.

This is the handshake of SPEC.md section 3.2, run in the release direction:
the KBS issues a nonce, the enclave returns composite evidence over it, and the
KBS releases the decryption key for a specific ``weights_hash`` only if every
gate check passes. The checks mirror the section 3.2 failure-paths table.

Scope and honesty. This is the *policy gate*. With the software provider it
proves the gate logic; it does not verify a real hardware root of trust, and
it cannot detect a forged quote from a physically-extracted attestation key
(the open key-extraction half of open question 8.8). ``memory_fingerprint`` is
the one detectable forgery class (measurement forgery), gated here when the
manifest requires it. Wipe-on-lapse / cadence custody is a separate concern and
not in this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable, Mapping, Optional

from ._challenge import Challenge, ChallengeError, ChallengeStore
from ._quote_verify import QuoteVerifier
from ._seal import seal_to_public_key
from .nvidia import NvidiaGpuVerifier
from .attestation import CompositeEvidence
from .models import (
    MemoryFingerprintChallenge,
    ServingImageStatus,
    WeightCustodyManifest,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: Optional[str] = None


@dataclass(frozen=True)
class ReleaseDecision:
    released: bool
    key: Optional[bytes]
    checks: list[CheckResult] = field(default_factory=list)
    # When channel binding is required, the key is returned only as bytes sealed
    # to the enclave's attested transport key (``_seal``); ``key`` is None so no
    # raw key ever crosses the channel, and only the enclave can open this
    # (SPEC 3.2 channel binding, relay defense). None on the default path.
    sealed_key: Optional[bytes] = None

    @property
    def failures(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed]


class KeyBrokerService:
    """A minimal attested key release service (SPEC.md section 3.2)."""

    def __init__(
        self,
        keystore: Mapping[str, bytes],
        *,
        challenge_ttl_seconds: int = 300,
        now: Optional[Callable[[], datetime]] = None,
        revoked_attestation_keys: Optional[Iterable[str]] = None,
        max_attestation_cache_age_seconds: int = 600,
        cpu_quote_verifier: Optional[QuoteVerifier] = None,
        gpu_report_verifier: Optional[NvidiaGpuVerifier] = None,
        require_channel_binding: bool = False,
    ) -> None:
        # keystore maps weights_hash -> the decryption key to release.
        self._keystore: dict[str, bytes] = dict(keystore)
        self._now = now or _utcnow
        self._challenges = ChallengeStore(ttl_seconds=challenge_ttl_seconds, now=self._now)
        self._revoked = set(revoked_attestation_keys or ())
        self._max_cache = max_attestation_cache_age_seconds
        # When set, the CPU quote's raw bytes are cryptographically verified
        # (signature + cert chain + nonce binding). When None, the gate trusts
        # the structured fields only, and says so in the check detail.
        self._cpu_quote_verifier = cpu_quote_verifier
        # When set, the GPU report's raw bytes are cryptographically verified
        # (signature + cert chain to NVIDIA's device root + nonce binding), the
        # GPU analog of cpu_quote_verifier. When None, the GPU is trusted on its
        # structured fields only (the existing _check_gpu composite binding), and
        # the check says so. See nvidia.build_gpu_verifier.
        self._gpu_report_verifier = gpu_report_verifier
        # When True, the evidence must carry an attested transport public key and
        # the released key is sealed to it (never returned in the clear), so a
        # relayed quote yields only ciphertext (SPEC 3.2 channel binding). Off by
        # default: the pre-channel-binding release shape is unchanged.
        self._require_channel_binding = require_channel_binding

    def issue_challenge(self) -> Challenge:
        return self._challenges.issue()

    def verify_and_release(
        self, manifest: WeightCustodyManifest, evidence: CompositeEvidence
    ) -> ReleaseDecision:
        """Run composite verification and release the key iff every check passes.

        The presented nonce is consumed on first use whatever the outcome, so a
        failed attempt cannot be retried with the same nonce.
        """
        rp = manifest.release_policy
        nonce = evidence.cpu.nonce_echo

        # 1. Nonce: issued by this KBS, unexpired, unused. A hard gate: if it
        #    fails there is nothing else to check.
        try:
            self._challenges.consume(nonce)
        except ChallengeError as exc:
            return ReleaseDecision(
                released=False,
                key=None,
                checks=[CheckResult("nonce_fresh", False, str(exc))],
            )

        checks: list[CheckResult] = [CheckResult("nonce_fresh", True)]

        # 1b. Channel binding: the transport key the released key will be sealed
        #     to, and the bytes folded into REPORT_DATA for the quote check.
        cb_check, channel_binding = self._check_channel_binding(evidence)
        checks.append(cb_check)

        # 2. CPU platform is one the manifest accepts.
        checks.append(
            CheckResult(
                "cpu_platform_allowed",
                evidence.cpu.platform in rp.required_hw_platform,
                None
                if evidence.cpu.platform in rp.required_hw_platform
                else f"cpu platform '{evidence.cpu.platform}' not in required_hw_platform",
            )
        )

        # 3. Assurance tier meets the manifest baseline.
        want_tier = rp.required_assurance_tier.value
        checks.append(
            CheckResult(
                "assurance_tier",
                evidence.cpu.assurance_tier == want_tier,
                None
                if evidence.cpu.assurance_tier == want_tier
                else f"assurance tier '{evidence.cpu.assurance_tier}' != required '{want_tier}'",
            )
        )

        # 4. Serving image: accepted, current-or-valid-retiring, not revoked,
        #    prefer-current.
        checks.append(self._check_serving_image(manifest, evidence))

        # 5. GPU: separate chain, bound to the CPU quote by the shared nonce.
        checks.append(self._check_gpu(manifest, evidence))

        # 6. Memory-fingerprint challenge (v0.8) when the posture requires it.
        checks.append(self._check_memory_fingerprint(manifest, evidence, nonce))

        # 7. Attestation-key revocation freshness (v0.8) when required.
        checks.append(self._check_attestation_revocation(manifest, evidence))

        # 7b. Cryptographic quote verification (signature + cert chain + nonce +
        #     transport-key binding) when a verifier is configured.
        checks.append(self._check_cpu_quote(evidence, nonce, channel_binding))

        # 7c. Cryptographic GPU-report verification (signature + cert chain to
        #     NVIDIA's device root + nonce binding) when a verifier is configured.
        checks.append(self._check_gpu_report(evidence, nonce))

        # 8. A key actually exists for this weights_hash.
        have_key = manifest.weights_hash in self._keystore
        checks.append(
            CheckResult(
                "key_available",
                have_key,
                None if have_key else "no key held for this weights_hash",
            )
        )

        released = all(c.passed for c in checks)
        key = self._keystore[manifest.weights_hash] if released else None

        # On the channel-bound path the key is sealed to the enclave's attested
        # transport key and never returned in the clear: a relayed quote yields
        # only ciphertext the relay cannot open (SPEC 3.2).
        sealed_key: Optional[bytes] = None
        if released and self._require_channel_binding:
            # released implies key_available and channel_binding both passed, so
            # both are non-None here; guard explicitly rather than assert (asserts
            # are stripped under -O, and this is the release path).
            transport_public_key = evidence.cpu.transport_public_key
            if key is not None and transport_public_key is not None:
                sealed_key = seal_to_public_key(transport_public_key, key)
                key = None

        return ReleaseDecision(
            released=released, key=key, checks=checks, sealed_key=sealed_key
        )

    # -- individual gate checks ------------------------------------------------

    def _check_serving_image(
        self, manifest: WeightCustodyManifest, evidence: CompositeEvidence
    ) -> CheckResult:
        rsi = manifest.release_policy.required_serving_image
        presented = evidence.cpu.serving_image_measurement
        match = next(
            (m for m in rsi.accepted_measurements if m.measurement == presented), None
        )
        if match is None:
            return CheckResult(
                "serving_image", False, "measurement not in accepted_measurements"
            )
        if match.status is ServingImageStatus.revoked:
            return CheckResult("serving_image", False, "serving image is revoked")

        has_current = any(
            m.status is ServingImageStatus.current for m in rsi.accepted_measurements
        )
        if match.status is ServingImageStatus.retiring:
            if match.retire_after is not None:
                retire_after = datetime.fromisoformat(match.retire_after)
                if self._now() > retire_after:
                    return CheckResult(
                        "serving_image", False, "retiring image is past retire_after"
                    )
            if has_current:
                return CheckResult(
                    "serving_image",
                    False,
                    "prefer-current: a current image is available",
                )
        return CheckResult("serving_image", True)

    def _check_gpu(
        self, manifest: WeightCustodyManifest, evidence: CompositeEvidence
    ) -> CheckResult:
        req = manifest.release_policy.required_gpu_measurement
        if req is None:
            return CheckResult("gpu", True, "no GPU measurement required")
        gpu = evidence.gpu
        if gpu is None:
            return CheckResult("gpu", False, "GPU report absent but required")
        if gpu.nonce_echo != evidence.cpu.nonce_echo:
            return CheckResult(
                "gpu", False, "GPU report not bound to CPU quote (nonce echo mismatch)"
            )
        if gpu.measurement != req.rim_pin:
            return CheckResult("gpu", False, "GPU measurement does not match rim_pin")
        return CheckResult("gpu", True)

    def _check_memory_fingerprint(
        self,
        manifest: WeightCustodyManifest,
        evidence: CompositeEvidence,
        nonce: str,
    ) -> CheckResult:
        required = (
            manifest.release_policy.memory_fingerprint_challenge
            is MemoryFingerprintChallenge.required_for_hostile_owner_posture
        )
        if not required:
            return CheckResult("memory_fingerprint", True, "not required")
        mf = evidence.memory_fingerprint
        if mf is None:
            return CheckResult(
                "memory_fingerprint", False, "required but not present in evidence"
            )
        if mf.challenge_nonce != nonce:
            return CheckResult(
                "memory_fingerprint", False, "fingerprint not bound to this challenge"
            )
        if mf.aliasing_detected:
            return CheckResult(
                "memory_fingerprint",
                False,
                "DRAM aliasing detected (BadRAM-class measurement forgery)",
            )
        return CheckResult("memory_fingerprint", True)

    def _check_channel_binding(
        self, evidence: CompositeEvidence
    ) -> tuple[CheckResult, bytes]:
        """Validate the transport key and return the REPORT_DATA binding bytes.

        Returns (check, channel_binding). ``channel_binding`` is the transport
        key's raw bytes when present and valid, else empty. When channel binding
        is not required, a present-but-valid key is still bound (defense in depth)
        and an absent one is fine.
        """
        tpk = evidence.cpu.transport_public_key
        if not tpk:
            if self._require_channel_binding:
                return (
                    CheckResult(
                        "channel_binding",
                        False,
                        "channel binding required but evidence has no transport_public_key",
                    ),
                    b"",
                )
            return CheckResult("channel_binding", True, "not required"), b""
        try:
            raw = bytes.fromhex(tpk)
        except ValueError:
            return (
                CheckResult("channel_binding", False, "transport_public_key is not valid hex"),
                b"",
            )
        if len(raw) != 32:
            return (
                CheckResult(
                    "channel_binding", False, "transport_public_key is not a 32-byte X25519 key"
                ),
                b"",
            )
        return CheckResult("channel_binding", True), raw

    def _check_cpu_quote(
        self, evidence: CompositeEvidence, nonce: str, channel_binding: bytes
    ) -> CheckResult:
        if self._cpu_quote_verifier is None:
            return CheckResult(
                "cpu_quote_verified",
                True,
                "not configured: structural trust only (no cryptographic quote verification)",
            )
        quote_b64 = evidence.cpu.quote_b64
        if quote_b64 is None:
            return CheckResult(
                "cpu_quote_verified", False, "verifier configured but evidence has no raw quote"
            )
        result = self._cpu_quote_verifier.verify(
            quote_b64, expected_nonce=nonce, channel_binding=channel_binding, now=self._now()
        )
        return CheckResult("cpu_quote_verified", result.verified, result.reason)

    def _check_gpu_report(
        self, evidence: CompositeEvidence, nonce: str
    ) -> CheckResult:
        if self._gpu_report_verifier is None:
            return CheckResult(
                "gpu_report_verified",
                True,
                "not configured: structural trust only (no cryptographic GPU verification)",
            )
        gpu = evidence.gpu
        if gpu is None:
            # Whether a GPU is required at all is _check_gpu's job; if none is
            # present there is no report to cryptographically verify.
            return CheckResult("gpu_report_verified", True, "no GPU report present")
        if gpu.quote_b64 is None:
            return CheckResult(
                "gpu_report_verified", False, "verifier configured but GPU report has no raw quote"
            )
        # The GPU evidence bundles the report and its device cert chain; the
        # report echoes the raw KBS nonce (offset 4), which is what ties it to
        # the CPU quote (composite binding in _check_gpu). No transport key on
        # the GPU side.
        result = self._gpu_report_verifier.verify(
            gpu.quote_b64, expected_nonce=nonce, now=self._now()
        )
        return CheckResult("gpu_report_verified", result.verified, result.reason)

    def _check_attestation_revocation(
        self, manifest: WeightCustodyManifest, evidence: CompositeEvidence
    ) -> CheckResult:
        if manifest.release_policy.attestation_revocation_check is None:
            return CheckResult("attestation_revocation", True, "not required")
        key_id = evidence.cpu.attestation_key_id
        if key_id in self._revoked:
            return CheckResult(
                "attestation_revocation", False, f"attestation key '{key_id}' is revoked"
            )
        if evidence.cpu.attestation_key_cache_age_seconds > self._max_cache:
            return CheckResult(
                "attestation_revocation",
                False,
                "revocation status cache is staler than the allowed window",
            )
        return CheckResult("attestation_revocation", True)
