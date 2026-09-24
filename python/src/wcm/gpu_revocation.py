"""Live, nonce-bound OCSP for the NVIDIA GPU attestation chain.

``release_policy.attestation_revocation_check`` is specified as
"live-per-release, max-cache-age: short-window", and SPEC 3.6 lists it as a
compensating control. The gate it drove compared a configured revoked-key set
with a self-reported cache age, so without something filling that set it could
not fail. The CRLs a verifier would otherwise fall back to are no better on the
NVIDIA side: every certificate in the device chain carries
``notAfter = 9999-12-31``, and the published lists hold zero entries with a two
year update interval, so an empty list cannot be told apart from a stale one.

This module asks NVIDIA instead, per release, with a fresh nonce per request,
and fails closed when it cannot get an answer.

**What the responder will and will not answer.** Measured against
``ocsp.ndis.nvidia.com``:

    FMC leaf (signs the report)   UNAUTHORIZED
    BROM (one per chip)           GOOD, nonce echoed
    Provisioner ICA               GOOD, nonce echoed
    GH100 Identity                GOOD, nonce echoed

Say the limit rather than rounding it off, because the two are not the same
thing: **this check never establishes the signing leaf's own revocation
status.** The GPU issues that certificate to itself and NVIDIA is not
authoritative for it. What the check establishes is that NVIDIA still stands
behind the chip and the intermediates above it, and a revoked BROM breaks the
chain for any leaf beneath it, so per-chip revocation is reachable one level up.
If NVIDIA ever had cause to revoke one leaf without revoking the BROM beneath
it, nothing here would see it.

**Rules enforced.**

1. Every link the responder is authoritative for must be GOOD. The leaf is not
   asked about: a request that can only come back UNAUTHORIZED would add a
   failure during an outage and nothing else. UNAUTHORIZED for any link that
   *is* asked is a refusal, otherwise a responder that stopped answering would
   read as a pass.
2. Each answer must echo the nonce this request sent. A missing echo is a
   refusal, not a warning: NVIDIA answers a request without a nonce, so a
   verifier that tolerates a missing echo accepts a replay.
3. Each answer's CertID must name the certificate that was asked about: serial
   number, issuer name hash and issuer key hash. RFC 6960 requires this and the
   nonce does not replace it, because a nonce ties an answer to a *request*, not
   to a certificate.
4. The signer must be the issuer itself, or a responder that issuer delegated
   with the OCSPSigning EKU. NVIDIA uses a delegated responder per level.
5. HTTPS is preferred where the certificate's AIA offers it, and is never relied
   on for rule 3.
6. Unreachable is a refusal. A first release must have a fresh answer and has
   nothing to fall back to. A renewal, which rides out an outage inside a window
   already granted, may reuse a previously verified answer while it is inside
   the short window and before its own ``nextUpdate``, and the detail says it
   was reused.
7. A verified revocation overrides a held GOOD from the moment it is seen.

Freshness is not authenticity: every answer is signed whether it is fresh or
reused, and what the short window bounds is how long ago NVIDIA said it.
"""
from __future__ import annotations

import threading
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional, Sequence, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
    OCSPExtensionOID,
)

#: NVIDIA's device responder, used for links whose certificate names no OCSP URL.
RESPONDER = "http://ocsp.ndis.nvidia.com"

#: How long a previously verified answer may be reused when the responder cannot
#: be reached. "short-window" in the policy text; the vendor's own nextUpdate is
#: a separate and usually looser bound, and both apply.
DEFAULT_MAX_AGE_SECONDS = 600

#: Labels for the links of an NVIDIA CC device chain, leaf first.
_LABELS = ("FMC leaf", "BROM", "Provisioner ICA", "Identity CA")

Post = Callable[[str, bytes], bytes]


class GpuRevocationUnavailable(RuntimeError):
    """No usable answer about a link. Always a refusal, never a fallback."""


@dataclass(frozen=True)
class Answer:
    """One link's revocation state, and how long it may be leaned on."""

    status: str
    source: str
    next_update: Optional[datetime]


@dataclass(frozen=True)
class RevocationResult:
    """The chain's verdict, with the instant the evidence behind it expires.

    ``not_after`` is the earliest ``nextUpdate`` across the answers this verdict
    rested on, or None when nothing time-bounded was consulted. A permission
    window granted on this verdict must not extend past it.
    """

    passed: bool
    detail: str
    not_after: Optional[datetime] = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


#: Attempts inside one request, and the seconds each is given.
#:
#: Measured on 24 September 2026 from two vantage points, twenty requests to
#: each of the responder's two edge addresses, one attempt each and no retry:
#:
#:     vantage point            166.117.200.57   166.117.113.121
#:     developer workstation         20 of 20          20 of 20
#:     confidential GPU host         20 of 20    **15 of 20**
#:
#: So the responder is not broadly unreliable, and the failures are not random.
#: One edge was lossy from one network, four timeouts and one reset, while the
#: same address answered perfectly from elsewhere at the same time. A client
#: cannot choose which edge its resolver hands it, so from that host roughly one
#: request in eight failed for reasons entirely outside the responder's control.
#:
#: A client that gave up after one attempt would refuse most first releases,
#: which would make live revocation unusable and push operators back onto the
#: stale CRLs this module exists to replace. At five attempts the chance of
#: exhausting them on one link is about one percent, and since failures are
#: fast the usual cost is a fraction of a second.
#:
#: Retrying here does not soften failing closed. The question is still "did this
#: request obtain a fresh answer", asked inside one bounded budget, rather than
#: "keep trying until one arrives". A single reset socket is not evidence that
#: NVIDIA has stopped answering.
ATTEMPTS = 5
ATTEMPT_TIMEOUT_SECONDS = 8


def http_post(url: str, body: bytes) -> bytes:
    if not url.startswith(("http://", "https://")):
        # The URL comes from a certificate's AIA extension, which travels inside
        # the evidence. Nothing but HTTP(S) is ever fetched, so file: and other
        # schemes cannot be reached through a crafted certificate.
        raise GpuRevocationUnavailable(f"refusing a non-HTTP OCSP responder URL: {url[:60]}")
    last: Optional[BaseException] = None
    for attempt in range(ATTEMPTS):
        request = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/ocsp-request"},
        )
        try:
            with urllib.request.urlopen(  # nosec B310
                request, timeout=ATTEMPT_TIMEOUT_SECONDS
            ) as response:
                body_bytes: bytes = response.read()
            return body_bytes
        except Exception as exc:  # noqa: BLE001 - reported below as one failure
            last = exc
            if attempt + 1 < ATTEMPTS:
                time.sleep(0.4 * (attempt + 1))
    raise GpuRevocationUnavailable(
        f"no answer from {url[:48]} in {ATTEMPTS} attempts: {str(last)[:80]}"
    )


def responder_for(certificate: x509.Certificate) -> str:
    """The certificate's own OCSP URL, or NVIDIA's responder when it names none.

    The per-chip BROM certificate carries no OCSP pointer and the responder
    answers for it anyway, so the chain's documented responder is the fallback.
    HTTPS is preferred where the certificate offers both.
    """
    urls: list[str] = []
    try:
        extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        aia = cast(x509.AuthorityInformationAccess, extension.value)
        for access in aia:
            if access.access_method == AuthorityInformationAccessOID.OCSP:
                urls.append(str(access.access_location.value))
    except x509.ExtensionNotFound:
        pass
    for url in urls:
        if url.lower().startswith("https://"):
            return url
    return urls[0] if urls else RESPONDER


def _names(
    response: ocsp.OCSPResponse, certificate: x509.Certificate, issuer: x509.Certificate
) -> bool:
    """Is this answer about exactly this certificate, under exactly this issuer?"""
    try:
        asked = (
            ocsp.OCSPRequestBuilder()
            .add_certificate(certificate, issuer, response.hash_algorithm)
            .build()
        )
    except (ValueError, TypeError):
        # An unusable or absent CertID hash algorithm names nothing.
        return False
    return (
        response.serial_number == asked.serial_number
        and response.issuer_key_hash == asked.issuer_key_hash
        and response.issuer_name_hash == asked.issuer_name_hash
    )


def _verify_signature(
    response: ocsp.OCSPResponse, issuer: x509.Certificate
) -> None:
    """Signed by the issuer, or by a responder that issuer delegated.

    NVIDIA uses a delegated responder per level, so the common case is the
    second: a certificate issued by the same issuer, carrying the OCSPSigning
    extended key usage, whose own signature verifies under the issuer's key.
    """
    signer = issuer
    if response.certificates:
        signer = response.certificates[0]
        usage: list[x509.ObjectIdentifier] = []
        try:
            extension = signer.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
            usage = list(cast(x509.ExtendedKeyUsage, extension.value))
        except x509.ExtensionNotFound:
            pass
        if ExtendedKeyUsageOID.OCSP_SIGNING not in usage:
            raise GpuRevocationUnavailable(
                "the responder certificate is not authorised to sign OCSP"
            )
        issuer_key = issuer.public_key()
        if not isinstance(issuer_key, ec.EllipticCurvePublicKey):
            raise GpuRevocationUnavailable(
                "the certificate's issuer does not hold an EC key, which this chain requires"
            )
        if signer.signature_hash_algorithm is None:
            raise GpuRevocationUnavailable(
                "the responder certificate names no signature hash algorithm"
            )
        try:
            issuer_key.verify(
                signer.signature,
                signer.tbs_certificate_bytes,
                ec.ECDSA(signer.signature_hash_algorithm),
            )
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise GpuRevocationUnavailable(
                "the responder was not delegated by this certificate's issuer"
            ) from exc
    signer_key = signer.public_key()
    if not isinstance(signer_key, ec.EllipticCurvePublicKey):
        raise GpuRevocationUnavailable(
            "the OCSP signer does not hold an EC key, which this chain requires"
        )
    if response.signature_hash_algorithm is None:
        raise GpuRevocationUnavailable("the OCSP answer names no signature hash algorithm")
    try:
        signer_key.verify(
            response.signature,
            response.tbs_response_bytes,
            ec.ECDSA(response.signature_hash_algorithm),
        )
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise GpuRevocationUnavailable(
            "the OCSP answer's signature does not verify"
        ) from exc


def verify_answer(
    response: ocsp.OCSPResponse,
    certificate: x509.Certificate,
    issuer: x509.Certificate,
    nonce: Optional[bytes],
) -> None:
    """Signed by NVIDIA, about this certificate, and for this request.

    The certificate check is not implied by the nonce. The responder is reachable
    over plain HTTP, so anything in the path can forward this request's nonce
    with a question about a different, healthy certificate and hand back that
    signed GOOD. The nonce would echo and the signature would verify. Only the
    CertID says which certificate NVIDIA vouched for.

    ``nonce`` is None only for an answer obtained out of band by someone else,
    where the echo proves nothing and freshness has to come from the timestamps.
    """
    if not _names(response, certificate, issuer):
        raise GpuRevocationUnavailable(
            "the answer is about a different certificate than the one asked"
        )
    if nonce is not None:
        try:
            extension = response.extensions.get_extension_for_oid(OCSPExtensionOID.NONCE)
            echoed = cast(x509.OCSPNonce, extension.value).nonce
        except x509.ExtensionNotFound as exc:
            raise GpuRevocationUnavailable(
                "the answer did not echo the nonce, so it may be a replay"
            ) from exc
        if echoed != nonce:
            raise GpuRevocationUnavailable(
                "the answer echoed a different nonce, so it is not for this request"
            )
    _verify_signature(response, issuer)


class NvidiaOcspClient:
    """Asks NVIDIA about one link at a time, and holds what it verified.

    The held answer exists so that a responder outage inside an existing
    permission window does not stop a running deployment. It is bounded twice,
    by ``max_age_seconds`` and by the answer's own ``nextUpdate``, and a verified
    revocation replaces a held GOOD immediately.
    """

    def __init__(
        self,
        *,
        post: Optional[Post] = None,
        nonce: Optional[Callable[[], bytes]] = None,
        max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    ) -> None:
        if max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be positive")
        self._post = post or http_post
        self._nonce = nonce or (lambda: __import__("os").urandom(32))
        self.max_age_seconds = int(max_age_seconds)
        self._held: dict[int, tuple[str, datetime, Optional[datetime]]] = {}
        self._lock = threading.Lock()

    def status(
        self, certificate: x509.Certificate, issuer: x509.Certificate, now: datetime,
        *, allow_reuse: bool = False,
    ) -> Answer:
        """Ask about one link. ``allow_reuse`` is false on a first release.

        A held answer exists so that an outage does not stop a deployment that
        is already running on a window someone granted. Starting a new one is a
        different act: there is no window to ride out, so there is nothing to
        fall back to and the answer has to be fresh.
        """
        nonce = self._nonce()
        request = (
            ocsp.OCSPRequestBuilder()
            .add_certificate(certificate, issuer, hashes.SHA384())
            .add_extension(x509.OCSPNonce(nonce), critical=False)
            .build()
        )
        try:
            raw = self._post(
                responder_for(certificate),
                request.public_bytes(serialization.Encoding.DER),
            )
            response = ocsp.load_der_ocsp_response(raw)
        except Exception as exc:  # noqa: BLE001 - every failure to obtain one is the same
            if not allow_reuse:
                raise GpuRevocationUnavailable(
                    f"NVIDIA could not be reached ({str(exc)[:100]}) and a first release "
                    "may not rest on an earlier answer"
                ) from exc
            return self._reuse(certificate, now, exc)

        if response.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED:
            # Not held: the responder is not authoritative, so there is nothing
            # here to reuse later and nothing that should look like a pass.
            return Answer("UNAUTHORIZED", "fresh", None)
        if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise GpuRevocationUnavailable(
                f"NVIDIA answered {response.response_status.name}"
            )
        verify_answer(response, certificate, issuer, nonce)
        if response.next_update_utc is not None and now >= response.next_update_utc:
            raise GpuRevocationUnavailable(
                "NVIDIA's answer is already past its own nextUpdate"
            )
        status = response.certificate_status.name
        with self._lock:
            # A verified revocation lands here and replaces any held GOOD, so
            # from this moment the reuse path can only serve the revocation.
            self._held[certificate.serial_number] = (
                status, now, response.next_update_utc,
            )
        return Answer(status, "fresh", response.next_update_utc)

    def _reuse(
        self, certificate: x509.Certificate, now: datetime, error: BaseException
    ) -> Answer:
        with self._lock:
            held = self._held.get(certificate.serial_number)
        if held is None:
            raise GpuRevocationUnavailable(
                f"NVIDIA could not be reached ({str(error)[:100]}) and no earlier "
                "answer about this certificate is held"
            )
        status, fetched, next_update = held
        age = int((now - fetched).total_seconds())
        if age > self.max_age_seconds:
            raise GpuRevocationUnavailable(
                f"NVIDIA could not be reached and the held answer is {age}s old, "
                f"past the {self.max_age_seconds}s short window"
            )
        if next_update is not None and now >= next_update:
            raise GpuRevocationUnavailable(
                "NVIDIA could not be reached and the held answer is past its own nextUpdate"
            )
        # Reuse does not restart any clock: the bound stays the one the original
        # answer carried, so a permission window cannot outlive it.
        return Answer(status, f"reused {age}s after it was obtained", next_update)


def check_chain(
    chain: Sequence[x509.Certificate],
    client: NvidiaOcspClient,
    now: Optional[datetime] = None,
    *,
    allow_reuse: bool = False,
) -> RevocationResult:
    """Ask NVIDIA about every link it is authoritative for, leaf first.

    ``chain`` is the device chain as it appears in GPU evidence: leaf, BROM,
    intermediates, root. The leaf is not asked about and the root is the anchor,
    so the questions are the links in between.
    """
    now = now if now is not None else _utcnow()
    if len(chain) < 3:
        return RevocationResult(
            False, "the GPU certificate chain is too short to check for revocation"
        )
    parts = [
        "leaf not established: NVIDIA does not answer for it, so this says "
        "nothing about the signing certificate itself; revoking the chip is "
        "reachable through BROM instead"
    ]
    not_after: Optional[datetime] = None
    for index in range(1, len(chain) - 1):
        certificate, issuer = chain[index], chain[index + 1]
        label = _LABELS[index] if index < len(_LABELS) else f"link {index}"
        try:
            answer = client.status(certificate, issuer, now, allow_reuse=allow_reuse)
        except GpuRevocationUnavailable as exc:
            return RevocationResult(False, f"{label}: {exc}")
        if answer.status == "UNAUTHORIZED":
            return RevocationResult(
                False, f"{label}: NVIDIA would not answer for a link it must vouch for"
            )
        if answer.status != "GOOD":
            return RevocationResult(
                False, f"{label}: NVIDIA reports this certificate {answer.status}"
            )
        if answer.next_update is not None:
            not_after = (answer.next_update if not_after is None
                         else min(not_after, answer.next_update))
        parts.append(f"{label} GOOD, {answer.source}")
    return RevocationResult(True, "NVIDIA OCSP, nonce-bound: " + "; ".join(parts), not_after)


def chain_from_evidence(evidence_b64: str) -> list[x509.Certificate]:
    """The device chain carried in GPU evidence, leaf first."""
    import base64
    import json

    document = json.loads(base64.b64decode(evidence_b64))
    return list(x509.load_pem_x509_certificates(document["cert_chain_pem"].encode()))
