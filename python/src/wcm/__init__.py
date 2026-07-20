"""Weight Custody Manifest (WCM) reference SDK — Layer 1 public API.

This package is the open reference implementation of the Layer 1 manifest from
the WCM specification: build a manifest, sign it jointly (builder + custodian,
plus a sovereign quorum when required), and verify those signatures.

Pre-1.0 and tracking a pre-1.0 spec. Layer 2 (attestation-gated key release),
the reference KBS, runtime custody, and derivative lineage are not implemented
here yet. See SPEC.md and the repo ROADMAP.
"""
from __future__ import annotations

from ._types import HashValue
from ._canonicalize import canonicalize, canonical_hash
from ._signing import (
    WCM_SIGNED_FIELDS,
    signing_pre_image,
    generate_ed25519,
    ed25519_from_private_bytes,
    ed25519_from_private_b64url,
    Ed25519KeyPair,
    Ed25519Signer,
    Ed25519Verifier,
)
from .models import (
    WeightCustodyManifest,
    Builder,
    ReleaseTerms,
    ReleasePolicy,
    RequiredGpuMeasurement,
    RequiredServingImage,
    AcceptedMeasurement,
    SovereignProfile,
    Custody,
    KbsImage,
    ManifestSignature,
    RightsHolder,
    DerivativePolicy,
    AssuranceTier,
    PhysicalHardening,
    TrustedTimeSource,
    MemoryFingerprintChallenge,
    Tenancy,
    KeyReleaseMode,
    ReplayProtection,
    ServingImageStatus,
    RevocationAuthority,
    CustodianType,
    SignatureRole,
    SignatureAlgorithm,
    KeyType,
)
from ._verify import (
    verify_manifest,
    VerificationContext,
    VerificationResult,
    SignatureResult,
)
from ._challenge import Challenge, ChallengeStore, ChallengeError
from .attestation import (
    CompositeEvidence,
    CpuQuote,
    GpuReport,
    MemoryFingerprint,
)
from .providers import (
    AttestationProvider,
    SoftwareProvider,
    AttestationUnavailableError,
)
from ._hw_providers import (
    CpuQuoteProvider,
    SevSnpProvider,
    TdxProvider,
    NvidiaCcProvider,
    HardwareCompositeProvider,
    select_provider,
    select_cpu_provider,
)
from .kbs import KeyBrokerService, ReleaseDecision, CheckResult
from ._quote_verify import (
    QuoteVerifier,
    QuoteVerification,
    TrustStore,
    JsonQuoteParser,
    ParsedQuote,
    QuoteParser,
    QuoteFormatError,
    verify_cert_chain,
)
from .custody import (
    EnclaveSession,
    SessionState,
    TimeFloor,
    KeyWipedError,
    ReattestationRequired,
    parse_cadence,
)
from .lineage import verify_lineage, LineageResult, is_root

__version__ = "0.7.0"

__all__ = [
    "__version__",
    "HashValue",
    "canonicalize",
    "canonical_hash",
    "WCM_SIGNED_FIELDS",
    "signing_pre_image",
    "generate_ed25519",
    "ed25519_from_private_bytes",
    "ed25519_from_private_b64url",
    "Ed25519KeyPair",
    "Ed25519Signer",
    "Ed25519Verifier",
    "WeightCustodyManifest",
    "Builder",
    "ReleaseTerms",
    "ReleasePolicy",
    "RequiredGpuMeasurement",
    "RequiredServingImage",
    "AcceptedMeasurement",
    "SovereignProfile",
    "Custody",
    "KbsImage",
    "ManifestSignature",
    "RightsHolder",
    "DerivativePolicy",
    "AssuranceTier",
    "PhysicalHardening",
    "TrustedTimeSource",
    "MemoryFingerprintChallenge",
    "Tenancy",
    "KeyReleaseMode",
    "ReplayProtection",
    "ServingImageStatus",
    "RevocationAuthority",
    "CustodianType",
    "SignatureRole",
    "SignatureAlgorithm",
    "KeyType",
    "verify_manifest",
    "VerificationContext",
    "VerificationResult",
    "SignatureResult",
    "Challenge",
    "ChallengeStore",
    "ChallengeError",
    "CompositeEvidence",
    "CpuQuote",
    "GpuReport",
    "MemoryFingerprint",
    "AttestationProvider",
    "SoftwareProvider",
    "AttestationUnavailableError",
    "CpuQuoteProvider",
    "SevSnpProvider",
    "TdxProvider",
    "NvidiaCcProvider",
    "HardwareCompositeProvider",
    "select_provider",
    "select_cpu_provider",
    "KeyBrokerService",
    "ReleaseDecision",
    "CheckResult",
    "QuoteVerifier",
    "QuoteVerification",
    "TrustStore",
    "JsonQuoteParser",
    "ParsedQuote",
    "QuoteParser",
    "QuoteFormatError",
    "verify_cert_chain",
    "EnclaveSession",
    "SessionState",
    "TimeFloor",
    "KeyWipedError",
    "ReattestationRequired",
    "parse_cadence",
    "verify_lineage",
    "LineageResult",
    "is_root",
]
