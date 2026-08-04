"""Command-line interface for the WCM reference SDK.

Verbs:
  wcm keygen [--out PREFIX]                Generate an Ed25519 key pair.
  wcm sign   MANIFEST --role R --signer S --key-file PRIV   Append a signature.
  wcm verify MANIFEST --key-file PUB [--key-file PUB ...]   Verify joint sigs.
  wcm inspect MANIFEST                     Summarize a manifest's fields/policy.
  wcm gate MANIFEST [--platform P] [--serving-image H] [--gpu-measurement RIM]
           [--memory-fingerprint]          Diagnose a release policy (MOCK attest).
  wcm verify-quote --kind {snp,tdx,gpu} QUOTE [--nonce HEX] [--root PEM]
                                           Verify a captured attestation quote.
  wcm verify-provenance MANIFEST --model DIR --signature SIG --public-key PEM
                                           Cross-verify OpenSSF model-signing.
  wcm conformance [--level L1|L2|L3|L4] [--results FILE] [--list-vectors]
                  [--list-codes]           Run the conformance suite.

Keys are read from files, never passed on the command line: a private key on
argv leaks into process listings and shell history, and a base64url key can
begin with '-', which an argument parser would mistake for an option. ``keygen
--out PREFIX`` writes ``PREFIX`` (private, base64url) and ``PREFIX.pub``
(public); those files feed ``--key-file`` directly.

Manifests are read and written as JSON. ``sign`` appends a signature block to
the ``signatures`` array and writes the result to --out (or stdout).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ._quote_verify import QuoteVerification, QuoteVerifier, TrustStore, verify_cert_chain
from ._signing import Ed25519Signer, ed25519_from_private_b64url, generate_ed25519
from ._verify import VerificationContext, verify_manifest
from .kbs import KeyBrokerService
from .models import MemoryFingerprintChallenge, ServingImageStatus, WeightCustodyManifest
from .nvidia import build_gpu_verifier
from .providers import SoftwareProvider
from .snp import SnpQuoteParser, parse_snp_report, verify_snp_report_signature
from .tdx import parse_tdx_quote, verify_tdx_quote

# Pinned vendor roots (SHA-256 over the DER). When the root travels inside the
# evidence chain (the TDX PCK chain, the NVIDIA device chain), pinning its
# fingerprint is the out-of-band trust anchor a real verifier uses instead of
# trusting whatever root the evidence happened to carry. AMD's root is carried in
# the SNP bundle and pinned by the caller's own trust store there.
INTEL_SGX_ROOT_CA_SHA256 = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"
NVIDIA_DEVICE_ROOT_SHA256 = "102bf659d5419614c9d8e6aecebc80454eb26b1df6a769ac720b9a690b167b48"


def _load_manifest(path: str) -> WeightCustodyManifest:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return WeightCustodyManifest.model_validate(data)


def _read_key(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().strip()


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _read_json(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)
    return data


def _fp(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _load_root_pem(path: str) -> x509.Certificate:
    return x509.load_pem_x509_certificates(_read_text(path).encode())[0]


def cmd_keygen(args: argparse.Namespace) -> int:
    kp = generate_ed25519()
    if args.out:
        priv_path = args.out
        pub_path = args.out + ".pub"
        with open(priv_path, "w", encoding="utf-8") as fh:
            fh.write(kp.private_b64url() + "\n")
        with open(pub_path, "w", encoding="utf-8") as fh:
            fh.write(kp.public_b64url() + "\n")
        print(
            f"key_id={kp.key_id}\nprivate: {priv_path}\npublic:  {pub_path}",
            file=sys.stderr,
        )
    else:
        out = {
            "key_id": kp.key_id,
            "public_key_b64url": kp.public_b64url(),
            "private_key_b64url": kp.private_b64url(),
        }
        print(json.dumps(out, indent=2))
        print(
            "\nKeep private_key_b64url secret. For scripting, prefer "
            "'wcm keygen --out PREFIX' to write key files.",
            file=sys.stderr,
        )
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    manifest = _load_manifest(args.manifest)
    kp = ed25519_from_private_b64url(_read_key(args.key_file))
    block = Ed25519Signer(kp).sign(
        manifest.unsigned_dict(), role=args.role, signer=args.signer
    )

    doc = manifest.model_dump(mode="json", exclude_none=True)
    doc.setdefault("signatures", [])
    doc["signatures"].append(block)

    text = json.dumps(doc, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"signed by role='{args.role}' key_id={kp.key_id}", file=sys.stderr)
    else:
        print(text)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    manifest = _load_manifest(args.manifest)
    ctx = VerificationContext()
    for path in args.key_file:
        ctx.add_key_b64url(_read_key(path))

    result = verify_manifest(manifest, ctx)
    report = {
        "ok": result.ok,
        "signatures": [
            {
                "role": r.role.value,
                "signer": r.signer,
                "key_id": r.key_id,
                "valid": r.valid,
                "reason": r.reason,
            }
            for r in result.signatures
        ],
        "missing_roles": [r.value for r in result.missing_roles],
        "errors": result.errors,
    }
    print(json.dumps(report, indent=2))
    return 0 if result.ok else 1


def cmd_inspect(args: argparse.Namespace) -> int:
    m = _load_manifest(args.manifest)
    rp = m.release_policy
    gpu = rp.required_gpu_measurement.rim_pin if rp.required_gpu_measurement else "none"
    roles = ", ".join(sorted({s.role.value for s in m.signatures})) or "unsigned"
    print(f"weights_hash         : {m.weights_hash}")
    print(f"base_confidentiality : {m.base_confidentiality.value}")
    print(f"deployment_model     : {m.deployment_model.value}")
    print(f"derived_from         : {m.derived_from or 'none (root manifest)'}")
    if m.rights_holder is not None:
        print(f"rights_holder        : base={m.rights_holder.base} derivative={m.rights_holder.derivative}")
    if m.provenance is not None and m.provenance.model_signing is not None:
        print(f"provenance           : model-signing digest {m.provenance.model_signing.signed_digest}")
    print(f"signatures           : {len(m.signatures)} ({roles})")
    derivatives = m.release_terms.derivatives.value if m.release_terms.derivatives is not None else "unspecified"
    print(f"release_terms        : license={m.release_terms.license} derivatives={derivatives}")
    print(
        "release_policy       : "
        f"tier={rp.required_assurance_tier.value} "
        f"platforms={'+'.join(rp.required_hw_platform)} gpu_rim={gpu}"
    )
    print(
        "                       "
        f"serving_images={len(rp.required_serving_image.accepted_measurements)} "
        f"memory_fingerprint={rp.memory_fingerprint_challenge.value} "
        f"trusted_time={rp.trusted_time_source.value}"
    )
    print(f"custody              : {m.custody.custodian_type.value} cadence={m.custody.attestation_cadence}")
    return 0


def cmd_gate(args: argparse.Namespace) -> int:
    m = _load_manifest(args.manifest)
    rp = m.release_policy

    ams = rp.required_serving_image.accepted_measurements
    current = next(
        (a.measurement for a in ams if a.status is ServingImageStatus.current),
        ams[0].measurement,
    )
    serving = args.serving_image or current
    platform = args.platform or rp.required_hw_platform[0]
    gpu_meas = args.gpu_measurement or (
        rp.required_gpu_measurement.rim_pin if rp.required_gpu_measurement else None
    )
    want_mf = (
        rp.memory_fingerprint_challenge
        is MemoryFingerprintChallenge.required_for_hostile_owner_posture
    ) or args.memory_fingerprint

    kbs = KeyBrokerService({m.weights_hash: b"diagnostic-placeholder-key-0000"})
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=serving,
        platform=platform,
        assurance_tier=rp.required_assurance_tier.value,
        gpu_measurement=gpu_meas,
        include_memory_fingerprint=want_mf,
    )
    decision = kbs.verify_and_release(m, evidence)

    print("release-policy diagnostic (MOCK software attestation, NOT a live hardware release)")
    print(f"  manifest        : {args.manifest}")
    print(f"  platform        : {platform}   serving-image: {serving[:23]}...")
    print("  checks:")
    for c in decision.checks:
        mark = "PASS" if c.passed else "FAIL"
        detail = f"  {c.detail}" if c.detail else ""
        print(f"    [{mark}] {c.name}{detail}")
    print(f"  released        : {decision.released}")
    if not decision.released:
        print("  -> a KBS with this policy would REFUSE to release the key.")
    return 0 if decision.released else 1


def _print_quote_result(kind: str, result: QuoteVerification) -> int:
    print(f"kind      : {kind}")
    print(f"verified  : {result.verified}")
    if result.leaf_subject:
        print(f"leaf      : {result.leaf_subject}")
    if result.reason:
        print(f"reason    : {result.reason}")
    return 0 if result.verified else 1


def _verify_snp(bundle: dict[str, Any], args: argparse.Namespace) -> QuoteVerification:
    vcek = x509.load_pem_x509_certificate(bundle["vcek_pem"].encode())
    inters = [
        x509.load_pem_x509_certificate(p.encode())
        for p in bundle.get("intermediates_pem", [])
    ]
    root = (
        _load_root_pem(args.root)
        if args.root
        else x509.load_pem_x509_certificate(bundle["root_pem"].encode())
    )
    trust = TrustStore()
    trust.add_root(root)
    nonce = args.nonce or bundle.get("expected_nonce")
    if nonce:
        # Guest-controlled REPORT_DATA: the full gate applies, nonce and all.
        return QuoteVerifier(SnpQuoteParser(vcek, inters), trust).verify(
            bundle["report_b64"], expected_nonce=nonce
        )
    # Azure vTPM path: REPORT_DATA binds the vTPM AK, not our nonce, so verify the
    # chain and report signature (genuine on Azure); freshness lives in the
    # separate vTPM quote over the AK, one layer up.
    now = datetime.now(timezone.utc)
    chain_error = verify_cert_chain(vcek, inters, trust, now)
    if chain_error is not None:
        return QuoteVerification(False, chain_error)
    report = base64.b64decode(bundle["report_b64"])
    if not verify_snp_report_signature(report, vcek):
        return QuoteVerification(False, "report signature does not verify under the VCEK")
    return QuoteVerification(
        True,
        reason="no nonce bound (Azure vTPM topology: REPORT_DATA binds the vTPM AK, not the KBS nonce)",
        leaf_subject=vcek.subject.rfc4514_string(),
    )


def _verify_tdx(bundle: dict[str, Any], args: argparse.Namespace) -> QuoteVerification:
    quote = base64.b64decode(bundle["quote_b64"])
    trust = TrustStore()
    if args.root:
        trust.add_root(_load_root_pem(args.root))
    else:
        q = parse_tdx_quote(quote)
        chain = [q.pck_leaf, *q.pck_intermediates]
        root = next((c for c in chain if c.subject == c.issuer), None)
        if root is None:
            return QuoteVerification(False, "no self-signed root in the quote's PCK chain")
        pinned = bundle.get("intel_sgx_root_ca_sha256") or INTEL_SGX_ROOT_CA_SHA256
        if _fp(root) != pinned:
            return QuoteVerification(
                False,
                f"PCK-chain root fingerprint {_fp(root)} does not match the pinned Intel SGX root",
            )
        trust.add_root(root)
    nonce = args.nonce if args.nonce is not None else bundle.get("expected_nonce")
    return verify_tdx_quote(quote, trust, expected_nonce=nonce)


def _verify_gpu(bundle: dict[str, Any], args: argparse.Namespace) -> QuoteVerification:
    if args.root:
        root_pem = _read_text(args.root)
    else:
        certs = x509.load_pem_x509_certificates(bundle["cert_chain_pem"].encode())
        root = next((c for c in certs if c.subject == c.issuer), None)
        if root is None:
            return QuoteVerification(False, "no self-signed root in the GPU device cert chain")
        if _fp(root) != NVIDIA_DEVICE_ROOT_SHA256:
            return QuoteVerification(
                False,
                f"device-chain root fingerprint {_fp(root)} does not match the pinned NVIDIA root",
            )
        root_pem = root.public_bytes(serialization.Encoding.PEM).decode()
    verifier = build_gpu_verifier(root_pem)
    evidence_b64 = base64.b64encode(
        json.dumps(
            {"report_b64": bundle["report_b64"], "cert_chain_pem": bundle["cert_chain_pem"]}
        ).encode()
    ).decode()
    nonce = args.nonce or bundle.get("nonce")
    if not nonce:
        return QuoteVerification(False, "no nonce given and none in the bundle")
    return verifier.verify(evidence_b64, expected_nonce=nonce)


def cmd_verify_quote(args: argparse.Namespace) -> int:
    bundle = _read_json(args.quote)
    dispatch = {"snp": _verify_snp, "tdx": _verify_tdx, "gpu": _verify_gpu}
    try:
        result = dispatch[args.kind](bundle, args)
    except (KeyError, ValueError, TypeError) as exc:
        print(f"kind      : {args.kind}\nverified  : False\nreason    : unparseable bundle: {exc}")
        return 1
    return _print_quote_result(args.kind, result)


def cmd_verify_provenance(args: argparse.Namespace) -> int:
    from .provenance import verify_provenance

    manifest = _load_manifest(args.manifest)
    try:
        result = verify_provenance(
            manifest, args.model, args.signature, public_key=args.public_key
        )
    except ImportError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"verified  : {result.verified}")
    if result.reason:
        print(f"reason    : {result.reason}")
    return 0 if result.verified else 1


def cmd_conformance(args: argparse.Namespace) -> int:
    from .conformance import (
        CODES,
        DECLARED_ONLY_LEVELS,
        LEVELS,
        load_vectors,
        run_reference,
        score_results,
        vectors_dir,
    )

    if args.list_codes:
        for code, description in CODES.items():
            print(f"{code}  {description}")
        return 0

    if args.list_vectors:
        for vector in load_vectors(level=args.level):
            print(f"{vector['level']}  {vector['kind']:10} {vector['expect']:6} {vector['id']}")
        return 0

    if args.results:
        with open(args.results, encoding="utf-8") as handle:
            payload = json.load(handle)
        report = score_results(payload, level=args.level)
        subject = payload.get("implementation", args.results)
    else:
        report = run_reference(level=args.level)
        subject = "reference implementation (this SDK)"

    print(f"vectors   : {vectors_dir()}")
    print(f"subject   : {subject}")
    print(report.render())
    if not args.results:
        # The reference deriving its own codes is a weaker signal than an
        # independent implementation doing so; say which one this was.
        print("note      : reference self-test; verdicts and WCM-* codes both checked")
    covered = ", ".join(r.level for r in report.levels if r.ok) or "none"
    print(f"levels ok : {covered}")
    if DECLARED_ONLY_LEVELS and args.level is None:
        pending = ", ".join(
            f"{lid} ({LEVELS[lid].title})" for lid in DECLARED_ONLY_LEVELS
        )
        print(
            f"NOT COVERED: {pending}. These levels are specified but have no "
            "vectors yet, so this run says nothing about them."
        )
    return 0 if report.ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wcm", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen", help="Generate an Ed25519 key pair")
    p_keygen.add_argument(
        "--out",
        default=None,
        help="Write PREFIX (private) and PREFIX.pub (public); default: JSON to stdout",
    )
    p_keygen.set_defaults(func=cmd_keygen)

    p_sign = sub.add_parser("sign", help="Append a signature to a manifest")
    p_sign.add_argument("manifest", help="Path to the manifest JSON")
    p_sign.add_argument(
        "--role",
        required=True,
        choices=["builder", "custodian", "sovereign", "additional"],
        help="The signing party's role",
    )
    p_sign.add_argument("--signer", required=True, help="The signer's identity string")
    p_sign.add_argument(
        "--key-file", required=True, help="File holding the signer's private key (base64url)"
    )
    p_sign.add_argument("--out", default=None, help="Output path (default: stdout)")
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify", help="Verify a manifest's joint signatures")
    p_verify.add_argument("manifest", help="Path to the manifest JSON")
    p_verify.add_argument(
        "--key-file",
        action="append",
        required=True,
        help="File holding a trusted public key (base64url); repeat for multiple",
    )
    p_verify.set_defaults(func=cmd_verify)

    p_inspect = sub.add_parser("inspect", help="Summarize a manifest's fields and policy")
    p_inspect.add_argument("manifest", help="Path to the manifest JSON")
    p_inspect.set_defaults(func=cmd_inspect)

    p_gate = sub.add_parser(
        "gate",
        help="Diagnose a manifest's release policy with a mock (software) attestation",
    )
    p_gate.add_argument("manifest", help="Path to the manifest JSON")
    p_gate.add_argument("--platform", default=None, help="CPU platform to present (default: first required)")
    p_gate.add_argument("--serving-image", default=None, help="Serving-image measurement to present")
    p_gate.add_argument("--gpu-measurement", default=None, help="GPU measurement (RIM) to present")
    p_gate.add_argument(
        "--memory-fingerprint",
        action="store_true",
        help="Include a clean memory-fingerprint response even if the manifest does not require it",
    )
    p_gate.set_defaults(func=cmd_gate)

    p_vq = sub.add_parser("verify-quote", help="Verify a captured attestation quote bundle")
    p_vq.add_argument("--kind", required=True, choices=["snp", "tdx", "gpu"], help="Quote type")
    p_vq.add_argument("quote", help="Path to the quote bundle JSON")
    p_vq.add_argument("--nonce", default=None, help="Expected challenge nonce (hex); overrides the bundle")
    p_vq.add_argument("--root", default=None, help="Trusted root cert (PEM) to override the pinned/bundled root")
    p_vq.set_defaults(func=cmd_verify_quote)

    p_vp = sub.add_parser(
        "verify-provenance",
        help="Cross-verify an OpenSSF model-signing signature against the manifest",
    )
    p_vp.add_argument("manifest", help="Path to the manifest JSON (must carry provenance.model_signing)")
    p_vp.add_argument("--model", required=True, help="Path to the model files that were signed")
    p_vp.add_argument("--signature", required=True, help="Path to the model-signing signature")
    p_vp.add_argument("--public-key", required=True, help="EC public key (PEM) to verify under")
    p_vp.set_defaults(func=cmd_verify_provenance)

    p_conf = sub.add_parser(
        "conformance",
        help="Run the conformance suite, or score another implementation's results",
    )
    p_conf.add_argument(
        "--level",
        choices=sorted(("L1", "L2", "L3", "L4")),
        help="Score one level only (default: every level that has vectors)",
    )
    p_conf.add_argument(
        "--results",
        help="Score this results JSON instead of self-testing the reference "
        "(see conformance/README.md for the shape)",
    )
    p_conf.add_argument(
        "--list-vectors", action="store_true", help="List the vectors and exit"
    )
    p_conf.add_argument(
        "--list-codes", action="store_true", help="List the WCM-* error codes and exit"
    )
    p_conf.set_defaults(func=cmd_conformance)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = args.func
    return int(func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
