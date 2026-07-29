"""CLI coverage for the verify/gate/inspect verbs, driven through ``main()``.

verify-quote is exercised against the committed fixtures for all three kinds
(SNP, TDX, GPU), happy path plus wrong-nonce and untrusted-root failures. gate
and inspect run against the example manifest. verify-provenance is guarded so it
skips when the model-signing extra is absent and runs for real when it is.
"""
from __future__ import annotations

import copy
import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wcm.cli import main

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
BAD_NONCE = "cd" * 32

try:
    import model_signing  # noqa: F401

    HAVE_MS = True
except ImportError:
    HAVE_MS = False

requires_ms = pytest.mark.skipif(not HAVE_MS, reason="model-signing extra not installed")


def _stranger_root(tmp_path: pathlib.Path) -> str:
    key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "stranger-root")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    p = tmp_path / "stranger.pem"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(p)


def _manifest_file(tmp_path: pathlib.Path, doc: dict) -> str:
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


# -- verify-quote: SNP ---------------------------------------------------------


def test_vq_snp_synthetic_ok(capsys):
    assert main(["verify-quote", "--kind", "snp", str(FIXTURES / "snp_quote_synthetic.json")]) == 0
    assert "verified  : True" in capsys.readouterr().out


def test_vq_snp_wrong_nonce(capsys):
    rc = main(
        ["verify-quote", "--kind", "snp", str(FIXTURES / "snp_quote_synthetic.json"), "--nonce", BAD_NONCE]
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "verified  : False" in out and "REPORT_DATA" in out


def test_vq_snp_untrusted_root(capsys, tmp_path):
    rc = main(
        [
            "verify-quote",
            "--kind",
            "snp",
            str(FIXTURES / "snp_quote_synthetic.json"),
            "--root",
            _stranger_root(tmp_path),
        ]
    )
    assert rc == 1
    assert "trusted root" in capsys.readouterr().out.lower()


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_vq_snp_azure_vtpm_ok(capsys):
    # Genuine Azure capture: REPORT_DATA is AK-bound, so there is no KBS nonce to
    # bind; the CLI verifies chain + report signature and says so.
    assert main(["verify-quote", "--kind", "snp", str(FIXTURES / "snp_quote_azure.json")]) == 0
    out = capsys.readouterr().out
    assert "verified  : True" in out and "vTPM" in out


# -- verify-quote: TDX ---------------------------------------------------------


def test_vq_tdx_ok(capsys):
    assert main(["verify-quote", "--kind", "tdx", str(FIXTURES / "tdx_quote_gcp.json")]) == 0
    assert "verified  : True" in capsys.readouterr().out


def test_vq_tdx_wrong_nonce(capsys):
    rc = main(
        ["verify-quote", "--kind", "tdx", str(FIXTURES / "tdx_quote_gcp.json"), "--nonce", BAD_NONCE]
    )
    assert rc == 1
    assert "verified  : False" in capsys.readouterr().out


def test_vq_tdx_untrusted_root(capsys, tmp_path):
    rc = main(
        [
            "verify-quote",
            "--kind",
            "tdx",
            str(FIXTURES / "tdx_quote_gcp.json"),
            "--root",
            _stranger_root(tmp_path),
        ]
    )
    assert rc == 1
    assert "verified  : False" in capsys.readouterr().out


# -- verify-quote: GPU ---------------------------------------------------------


def test_vq_gpu_ok(capsys):
    assert main(["verify-quote", "--kind", "gpu", str(FIXTURES / "gpu_h100_attestation.json")]) == 0
    out = capsys.readouterr().out
    assert "verified  : True" in out and "GSP FMC LF" in out


def test_vq_gpu_wrong_nonce(capsys):
    rc = main(
        ["verify-quote", "--kind", "gpu", str(FIXTURES / "gpu_h100_attestation.json"), "--nonce", BAD_NONCE]
    )
    assert rc == 1
    assert "verified  : False" in capsys.readouterr().out


def test_vq_gpu_untrusted_root(capsys, tmp_path):
    rc = main(
        [
            "verify-quote",
            "--kind",
            "gpu",
            str(FIXTURES / "gpu_h100_attestation.json"),
            "--root",
            _stranger_root(tmp_path),
        ]
    )
    assert rc == 1
    assert "trusted root" in capsys.readouterr().out.lower()


# -- gate ----------------------------------------------------------------------


def test_gate_conformant_releases(capsys, example_dict, tmp_path):
    rc = main(["gate", _manifest_file(tmp_path, example_dict)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "released        : True" in out
    assert "[PASS] serving_image" in out


def test_gate_bad_serving_image_refuses(capsys, example_dict, tmp_path):
    rc = main(
        ["gate", _manifest_file(tmp_path, example_dict), "--serving-image", "sha256:" + "0" * 64]
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "released        : False" in out
    assert "[FAIL] serving_image" in out


# -- inspect -------------------------------------------------------------------


def test_inspect_prints_key_fields(capsys, example_dict, tmp_path):
    assert main(["inspect", _manifest_file(tmp_path, example_dict)]) == 0
    out = capsys.readouterr().out
    assert example_dict["weights_hash"] in out
    assert "base_confidentiality" in out
    assert "release_policy" in out


# -- verify-provenance (model-signing extra) -----------------------------------


@requires_ms
def test_verify_provenance_cli_round_trip(capsys, example_dict, tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from wcm import model_signing_digest

    priv = _ec.generate_private_key(_ec.SECP256R1())
    priv_p = tmp_path / "key.pem"
    priv_p.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub_p = tmp_path / "key.pub"
    pub_p.write_bytes(
        priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    model = tmp_path / "model.bin"
    model.write_bytes(b"weights-v1")
    sig = tmp_path / "model.sig"
    model_signing.signing.Config().use_elliptic_key_signer(private_key=str(priv_p)).sign(
        str(model), str(sig)
    )

    doc = copy.deepcopy(example_dict)
    doc["provenance"] = {"model_signing": {"signed_digest": model_signing_digest(str(model))}}
    manifest = _manifest_file(tmp_path, doc)

    rc = main(
        [
            "verify-provenance",
            manifest,
            "--model",
            str(model),
            "--signature",
            str(sig),
            "--public-key",
            str(pub_p),
        ]
    )
    assert rc == 0
    assert "verified  : True" in capsys.readouterr().out
