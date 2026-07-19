"""Command-line interface for the WCM Layer 1 reference SDK.

Verbs:
  wcm keygen [--out PREFIX]                Generate an Ed25519 key pair.
  wcm sign   MANIFEST --role R --signer S --key-file PRIV   Append a signature.
  wcm verify MANIFEST --key-file PUB [--key-file PUB ...]   Verify joint sigs.

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
import json
import sys
from typing import Optional

from ._signing import Ed25519Signer, ed25519_from_private_b64url, generate_ed25519
from ._verify import VerificationContext, verify_manifest
from .models import WeightCustodyManifest


def _load_manifest(path: str) -> WeightCustodyManifest:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return WeightCustodyManifest.model_validate(data)


def _read_key(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().strip()


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

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = args.func
    return int(func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
