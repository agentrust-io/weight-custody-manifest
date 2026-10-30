"""Historical byte choices through the public runtime-record verifier.

The old preimages below are explicit fixture bytes, not another invocation of
production canonicalization. They document a compatibility boundary; there is
no legacy verifier fallback or migration policy in this test.
"""
from dataclasses import replace
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from wcm.runtime_records import RuntimeEvent, runtime_public_key, sign_runtime_record


@pytest.mark.parametrize(('detail', 'legacy_detail', 'compatible'), [
    ({'v': 1}, b'{"v":1}', True),
    ({'v': 1e-6}, b'{"v":1e-06}', False),
    ({'v': '\u2028'}, b'{"v":"\\u2028"}', False),
])
def test_archived_runtime_record_requires_its_original_canonical_bytes(
    detail, legacy_detail, compatible,
):
    # Public, deterministic test key; never an operational signing identity.
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pin = runtime_public_key(key)
    current = sign_runtime_record(
        signing_key=key, sequence=0, event=RuntimeEvent.lease_started,
        occurred_at='2026-10-01T00:00:00Z', weights_hash='sha256:' + 'a' * 64,
        manifest_hash='sha256:' + 'b' * 64, lease_id='fixture', detail=detail,
    )
    # Optional-null previous_record_hash is omitted by the existing profile.
    legacy_payload = (
        b'{"algorithm":"Ed25519","detail":' + legacy_detail
        + b',"event":"lease_started","kind":"wcm-runtime-record/v1",'
        + b'"lease_id":"fixture","manifest_hash":"sha256:' + b'b' * 64
        + b'","occurred_at":"2026-10-01T00:00:00Z","public_key_b64url":"'
        + pin.encode('ascii') + b'","sequence":0,"weights_hash":"sha256:'
        + b'a' * 64 + b'"}'
    )
    signature = key.sign(legacy_payload)
    # Positive historical-byte control proves the fixture is properly signed.
    key.public_key().verify(signature, legacy_payload)
    encoded = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')
    archived = replace(current, signature_b64url=encoded)
    assert current.verify(pin)
    assert archived.verify(pin) is compatible
    # Record hashes include the signature and form the next chain link.
    old_record_bytes = legacy_payload.replace(
        b',"weights_hash":', b',"signature_b64url":"' + encoded.encode('ascii') + b'","weights_hash":',
    )
    old_hash = 'sha256:' + hashlib.sha256(old_record_bytes).hexdigest()
    assert (archived.record_hash == old_hash) is compatible
