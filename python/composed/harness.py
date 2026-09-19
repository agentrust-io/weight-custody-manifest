"""Source-pinned software composition; no hardware or agent isolation claim."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
from dataclasses import replace
from uuid import uuid4

from ca2a_runtime.delegation.credential import DelegationCredential, new_keypair
from ca2a_runtime.errors import CA2AError
from ca2a_runtime.node import PeerNode
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.transport import client, server
from cmcp_runtime.disclosure import (
    DisclosureGate,
    ReleaseAuthority,
    ReleaseRecipient,
    ReleaseRequest,
    ReplayStore,
    approve_exact_output,
)
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from wcm import open_sealed


class Refused(Exception):
    """An observed boundary refused; never include protected content."""


def model_artifact():
    """Nonsecret affine model; binds a fresh transaction into authenticated data."""
    tx = uuid4().hex
    plain = json.dumps({'transaction': tx, 'a': 3, 'b': 2}).encode()
    nonce = os.urandom(12)
    artifact = nonce + AESGCM(b'x' * 32).encrypt(nonce, plain, tx.encode())
    return tx, plain, artifact




def require_transaction(payload, tx):
    if json.loads(payload)['transaction'] != tx:
        raise Refused()


async def mediate(sink, payload, tool):
    from composed.gateway import make_gateway
    proxy, dispatch = make_gateway(sink)
    try:
        return await dispatch(tool, {'mode': 'echo', 'value': payload.decode()})
    finally:
        await proxy.aclose()


def delegate(payload, tx, observed, *, capability='read', hardware=False):
    root_key, root_pub = new_keypair()
    holder, holder_pub = new_keypair()
    chain = [DelegationCredential(credential_id=tx, issuer=root_pub,
             subject=holder_pub, scope=frozenset({'read', 'write'}), depth=0).sign(root_key)]

    class ObservedPeer(PeerNode):
        def handle(self, message):
            result = super().handle(message)
            observed.append(result.payload)
            return result

    node = ObservedPeer(LocalPolicy.of({'read'}), trusted_root_issuers={root_pub})
    http = server.serve(node, port=0)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        return client.send_task(f'http://127.0.0.1:{http.server_port}', chain,
                                capability, tx, holder_key=holder, payload=payload,
                                require_hardware=hardware, require_authenticated_response=True)
    finally:
        http.shutdown()
        http.server_close()
        thread.join(5)


def compose(setup, artifact, tx, root, provision, workload_evidence, monkeypatch,
            *, fault='none'):
    """Execute real component APIs; observers are distinct, not independent operators.

    The test owns synthetic signing roots. The trusted controller connects stages;
    its transaction checks are additional TCB, not a new interoperable protocol.
    """
    receiver, _, _, _, manifest, _, _, _ = setup
    states = dict.fromkeys(('provisioning', 'key_release', 'model', 'tool', 'peer',
                           'response', 'authorization', 'delivery'), 'unavailable')
    peer_receipts, deliveries = [], []
    sink = root / 'tool-private.jsonl'
    stage = 'provisioning'
    failure = None
    request = approval = gate = None
    try:
        provision(setup, monkeypatch)
        states[stage] = 'established'
        stage = 'key_release'
        kwargs = {'measurement': b'\x66' * 48} if fault == 'workload' else {}
        evidence, private = workload_evidence(setup, **kwargs)
        if fault == 'missing-evidence':
            evidence.cpu.quote_b64 = None
        if fault == 'key':
            from wcm import generate_transport_keypair
            evidence.cpu.transport_public_key = generate_transport_keypair()[1]
        if fault == 'configuration':
            manifest = manifest.model_copy(deep=True)
            manifest.weights_hash = 'sha256:' + '99' * 32
        decision = receiver.verify_and_release(manifest, evidence)
        if not decision.released:
            raise Refused()
        key = open_sealed(decision.sealed_key, private)
        states[stage] = 'established'
        stage = 'model'
        if fault == 'model':
            artifact = artifact[:-1] + bytes([artifact[-1] ^ 1])
        plain = AESGCM(key).decrypt(artifact[:12], artifact[12:], tx.encode())
        if 'sha256:' + hashlib.sha256(plain).hexdigest() != manifest.weights_hash:
            raise Refused()
        model = json.loads(plain)
        if model['transaction'] != tx:
            raise Refused()
        # Actual deterministic CPU computation; no model-serving framework or TEE.
        payload = json.dumps({'transaction': tx, 'value': model['a'] * 7 + model['b']}).encode()
        states[stage] = 'established'
        stage = 'tool'
        tool = 'public.tool' if fault == 'forbidden-tool' else 'permitted.tool'
        if fault == 'transaction':
            changed = json.loads(payload)
            changed['transaction'] = uuid4().hex
            payload = json.dumps(changed).encode()
        result = asyncio.run(mediate(sink, payload, tool))
        if not result['allowed']:
            raise Refused()
        # Use the actual tool return, not the controller's original input.
        returned = result['response'].encode()
        require_transaction(returned, tx)
        states[stage] = 'established'
        stage = 'peer'
        if fault == 'response':
            post = client._post_authenticated

            def changed_mac(url, raw):
                status, reply = post(url, raw)
                body = json.loads(reply)
                body['mac'] = '00' * 32
                return status, json.dumps(body).encode()

            monkeypatch.setattr(client, '_post_authenticated', changed_mac)
        result = delegate(returned, tx, peer_receipts,
                          capability='write' if fault == 'scope' else 'read',
                          hardware=fault == 'downgrade')
        states[stage] = 'established'
        stage = 'response'
        if result['record']['record_id'] != tx:
            raise Refused()
        if result['response_authentication']['audience'] != 'live-caller-only':
            raise Refused()
        states[stage] = 'established'
        stage = 'authorization'
        owner_key = Ed25519PrivateKey.generate()

        def deliver(data):
            if fault == 'timeout-before':
                raise TimeoutError('synthetic failure before receipt')
            deliveries.append(data)
            if fault == 'timeout':
                raise TimeoutError('synthetic lost acknowledgement')

        authority = ReleaseAuthority(owner_key.public_key(), frozenset({tx}),
                                     frozenset({'recipient'}), frozenset({'review'}))
        gate = DisclosureGate(policy_version='composition-v1', source_scopes=frozenset({tx}),
                sensitivity_order={'public': 0, 'confidential': 2},
                recipients={'recipient': ReleaseRecipient('public', 'external', deliver)},
                authorities={} if fault == 'revoked' else {'owner': authority},
                replay_store=ReplayStore(root / 'replay.sqlite'), now=lambda: 100)
        request = ReleaseRequest(returned, 'synthetic-workload', tx, ('confidential',),
                                 'recipient', 'review', 'composition-v1')
        approval = approve_exact_output(request, principal='owner', key=owner_key,
                                        not_before=90, expires_at=110)
        if fault == 'missing-approval':
            approval = None
        if fault == 'output':
            request = replace(request, payload=returned + b'!')
        outcome = gate.release(request, approval)
        if outcome.disposition != 'authorized_disclosure':
            raise Refused()
        states[stage] = 'established'
        states['delivery'] = 'unknown' if outcome.delivery == 'unknown' else 'acknowledged'
    except (Refused, InvalidTag, CA2AError) as exc:
        # Preserve the exception class for the oracle; unexpected errors cannot
        # satisfy a negative control merely because later stages did not run.
        failure = type(exc).__name__
        if stage == 'peer' and peer_receipts:
            states['peer'] = 'established'
            stage = 'response'
        states[stage] = 'contradicted' if isinstance(exc, Refused) else 'unavailable'
    finally:
        receiver.retire()
    observed_tools = [json.loads(line) for line in sink.read_text().splitlines()] if sink.exists() else []
    return {'transaction': tx, 'fault': fault, 'states': states, 'failure': failure,
            'tool_receipts': observed_tools, 'peer_receipts': peer_receipts,
            'deliveries': deliveries, 'gate': gate, 'request': request, 'approval': approval}
