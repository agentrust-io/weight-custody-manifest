"""Optional cross-repository tests; invoked explicitly by composed-software CI."""
import hashlib
import json
import os
from pathlib import Path

import pytest
from composed.harness import compose, model_artifact
from tests.conftest import example_dict, example_manifest  # noqa: F401
from tests.test_broker_receiver import provision, workload_evidence
from tests.test_broker_receiver import setup as receiver_setup


@pytest.fixture(scope='session', autouse=True)
def verify_import_sources():
    import importlib
    if configured := os.environ.get('COMPOSED_ROOTS'):
        roots = json.loads(configured)
        for component, name in [('wcm', 'wcm.broker_receiver'),
                                ('cmcp', 'cmcp_runtime.disclosure'),
                                ('ca2a', 'ca2a_runtime.response')]:
            actual = Path(importlib.import_module(name).__file__).resolve()
            assert actual.is_relative_to(Path(roots[component]).resolve())
        if 'confinement' in roots:
            actual = Path(importlib.import_module('examples.confinement.adapter').__file__).resolve()
            assert actual.is_relative_to(Path(roots['confinement']).resolve())


@pytest.fixture
def prepared(example_manifest):  # noqa: F811 - pytest fixture injection
    tx, plain, artifact = model_artifact()
    example_manifest.weights_hash = 'sha256:' + hashlib.sha256(plain).hexdigest()
    return receiver_setup.__wrapped__(example_manifest), tx, artifact


def run(prepared, tmp_path, monkeypatch, fault='none'):
    setup, tx, artifact = prepared
    return compose(setup, artifact, tx, tmp_path, provision, workload_evidence,
                   monkeypatch, fault=fault)


def retain(result):
    if path := os.environ.get('COMPOSED_EVIDENCE'):
        public = {key: result[key] for key in ('transaction', 'fault', 'states', 'failure')}
        public['observations'] = {key: len(result[key]) for key in
                                  ('tool_receipts', 'peer_receipts', 'deliveries')}
        if 'confinement' in result:
            public['confinement'] = result['confinement']
        if 'mutation_target' in result:
            public['mutation_target'] = result['mutation_target']
        public['oracle'] = 'passed'
        public['expected'] = ('weakening changes the required boundary observation' if result['fault'].startswith('mutation-')
                              else 'unknown delivery, no retry' if result['fault'].startswith('timeout')
                              else 'one authorized delivery, replay refused' if result['fault'] == 'none'
                              else 'no final disclosure')
        if result['fault'].startswith('confined-'):
            public['expected'] = 'authorized final delivery and observed isolation' if result['fault'] == 'confined-positive' else 'weakened isolation is detected by an external sink'
        public['evidence_class'] = 'synthetic-attestation/local-software'
        with Path(path).open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(public) + '\n')


def test_composed_positive_and_durable_replay(prepared, tmp_path, monkeypatch):
    r = run(prepared, tmp_path, monkeypatch)
    assert r['failure'] is None, r['failure']
    assert all(value == 'established' for key, value in r['states'].items() if key != 'delivery')
    assert r['states']['delivery'] == 'acknowledged'
    assert len(r['tool_receipts']) == len(r['peer_receipts']) == len(r['deliveries']) == 1
    expected = {'transaction': r['transaction'], 'value': 23}
    assert json.loads(r['tool_receipts'][0]['arguments']['value']) == expected
    assert json.loads(r['peer_receipts'][0]) == expected
    assert json.loads(r['deliveries'][0]) == expected
    from cmcp_runtime.disclosure import ReplayStore
    r['gate']._store = ReplayStore(tmp_path / 'replay.sqlite')
    again = r['gate'].release(r['request'], r['approval'])
    assert again.disposition == 'denied'
    assert len(r['deliveries']) == 1
    retain(r)


@pytest.mark.parametrize('fault,stage,error,tools,peers', [
    ('workload', 'key_release', 'Refused', 0, 0),
    ('key', 'key_release', 'Refused', 0, 0),
    ('configuration', 'key_release', 'Refused', 0, 0),
    ('missing-evidence', 'key_release', 'Refused', 0, 0),
    ('model', 'model', 'InvalidTag', 0, 0),
    ('forbidden-tool', 'tool', 'Refused', 0, 0),
    ('transaction', 'tool', 'Refused', 1, 0),
    ('response', 'response', 'ResponseAuthenticationFailed', 1, 1),
    ('scope', 'peer', 'AuthenticatedPeerError', 1, 0),
    ('downgrade', 'peer', 'AttestationFailed', 1, 0),
    ('missing-approval', 'authorization', 'Refused', 1, 1),
    ('revoked', 'authorization', 'Refused', 1, 1),
    ('output', 'authorization', 'Refused', 1, 1),
])
def test_composed_refusal(prepared, tmp_path, monkeypatch, fault, stage, error, tools, peers):
    r = run(prepared, tmp_path, monkeypatch, fault)
    assert r['failure'] == error
    assert r['states'][stage] in {'contradicted', 'unavailable'}
    assert len(r['tool_receipts']) == tools
    assert len(r['peer_receipts']) == peers
    assert r['deliveries'] == []
    retain(r)


@pytest.mark.parametrize('fault,receipts', [('timeout', 1), ('timeout-before', 0)])
def test_ack_loss_preserves_unknown_and_consumption(prepared, tmp_path, monkeypatch, fault, receipts):
    r = run(prepared, tmp_path, monkeypatch, fault)
    assert r['failure'] is None
    assert r['states']['authorization'] == 'established'
    assert r['states']['delivery'] == 'unknown'
    assert len(r['deliveries']) == receipts  # Same unknown outcome, distinct actual receipt.
    assert r['gate'].release(r['request'], r['approval']).disposition == 'denied'
    assert len(r['deliveries']) == receipts
    retain(r)


@pytest.mark.parametrize('mutation,fault', [
    ('workload', 'workload'), ('sink', 'forbidden-tool'), ('mac', 'response'),
    ('output', 'output'), ('transaction', 'transaction'), ('replay', 'none'),
    ('key', 'key'), ('configuration', 'configuration'), ('missing-evidence', 'missing-evidence'),
    ('model', 'model'), ('scope', 'scope'), ('downgrade', 'downgrade'),
    ('missing-approval', 'missing-approval'), ('revoked', 'revoked'),
    ('timeout', 'timeout'), ('timeout-before', 'timeout-before'),
])
def test_gate_mutation_is_detected(prepared, tmp_path, monkeypatch, mutation, fault):
    """Weaken real gates in memory; require the intended no-delivery oracle to fail."""
    import base64
    import inspect
    import textwrap
    from dataclasses import replace

    from ca2a_runtime.policy import LocalPolicy
    from ca2a_runtime.response import PendingResponse
    from ca2a_runtime.transport import client
    from cmcp_runtime import disclosure
    from cmcp_runtime.sink_policy import SinkPolicy
    from composed import harness
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from wcm._quote_verify import QuoteVerifier
    from wcm.broker_receiver import _NativeWorkloadVerifier, parse_snp_report
    from wcm.kbs import CheckResult, KeyBrokerService

    def rewrite(target, attribute, needle, replacement):
        original = getattr(target, attribute)
        source = textwrap.dedent(inspect.getsource(original))
        assert source.count(needle) == 1
        scope = dict(original.__globals__)
        exec(source.replace(needle, replacement), scope)  # noqa: S102 - exact test-only source
        monkeypatch.setattr(target, attribute, scope[original.__name__])

    if mutation == 'workload':
        verify = _NativeWorkloadVerifier.verify

        def accept_measured(self, quote_b64, **kwargs):
            report = parse_snp_report(base64.b64decode(quote_b64))
            kwargs['expected_workload_measurement'] = 'sha256:' + hashlib.sha256(report.measurement).hexdigest()
            return verify(self, quote_b64, **kwargs)

        monkeypatch.setattr(_NativeWorkloadVerifier, 'verify', accept_measured)
    elif mutation == 'sink':
        monkeypatch.setattr(SinkPolicy, 'require', lambda *args, **kwargs: None)
    elif mutation == 'mac':
        original = PendingResponse.verify
        source = textwrap.dedent(inspect.getsource(original))
        needle = 'if not hmac.compare_digest(mac, _mac(key, envelope)):'
        assert needle in source
        scope = dict(original.__globals__)
        exec(source.replace(needle, 'if False:'), scope)  # noqa: S102 - fixed test-only source mutation
        monkeypatch.setattr(PendingResponse, 'verify', scope['verify'])
    elif mutation == 'output':
        original = disclosure._approval_input
        # Erase the exact-output commitment consistently from signer and verifier.
        def unbound(request, *args):
            return original(replace(request, payload=b''), *args)
        monkeypatch.setattr(disclosure, '_approval_input', unbound)
    elif mutation == 'transaction':
        monkeypatch.setattr(harness, 'require_transaction', lambda *args: None)
    elif mutation == 'key':
        rewrite(QuoteVerifier, 'verify', 'if actual != expected:', 'if False:')
    elif mutation == 'configuration':
        rewrite(KeyBrokerService, 'verify_and_release',
                'pinned = manifest_hash in self._trusted_manifest_identities', 'pinned = True')
    elif mutation == 'missing-evidence':
        check = KeyBrokerService._check_cpu_quote
        def allow_absent(self, evidence, nonce, binding):
            if evidence.cpu.quote_b64 is None:
                return CheckResult('cpu_quote_verified', True)
            return check(self, evidence, nonce, binding)
        monkeypatch.setattr(KeyBrokerService, '_check_cpu_quote', allow_absent)
    elif mutation == 'model':
        def unauthenticated(key, artifact, tx):
            # GCM update returns plaintext before tag authentication at finalize.
            decryptor = Cipher(algorithms.AES(key), modes.GCM(artifact[:12])).decryptor()
            decryptor.authenticate_additional_data(tx.encode())
            return decryptor.update(artifact[12:-16])
        monkeypatch.setattr(harness, 'decrypt_model', unauthenticated)
    elif mutation == 'scope':
        monkeypatch.setattr(LocalPolicy, 'intersect', lambda self, delegated: delegated)
    elif mutation == 'downgrade':
        rewrite(client, 'verify_offer', 'if require_hardware:', 'if False:')
    elif mutation == 'missing-approval':
        rewrite(disclosure.DisclosureGate, 'release', 'if not within:',
                'if not within and approval is not None:')
    elif mutation == 'revoked':
        rewrite(disclosure.DisclosureGate, 'release',
                "if (request.source_scope not in authority.source_scopes\n"
                "                or request.recipient not in authority.recipients\n"
                "                or request.purpose not in authority.purposes):",
                'if False:')
    elif mutation in {'timeout', 'timeout-before'}:
        rewrite(disclosure.DisclosureGate, 'release',
                'return ReleaseObservation(disposition, "delivery_unknown", "unknown")',
                'return ReleaseObservation(disposition, "adapter_acknowledged", "acknowledged")')
    else:
        monkeypatch.setattr(disclosure.ReplayStore, 'consume', lambda *args: True)
    r = run(prepared, tmp_path, monkeypatch, fault)
    assert r['failure'] is None, r['failure']
    assert len(r['deliveries']) == (0 if mutation == 'timeout-before' else 1)
    if mutation in {'timeout', 'timeout-before'}:
        assert r['states']['delivery'] == 'acknowledged'
        with pytest.raises(AssertionError):
            assert r['states']['delivery'] == 'unknown'
    elif mutation == 'replay':
        again = r['gate'].release(r['request'], r['approval'])
        assert again.delivery == 'acknowledged'
        with pytest.raises(AssertionError):
            assert len(r['deliveries']) == 1
    else:
        with pytest.raises(AssertionError):
            assert r['deliveries'] == []
    r['mutation_target'] = fault
    r['fault'] = 'mutation-' + mutation
    retain(r)
