"""The same full software path, with an adversarial agent at the tool boundary."""
import os

import pytest
from composed.confined import confined_mediator, require_isolation
from composed.harness import compose
from composed.test_composed import prepared, retain, verify_import_sources  # noqa: F401
from tests.conftest import example_dict, example_manifest  # noqa: F401
from tests.test_broker_receiver import provision, workload_evidence

pytestmark = pytest.mark.skipif(not os.environ.get('COMPOSED_AGENT_IMAGE'),
                               reason='requires the explicit native-Linux composed profile')


@pytest.mark.parametrize('mutation', [None, 'network', 'filesystem', 'logging'])
def test_confined_composition(prepared, tmp_path, monkeypatch, mutation):  # noqa: F811
    setup, tx, artifact = prepared
    observed = {}
    result = compose(setup, artifact, tx, tmp_path, provision, workload_evidence, monkeypatch,
                     mediator=confined_mediator(monkeypatch, observed, mutation))
    assert result['failure'] is None
    assert result['states']['delivery'] == 'acknowledged'
    assert len(result['tool_receipts']) == len(result['peer_receipts']) == len(result['deliveries']) == 1
    assert observed['stats']['allowed'] == observed['stats']['denied'] == 1
    assert observed['stats']['stderr_bytes'] > 0
    assert not observed['running']
    if mutation is None:
        require_isolation(observed)
    else:
        if mutation == 'network':
            assert observed['network'] == {'tcp': 1, 'tcp6': 1, 'udp': 1}
        elif mutation == 'filesystem':
            assert observed['file']
        else:
            assert observed['logs']
        with pytest.raises(AssertionError):
            require_isolation(observed)
    result['fault'] = 'confined-' + (mutation or 'positive')
    result['confinement'] = observed
    retain(result)
