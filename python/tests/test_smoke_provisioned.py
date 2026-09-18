"""Startup transport failures are retryable; provisioning POST failures are not."""
from http.client import RemoteDisconnected
import importlib.util
from pathlib import Path
from urllib.error import URLError

import pytest

DOCKER = Path(__file__).resolve().parents[1] / "docker"
pytestmark = pytest.mark.skipif(not DOCKER.is_dir(), reason="image tools require repository checkout")


@pytest.fixture
def smoke():
    path = DOCKER / "smoke_provisioned.py"
    spec = importlib.util.spec_from_file_location("smoke_provisioned_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("error", [ConnectionResetError("reset"), RemoteDisconnected("closed"),
                                   URLError("not yet listening"), TimeoutError("timeout")])
def test_startup_transport_failure_then_success(smoke, monkeypatch, capsys, error):
    calls = []
    def request(base, path, payload=None):
        calls.append(path)
        if len(calls) == 1:
            raise error
        if path == "/health":
            return 200, {"status": "ok"}
        if path == "/challenge":
            return 409, {}
        return 503, {"detail": "native SNP attestation unavailable"}
    monkeypatch.setattr(smoke, "request", request)
    monkeypatch.setattr(smoke.time, "sleep", lambda _: None)
    smoke.check("http://127.0.0.1:8081")
    assert calls == ["/health", "/health", "/challenge", "/provisioning/report", "/challenge"]
    assert "PASS:" in capsys.readouterr().out


def test_startup_deadline_expires_without_pass(smoke, monkeypatch, capsys):
    calls = []
    clock = iter([0.0, 31.0])
    def request(base, path, payload=None):
        calls.append(path)
        raise ConnectionResetError("still starting")
    monkeypatch.setattr(smoke, "request", request)
    monkeypatch.setattr(smoke.time, "monotonic", lambda: next(clock))
    with pytest.raises(RuntimeError, match="failed to start"):
        smoke.check("http://127.0.0.1:8081")
    assert calls == ["/health"]
    assert "PASS:" not in capsys.readouterr().out


@pytest.mark.parametrize("failed_path", ["/challenge", "/provisioning/report"])
def test_post_network_error_is_not_retried(smoke, monkeypatch, capsys, failed_path):
    calls = []
    def request(base, path, payload=None):
        calls.append(path)
        if path == failed_path:
            raise ConnectionResetError("post response lost")
        return (200, {"status": "ok"}) if path == "/health" else (409, {})
    monkeypatch.setattr(smoke, "request", request)
    with pytest.raises(ConnectionResetError):
        smoke.check("http://127.0.0.1:8081")
    assert calls.count(failed_path) == 1
    assert "PASS:" not in capsys.readouterr().out
