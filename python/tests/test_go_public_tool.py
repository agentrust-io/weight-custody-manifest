"""Safety and payload tests for the guarded public cutover tool."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("go_public", ROOT / "tools/go_public.py")
assert SPEC and SPEC.loader
go_public = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(go_public)


def test_ruleset_requires_release_checks():
    payload = go_public.ruleset_payload(42)
    status_rule = next(r for r in payload["rules"] if r["type"] == "required_status_checks")
    contexts = {
        item["context"]
        for item in status_rule["parameters"]["required_status_checks"]
    }
    assert contexts == set(go_public.REQUIRED_CHECKS)
    assert payload["bypass_actors"] == [
        {"actor_id": 42, "actor_type": "User", "bypass_mode": "always"}
    ]


def test_local_preflight_passes_current_checkout():
    results = go_public.local_preflight(ROOT)
    assert results
    assert all(item["ok"] for item in results), results


def test_execute_refuses_non_main(monkeypatch):
    monkeypatch.setattr(
        go_public,
        "remote_preflight",
        lambda **_: {
            "repository": {"visibility": "PRIVATE"},
            "working_tree_clean": True,
            "branch": "feature",
        },
    )
    with pytest.raises(go_public.CutoverError, match="from main"):
        go_public.execute(runner=lambda *a, **k: None)


def test_execute_refuses_dirty_tree(monkeypatch):
    monkeypatch.setattr(
        go_public,
        "remote_preflight",
        lambda **_: {
            "repository": {"visibility": "PRIVATE"},
            "working_tree_clean": False,
            "branch": "main",
        },
    )
    with pytest.raises(go_public.CutoverError, match="clean"):
        go_public.execute(runner=lambda *a, **k: None)


def test_main_without_execute_is_read_only(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(go_public, "local_preflight", lambda root: [{"name": "ok", "ok": True}])
    monkeypatch.setattr(
        go_public,
        "remote_preflight",
        lambda: {
            "repository": {"visibility": "PRIVATE"},
            "working_tree_clean": True,
            "branch": "main",
        },
    )
    monkeypatch.setattr(go_public, "execute", lambda: calls.append("execute"))
    assert go_public.main([]) == 0
    assert calls == []
    assert "Read-only preflight complete" in capsys.readouterr().out


def test_main_requires_exact_confirmation(monkeypatch):
    monkeypatch.setattr(go_public, "local_preflight", lambda root: [{"name": "ok", "ok": True}])
    monkeypatch.setattr(
        go_public,
        "remote_preflight",
        lambda: {
            "repository": {"visibility": "PRIVATE"},
            "working_tree_clean": True,
            "branch": "main",
        },
    )
    with pytest.raises(go_public.CutoverError, match="refusing mutation"):
        go_public.main(["--execute", "--confirm", "wrong"])
