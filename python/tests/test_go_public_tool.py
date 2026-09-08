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


@pytest.mark.parametrize("exists", [False, True])
def test_pages_uses_published_branch_and_custom_domain(exists):
    import json
    calls = []

    def runner(args, **kwargs):
        calls.append((args, kwargs))
        if args == ["gh", "api", f"repos/{go_public.REPOSITORY}/pages"]:
            return SimpleNamespace(returncode=0 if exists else 1,
                                   stdout="{}" if exists else "",
                                   stderr="" if exists else "gh: Not Found (HTTP 404)")
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    go_public.configure_pages(runner=runner)
    writes = [(args[3], json.loads(kw["input_text"]))
              for args, kw in calls if "--method" in args]
    expected_source = {"branch": "gh-pages", "path": "/"}
    if not exists:
        assert writes[0] == ("POST", {"build_type": "legacy", "source": expected_source})
    assert writes[-1] == ("PUT", {"build_type": "legacy", "source": expected_source,
                                  "cname": "wcm.agentrust-io.com"})
    assert len(writes) == (1 if exists else 2)


def test_pages_read_failure_does_not_create_or_update():
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=1, stdout="", stderr="gh: Forbidden (HTTP 403)")

    with pytest.raises(go_public.CutoverError, match="403"):
        go_public.configure_pages(runner=runner)
    assert len(calls) == 1



def test_execute_configures_pages(monkeypatch):
    calls = []
    monkeypatch.setattr(go_public, "remote_preflight", lambda **_: {
        "repository": {"visibility": "PRIVATE"}, "working_tree_clean": True, "branch": "main"})
    monkeypatch.setattr(go_public, "gh_json", lambda args, **_: 42 if "user" in args else [])
    monkeypatch.setattr(go_public, "api", lambda *a, **k: None)
    monkeypatch.setattr(go_public, "configure_pages", lambda **_: calls.append("pages"))
    go_public.execute(runner=lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""))
    assert calls == ["pages"]
