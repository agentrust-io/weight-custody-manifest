#!/usr/bin/env python3
"""Guarded WCM public-repository cutover.

The default mode is read-only and prints a preflight report. Mutation requires
both ``--execute`` and an exact repository-specific confirmation string. This
tool intentionally does not change DNS, edit package metadata, publish a package,
or create a release.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable


REPOSITORY = "agentrust-io/weight-custody-manifest"
CONFIRMATION = f"{REPOSITORY}:PUBLIC"
HOMEPAGE = "https://wcm.agentrust-io.com"
REQUIRED_CHECKS = ("test (3.11)", "test (3.12)", "test (3.13)", "packaging")
TEAM_PERMISSIONS = {
    "opaque-lt": "admin",
    "agentrust-io-partners": "pull",
    "agentrust-io-collaborators": "pull",
}


class CutoverError(RuntimeError):
    """A precondition or GitHub operation failed."""


def command(
    args: list[str], *, input_text: str | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise CutoverError(f"{' '.join(args)} failed: {detail}")
    return result


def gh_json(args: list[str], *, runner: Callable[..., Any] = command) -> Any:
    result = runner(["gh", *args])
    return json.loads(result.stdout)


def ruleset_payload(user_id: int) -> dict[str, Any]:
    return {
        "name": "protect-default-branch",
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [
            {
                "actor_id": user_id,
                "actor_type": "User",
                "bypass_mode": "always",
            }
        ],
        "conditions": {
            "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}
        },
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": True,
                    "require_last_push_approval": True,
                    "required_review_thread_resolution": True,
                    "allowed_merge_methods": ["merge", "squash", "rebase"],
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": False,
                    "required_status_checks": [
                        {"context": context} for context in REQUIRED_CHECKS
                    ],
                },
            },
        ],
    }


def local_preflight(root: Path) -> list[dict[str, Any]]:
    checks: list[tuple[str, bool, str]] = []
    required = (
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "PUBLIC-RELEASE.md",
        "GOVERNANCE.md",
        "MAINTAINERS.md",
        "CODE_OF_CONDUCT.md",
        ".github/CODEOWNERS",
        ".github/workflows/python.yml",
        ".github/workflows/docs.yml",
        "CNAME",
        "python/pyproject.toml",
    )
    for relative in required:
        checks.append((f"file:{relative}", (root / relative).is_file(), "required"))

    workflow = (root / ".github/workflows/python.yml").read_text(encoding="utf-8")
    pull_request_block = workflow.split("pull_request:", 1)[1].split("permissions:", 1)[0]
    checks.append(
        (
            "required-checks-run-on-every-pr",
            "paths:" not in pull_request_block and "paths-ignore:" not in pull_request_block,
            "python workflow must not path-filter required PR checks",
        )
    )
    pyproject = (root / "python/pyproject.toml").read_text(encoding="utf-8")
    # Accept either the served docs site or the repository URL. The repository
    # URL 404s for an anonymous reader until the visibility flip, so requiring it
    # here forced the tree to carry a dead link for the whole pre-flip period, and
    # any release cut in that window shipped it. v0.26.0 did. Restoring the
    # repository URL is the cutover's job, not a precondition of it: execute()
    # already passes --homepage HOMEPAGE to gh repo edit in the same call that
    # makes the repository public, so the two cannot drift apart.
    checks.append(
        (
            "package-homepage",
            f'Homepage = "{HOMEPAGE}"' in pyproject
            or f'Homepage = "https://github.com/{REPOSITORY}"' in pyproject,
            "package metadata Homepage must be the docs site (pre-flip) or the repository (post-flip)",
        )
    )
    checks.append(
        (
            "package-documentation",
            'Documentation = "https://wcm.agentrust-io.com"' in pyproject,
            "package metadata must point at the documentation site",
        )
    )
    checks.append(
        (
            "cname",
            (root / "CNAME").read_text(encoding="utf-8").strip()
            == "wcm.agentrust-io.com",
            "expected docs domain",
        )
    )
    return [{"name": n, "ok": ok, "detail": detail} for n, ok, detail in checks]


def remote_preflight(*, runner: Callable[..., Any] = command) -> dict[str, Any]:
    repo = gh_json(
        [
            "repo",
            "view",
            REPOSITORY,
            "--json",
            "visibility,defaultBranchRef,homepageUrl,url",
        ],
        runner=runner,
    )
    status = runner(["git", "status", "--porcelain"])
    branch = runner(["git", "branch", "--show-current"])
    return {
        "repository": repo,
        "working_tree_clean": not status.stdout.strip(),
        "branch": branch.stdout.strip(),
    }


def api(
    method: str,
    endpoint: str,
    payload: dict[str, Any] | None = None,
    *,
    runner: Callable[..., Any] = command,
) -> None:
    args = ["gh", "api", "--method", method, endpoint]
    input_text = None
    if payload is not None:
        args.extend(["--input", "-"])
        input_text = json.dumps(payload)
    runner(args, input_text=input_text)


def execute(*, runner: Callable[..., Any] = command) -> None:
    before = remote_preflight(runner=runner)
    if before["repository"]["visibility"].upper() != "PRIVATE":
        raise CutoverError("repository must be private at cutover start")
    if not before["working_tree_clean"]:
        raise CutoverError("working tree must be clean")
    if before["branch"] != "main":
        raise CutoverError("cutover must run from main")

    runner(
        [
            "gh",
            "repo",
            "edit",
            REPOSITORY,
            "--visibility",
            "public",
            "--accept-visibility-change-consequences",
            "--homepage",
            HOMEPAGE,
        ]
    )

    user_id = int(gh_json(["api", "user", "--jq", ".id"], runner=runner))
    rulesets = gh_json(["api", f"repos/{REPOSITORY}/rulesets"], runner=runner)
    if not any(item.get("name") == "protect-default-branch" for item in rulesets):
        api(
            "POST",
            f"repos/{REPOSITORY}/rulesets",
            ruleset_payload(user_id),
            runner=runner,
        )

    api(
        "PATCH",
        f"repos/{REPOSITORY}",
        {
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"},
            }
        },
        runner=runner,
    )
    api("PUT", f"repos/{REPOSITORY}/private-vulnerability-reporting", runner=runner)
    for team, permission in TEAM_PERMISSIONS.items():
        api(
            "PUT",
            f"orgs/agentrust-io/teams/{team}/repos/{REPOSITORY}",
            {"permission": permission},
            runner=runner,
        )

    # Pages may already exist because docs deploy to gh-pages. POST returns 422
    # when it exists, so only create it after a read reports 404.
    pages = runner(
        ["gh", "api", f"repos/{REPOSITORY}/pages"], check=False
    )
    if pages.returncode == 1 and "404" in pages.stderr:
        api(
            "POST",
            f"repos/{REPOSITORY}/pages",
            {"build_type": "workflow"},
            runner=runner,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="perform the cutover")
    parser.add_argument("--confirm", default="", help="exact cutover confirmation")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)

    local = local_preflight(args.root)
    remote = remote_preflight()
    report = {"mode": "execute" if args.execute else "preflight", "local": local, **remote}
    print(json.dumps(report, indent=2))

    failures = [item for item in local if not item["ok"]]
    if failures:
        raise CutoverError("local preflight failed")
    if args.execute:
        if args.confirm != CONFIRMATION:
            raise CutoverError(
                f"refusing mutation: pass --confirm {CONFIRMATION!r} exactly"
            )
        execute()
        print("Cutover operations completed. Run this tool again for post-state output.")
    else:
        print(f"Read-only preflight complete. Future confirmation token: {CONFIRMATION}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CutoverError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
