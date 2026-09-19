"""Reproduce the explicitly synthetic composition against immutable source pins."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import subprocess
import sys
from pathlib import Path

PINS = {
    'cmcp': '2cdb168ce52020406ff0ef6cbc34447f0ea55aee',
    'ca2a': 'fc22c644846111c7f375446399e9097a73f93214',
}


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cmcp-source', type=Path, required=True)
    parser.add_argument('--ca2a-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    sources = {'wcm': root, 'cmcp': args.cmcp_source.resolve(), 'ca2a': args.ca2a_source.resolve()}
    for name, pin in PINS.items():
        if git(sources[name], 'rev-parse', 'HEAD') != pin:
            raise SystemExit(f'{name}: source revision differs from reviewed pin')
        if git(sources[name], 'status', '--porcelain', '--untracked-files=no'):
            raise SystemExit(f'{name}: tracked source edits invalidate the pin')
    args.output.mkdir(parents=True, exist_ok=True)
    observations = args.output / 'observations.jsonl'
    if observations.exists():
        raise SystemExit('use a fresh output directory; evidence must not append to an old run')
    source_files = sorted((root / 'python/composed').glob('*.py'))
    manifest = {
        'profile': 'wcm-composed-software-v1',
        'claim': 'selected software admission gates prevent downstream delivery in the tested path',
        'evidence_class': 'synthetic-attestation/local-software',
        'sources': {name: git(path, 'rev-parse', 'HEAD') for name, path in sources.items()},
        'wcm_tracked_diff_sha256': hashlib.sha256(git(root, 'diff', 'HEAD').encode()).hexdigest(),
        'harness_files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files},
        'dependencies': sorted([{'name': d.metadata['Name'], 'version': d.version}
                                for d in importlib.metadata.distributions()], key=lambda d: d['name'].lower()),
        'policy': {'model': 'affine y=3x+2, input 7', 'tool': 'confidential ceiling',
                   'peer_scope': ['read'], 'release_recipient': 'recipient',
                   'release_purpose': 'review', 'policy_version': 'composition-v1'},
        'trust': 'test-generated SNP signing chain, owner signing key and local delegation root',
        'principals': ['synthetic owner', 'broker', 'workload', 'tool', 'delegated peer', 'recipient'],
        'limits': ['no hardware or protected-key custody', 'no OS egress confinement in this composed run',
                   'same host/operator; observers share test ownership', 'in-memory adapters and loopback HTTP',
                   'affine diagnostic model, not LLM execution', 'selected mutations only; not complete issue 199 acceptance',
                   'unreleased source pins; not a published integration', 'no secure erasure or trusted clock'],
    }
    env = dict(os.environ)
    env['PYTHONPATH'] = os.pathsep.join(str(p) for p in [root/'python', root/'python/src',
                                                        sources['cmcp']/'src', sources['ca2a']/'src'])
    env['COMPOSED_ROOTS'] = json.dumps({name: str(path) for name, path in sources.items()})
    env['COMPOSED_EVIDENCE'] = str(observations.resolve())
    command = [sys.executable, '-m', 'pytest', '-q', '-o', 'addopts=', 'composed/test_composed.py']
    manifest['command'] = ['python', *command[1:]]
    result = subprocess.run(command, cwd=root/'python', env=env, capture_output=True, text=True, check=False)
    manifest['exit_code'] = result.returncode
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    (args.output/'pytest.log').write_text(result.stdout+result.stderr,encoding='utf-8')
    print(result.stdout)
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
