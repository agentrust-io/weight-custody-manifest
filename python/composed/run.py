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
    parser.add_argument('--confinement-source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    sources = {'wcm': root, 'cmcp': args.cmcp_source.resolve(), 'ca2a': args.ca2a_source.resolve()}
    pins = dict(PINS)
    if args.confinement_source:
        sources['confinement'] = args.confinement_source.resolve()
        pins['confinement'] = 'bad751becca0ec5c42d70062e5c9fe5ee1380e85'
        if not os.environ.get('COMPOSED_AGENT_IMAGE'):
            raise SystemExit('confined profile requires a built image ID')
    for name, pin in pins.items():
        if git(sources[name], 'rev-parse', 'HEAD') != pin:
            raise SystemExit(f'{name}: source revision differs from reviewed pin')
        if git(sources[name], 'status', '--porcelain', '--untracked-files=no'):
            raise SystemExit(f'{name}: tracked source edits invalidate the pin')
    args.output.mkdir(parents=True, exist_ok=True)
    observations = args.output / 'observations.jsonl'
    if observations.exists():
        raise SystemExit('use a fresh output directory; evidence must not append to an old run')
    source_files = sorted((root / 'python/composed').glob('*.py')) + [root / 'python/composed/Dockerfile']
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
                   'affine diagnostic model, not LLM execution', 'mutation coverage is scoped to named scenarios; not complete issue 199 acceptance',
                   'unreleased source pins; not a published integration', 'no secure erasure or trusted clock'],
    }
    env = dict(os.environ)
    env['PYTHONPATH'] = os.pathsep.join(str(p) for p in [root/'python', root/'python/src',
                                                        sources['cmcp']/'src', sources['ca2a']/'src'])
    if args.confinement_source:
        env['PYTHONPATH'] += os.pathsep + str(sources['confinement'])
        manifest['confinement_image'] = env['COMPOSED_AGENT_IMAGE']
        manifest['limits'].remove('no OS egress confinement in this composed run')
        manifest['limits'].append('selected agent egress probes only; host, broker, tool and peer remain trusted')
    env['COMPOSED_ROOTS'] = json.dumps({name: str(path) for name, path in sources.items()})
    env['COMPOSED_EVIDENCE'] = str(observations.resolve())
    command = [sys.executable, '-m', 'pytest', '-q', '-o', 'addopts=', 'composed/test_composed.py']
    if args.confinement_source:
        command.append('composed/test_confined.py')
    manifest['command'] = ['python', *command[1:]]
    result = subprocess.run(command, cwd=root/'python', env=env, capture_output=True, text=True, check=False)
    code = result.returncode
    if code == 0:
        rows = [json.loads(line) for line in observations.read_text().splitlines()]
        normal = {row['fault'] for row in rows if not row['fault'].startswith(('mutation-', 'confined-'))}
        targeted = {row['mutation_target'] for row in rows if row['fault'].startswith('mutation-')}
        manifest['mutation_targets'] = sorted(targeted)
        manifest['untargeted_cases'] = sorted(normal - targeted)
        if normal != targeted:
            code = 1  # A new named software case cannot silently lack its causal control.
    manifest['exit_code'] = code
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    (args.output/'pytest.log').write_text(result.stdout+result.stderr,encoding='utf-8')
    print(result.stdout)
    return code


if __name__ == '__main__':
    sys.exit(main())
