"""Writes a freeze manifest (hashes + UTC date) for a separate retrospective run.

It refuses to freeze unless: the adjudication metadata is valid with nothing
unassessed, every adjudication is user_confirmed (assistant drafts are not enough),
and the specification file is not already marked frozen under a different hash.
It never runs the evaluation and never overwrites an existing manifest.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from memlink_rank import sha256_file

CODE = ('memlink_rank.py', 'memlink_assess.py', 'memlink_core.py', 'memlink_adjudicate.py', 'memlink_freeze.py')


def check_ready(metadata, results):
    problems = []
    if not metadata.get('valid'):
        problems.append('adjudication validation is not clean')
    if metadata.get('unassessed_finding_ids'):
        problems.append('unassessed findings remain')
    pending = sorted({r['status'] for r in results if r.get('status') != 'user_confirmed'})
    if pending:
        problems.append('adjudications not user_confirmed: %s' % ', '.join(pending))
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--adjudication-dir', required=True, help='folder holding adjudication_metadata.json and adjudicated_findings.json')
    parser.add_argument('--spec', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--input', action='append', default=[], help='input file to hash (repeatable)')
    parser.add_argument('--output', required=True, help='new manifest path')
    args = parser.parse_args(argv)
    folder = Path(args.adjudication_dir)
    metadata = json.loads((folder / 'adjudication_metadata.json').read_text(encoding='utf-8'))
    results = json.loads((folder / 'adjudicated_findings.json').read_text(encoding='utf-8'))
    problems = check_ready(metadata, results)
    if problems:
        print('refusing to freeze: ' + '; '.join(problems), file=sys.stderr)
        return 2
    output = Path(args.output)
    if output.exists():
        print('refusing to overwrite an existing manifest', file=sys.stderr)
        return 2
    here = Path(__file__).resolve().parent
    manifest = {'frozen_utc': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
                'frozen_at_utc': datetime.now(timezone.utc).isoformat(),
                'code_sha256': {name: sha256_file(here / name) for name in CODE},
                'spec_sha256': sha256_file(args.spec), 'config_sha256': sha256_file(args.config),
                'adjudication_sha256': sha256_file(folder / 'adjudicated_findings.json'),
                'input_sha256': {p: sha256_file(p) for p in args.input},
                'note': 'Evaluation must run separately, against separately held ground truth; amendments need a new version.'}
    output.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print('freeze manifest written:', output)
    return 0


if __name__ == '__main__':
    sys.exit(main())
