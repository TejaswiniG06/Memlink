"""MemLink Phase 1: one reproducible command from verified DC01 exports to ranked, adjudicated findings.

    python -B memlink_run.py --run-config <phase1_run.json> --output <new folder>

Order of work (fails closed before any result is written if an input check fails):
  1. verify input identity   - case/host/snapshot/image hash agree; plugin outputs, the normalized
                               collection and the thread export match their recorded hashes
  2. verify timestamps       - capture time and time zone basis present, every event/process time parses,
                               future-dated and inverted times are listed
  3. analyse + rank          - memlink_rank (spec, baselines, predicates, family accounting, tiers)
  4. verify review gating    - every satisfied review-dependent predicate has a status=reviewed entry
  5. verify determinism      - analysis repeated, input order reversed: identical ranked output required
  6. validate adjudications  - memlink_adjudicate (every cited record re-opened, policy limits)
Mode is always 'development'; freezing is a separate step (memlink_freeze.py).
"""
import argparse
import hashlib
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import memlink_adjudicate as adj
import memlink_rank as rk
from memlink_assess import relocate

REVIEW_KEYS = {'A01.2_': 'reviewed_malicious_content', 'A03.1_': 'payload_structure',
               'A03.2_': 'injection_payload_evidence', 'A05.1_': 'survives_review'}
REQUIRED_PLUGINS = ('windows.pslist', 'windows.psscan')


class Checks:
    def __init__(self):
        self.items = []

    def add(self, name, status, detail):
        self.items.append({'check': name, 'status': status, 'detail': detail})

    @property
    def failed(self):
        return [c for c in self.items if c['status'] == 'fail']


def load_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def hash_and_count(path):
    digest, lines = hashlib.sha256(), 0
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(8 << 20), b''):
            digest.update(block)
            lines += block.count(b'\n')
    return digest.hexdigest(), lines


def verify_identity(run, config, path_map, checks):
    roots = [relocate(p, path_map) for p in run['memory_runs']]
    for root in roots:
        manifest = load_json(root / 'manifest.json')
        wanted = {'case_id': config['case_id'], 'host_id': config['host_id'], 'snapshot_id': config['snapshot_id'],
                  'image_sha256': config['memory_sha256']}
        mismatch = {k: (manifest.get(k), v) for k, v in wanted.items() if manifest.get(k) != v}
        checks.add('memory run identity %s' % root.name, 'fail' if mismatch else 'pass',
                   'case/host/snapshot/image hash differ from config: %s' % mismatch if mismatch else
                   'case, host, snapshot and image SHA-256 equal the case configuration')
        bad = {k: v['status'] for k, v in manifest['plugins'].items() if v['status'] not in ('success', 'success_empty')}
        missing = [p for p in REQUIRED_PLUGINS if manifest['plugins'].get(p, {}).get('status') not in ('success', 'success_empty')
                   and not any(p in load_json(r / 'manifest.json')['plugins'] for r in roots)]
        checks.add('extraction status %s' % root.name, 'warn' if bad else 'pass',
                   'non-success plugins (not negative findings): %s' % bad if bad else 'all recorded plugins succeeded')
    names = {p for r in roots for p in load_json(r / 'manifest.json')['plugins']}
    checks.add('required plugins present', 'fail' if any(p not in names for p in REQUIRED_PLUGINS) else 'pass', sorted(names))
    manifest = load_json(relocate(run['disk_evidence_manifest'], path_map))
    started = time.time()
    digest, lines = hash_and_count(relocate(run['disk_evidence'], path_map))
    ok = digest == manifest.get('sha256') and lines == manifest.get('total_records')
    checks.add('normalized collection hash and record count', 'pass' if ok else 'fail',
               {'sha256': digest, 'records': lines, 'manifest_sha256': manifest.get('sha256'), 'manifest_records': manifest.get('total_records'),
                'seconds': round(time.time() - started, 1)})
    events = [json.loads(l) for l in relocate(run['service_events'], path_map).read_text(encoding='utf-8-sig').splitlines() if l.strip()]
    foreign = [e.get('host_id') for e in events if e.get('host_id') != config['host_id']]
    checks.add('service events host identity', 'fail' if foreign else 'pass',
               '%d events; historical Computer names preserved, host_id equals %s' % (len(events), config['host_id']))
    threads_path = relocate(run['threads'], path_map)
    entries = load_json(relocate(run['threads_run_manifest'], path_map))
    entry = next((e for e in entries if e.get('plugin') == 'windows.threads'), None)
    image = None
    if entry:
        command = entry.get('command') or []
        image = command[command.index('-f') + 1] if '-f' in command else None
    same_image = image is not None and image.replace('\\', '/').casefold() == str(config['memory_image']).replace('\\', '/').casefold()
    threads_hash = rk.sha256_file(threads_path)
    ok = bool(entry) and entry.get('sha256') == threads_hash and same_image
    checks.add('thread export identity', 'pass' if ok else 'fail',
               {'output_sha256_matches_run_manifest': bool(entry) and entry.get('sha256') == threads_hash,
                'extracted_from_configured_image_path': same_image,
                'strength': 'path recorded in run manifest; image hash is verified through the memory run manifests'})
    spec = load_json(relocate(run['spec'], path_map))
    frozen = 'frozen' in str(spec.get('status', '')).lower() and 'not_frozen' not in str(spec.get('status', '')).lower()
    checks.add('specification status', 'fail' if frozen else 'pass',
               'spec status %r; this command only produces development runs' % spec.get('status'))
    return roots


def verify_timestamps(config, analysis, checks):
    capture = analysis['capture']
    checks.add('capture time and time-zone basis', 'pass' if capture and config.get('verified_timezone_configuration') else 'fail',
               {'memory_capture_utc': config.get('memory_capture_utc'), 'timezone_basis': config.get('verified_timezone_configuration')})
    unparsable = [e['record_id'] for e in analysis['events'] if rk.parse_time(e['utc']) is None]
    future = [e['record_id'] for e in analysis['events'] if rk.parse_time(e['utc']) and capture and (rk.parse_time(e['utc']) - capture).total_seconds() >= 1]
    checks.add('service event timestamps', 'fail' if unparsable else ('warn' if future else 'pass'),
               {'events': len(analysis['events']), 'unparsable': unparsable, 'after_capture_by_1s_or_more': future,
                'note': '7-digit fractional seconds parse on any Python version'})
    bad_parse, inverted, after = [], [], []
    for name in ('windows.pslist', 'windows.psscan'):
        for row in analysis['tables'].get(name, []):
            created, exited = row.get('CreateTime'), row.get('ExitTime')
            c, x = rk.parse_time(created), rk.parse_time(exited)
            if (created and c is None) or (exited and x is None):
                bad_parse.append((name, row.get('PID')))
            elif c and x and x < c:
                inverted.append((name, row.get('PID')))
            elif c and capture and c > capture:
                after.append((name, row.get('PID')))
    checks.add('process timestamps', 'fail' if bad_parse else ('warn' if inverted or after else 'pass'),
               {'unparsable': bad_parse, 'exit_before_create': inverted, 'created_after_capture': after})


def predicate_gate(ranked, reviews, checks):
    violations = []
    for finding in ranked:
        for name, state in finding.predicates.items():
            key = next((v for p, v in REVIEW_KEYS.items() if name.startswith(p)), None)
            if key and state['satisfied'] and not rk.reviewed(reviews, finding.subject, key):
                if not (name.startswith('A03.1_') and state['satisfied'] and rk.reviewed(reviews, finding.subject, key)):
                    violations.append((finding.id, name))
    statuses = Counter(r.get('status') for r in reviews)
    checks.add('review gating', 'fail' if violations else 'pass',
               {'reviews_supplied': len(reviews), 'review_status_counts': dict(statuses),
                'satisfied_review_dependent_predicates_without_reviewed_entry': violations})


def canonical(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, ensure_ascii=False).encode('utf-8')).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Verify inputs, rank, adjudicate; development mode only.')
    parser.add_argument('--run-config', required=True)
    parser.add_argument('--output', required=True, help='new folder; must not exist')
    parser.add_argument('--path-map', action='append', default=[], metavar='SRC=DST')
    args = parser.parse_args(argv)
    run = load_json(args.run_config)
    path_map = [tuple(item.split('=', 1)) for item in args.path_map]
    config = load_json(relocate(run['config'], path_map))
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    checks = Checks()
    started = datetime.now(timezone.utc)
    try:
        roots = verify_identity(run, config, path_map, checks)
        inputs = dict(runs=[str(r) for r in roots], spec_path=str(relocate(run['spec'], path_map)),
                      service_events=str(relocate(run['service_events'], path_map)), threads_path=str(relocate(run['threads'], path_map)),
                      disk_evidence=str(relocate(run['disk_evidence'], path_map)))
        reviews = load_json(relocate(run['reviews'], path_map)) if run.get('reviews') else []
        if checks.failed:
            raise ValueError('input identity checks failed')
        first = rk.analyze(config=config, reviews=reviews, path_map=path_map, **inputs)
        verify_timestamps(config, first, checks)
        predicate_gate(first['ranked'], reviews, checks)
        rows_a = [f.as_dict() for f in first['ranked']]
        second = rk.analyze(config=config, reviews=reviews, path_map=path_map, **inputs)
        rows_b = [f.as_dict() for f in second['ranked']]
        shuffled = rk.rank(list(reversed(first['findings'])))
        same_order = [f.id for f in shuffled] == [f.id for f in first['ranked']]
        deterministic = canonical(rows_a) == canonical(rows_b) and same_order
        checks.add('deterministic ranking', 'pass' if deterministic else 'fail',
                   {'repeat_run_identical': canonical(rows_a) == canonical(rows_b), 'input_order_independent': same_order,
                    'ranked_content_sha256': canonical(rows_a)})
        if checks.failed:
            raise ValueError('verification failed')
        doc = load_json(relocate(run['adjudications'], path_map)) if run.get('adjudications') else {'entries': []}
        maps = path_map
        results, unassessed, doc_errors = adj.adjudicate(rows_a, doc, str(Path.cwd()), maps)
        again, _, _ = adj.adjudicate(rows_b, doc, str(Path.cwd()), maps)
        adjudication_same = canonical(results) == canonical(again)
        invalid = [r['finding_id'] for r in results if r['validation_errors']]
        checks.add('adjudication validation', 'fail' if (invalid or doc_errors or unassessed or not adjudication_same) else 'pass',
                   {'findings': len(results), 'unassessed': unassessed, 'document_errors': doc_errors, 'invalid_entries': invalid,
                    'repeat_identical': adjudication_same})
        metadata = {'run_mode': 'development', 'frozen': False, 'specification_version': first['spec'].version,
                    'specification_status': first['spec'].status, 'run_utc': started.isoformat(),
                    'extraction_statuses': first['statuses'], 'memory_capture_utc': config.get('memory_capture_utc'),
                    'reviews_supplied': len(reviews), 'relevant_groups_assumption': {k: sorted(v) for k, v in rk.RELEVANT_GROUPS.items()},
                    'code_sha256': {n: rk.sha256_file(Path(__file__).with_name(n)) for n in
                                    ('memlink_run.py', 'memlink_rank.py', 'memlink_assess.py', 'memlink_core.py', 'memlink_adjudicate.py')}}
        rk.write_outputs(output / 'ranking', first['ranked'], first['spec'], dict(metadata), rk.NOT_EVALUABLE)
        meta = {'mode': 'development', 'frozen': False, 'ranked_sha256': rk.sha256_file(output / 'ranking' / 'ranked_findings.json'),
                'adjudications_sha256': rk.sha256_file(relocate(run['adjudications'], path_map)) if run.get('adjudications') else None,
                'code_sha256': adj.__file__ and rk.sha256_file(Path(adj.__file__))}
        meta = adj.write_outputs(output / 'adjudication', results, unassessed, doc_errors, meta)
        adj.write_report(output / 'adjudication', rows_a, results, meta)
        (output / 'loader_review.json').write_text(json.dumps(first['loader_rows'], indent=2, default=str), encoding='utf-8')
        summary = {'tier_counts': dict(Counter(f.tier() for f in first['ranked'])), 'findings': len(first['ranked']),
                   'verdicts_unique_conclusions': meta['verdict_counts_unique_conclusions']}
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        checks.add('run aborted', 'fail', str(error))
        summary = None
    report = {'mode': 'development', 'frozen': False, 'started_utc': started.isoformat(), 'overall': 'fail' if checks.failed else 'pass',
              'checks': checks.items, 'summary': summary}
    (output / 'verification_report.json').write_text(json.dumps(report, indent=2, default=str), encoding='utf-8')
    yara_file = None
    if run.get('yara_matches') and not checks.failed:
        yara_file = relocate(run['yara_matches'], path_map)
        yara = load_json(yara_file)
        rules_hash = rk.sha256_file(relocate(run['yara_rules'], path_map))
        unverified = yara['summary']['unverified_matches']
        ok = yara['summary']['rules_sha256'] == rules_hash and unverified == 0
        checks.add('yara metadata', 'pass' if ok else 'warn',
                   {'rules_file_hash_matches': yara['summary']['rules_sha256'] == rules_hash, 'verified_matches': yara['summary']['verified_matches'],
                    'unverified_matches_not_used': unverified, 'used_for': 'corroboration display only; never tier, predicate or verdict'})
        (output / 'verification_report.json').write_text(json.dumps(dict(report, checks=checks.items), indent=2, default=str), encoding='utf-8')
    if run.get('traces') and not checks.failed:
        import memlink_dashboard as dash
        data = dash.build_data(output, relocate(run['traces'], path_map), str(Path.cwd()), path_map, yara_file)
        (output / 'dashboard.html').write_text(dash.render(data), encoding='utf-8')
        print('dashboard written: %s (%d findings, %d traces)' % (output / 'dashboard.html', len(data['findings']), len(data['traces'])))
    for item in checks.items:
        print('[%s] %s' % (item['status'].upper(), item['check']))
    if summary:
        print('findings %(findings)d; tiers %(tier_counts)s; unique conclusions %(verdicts_unique_conclusions)s' % summary)
    print('overall: %s -> %s' % (report['overall'], output))
    return 1 if checks.failed else 0


if __name__ == '__main__':
    sys.exit(main())
