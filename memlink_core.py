"""Conservative shared records and explainable memory/disk linking."""
import argparse
import csv
import hashlib
import html
import json
import ntpath
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def normalize_path(value, mappings=None):
    original = str(value or '').strip()
    path = original.replace('/', '\\')
    if path.startswith('\\??\\'):
        path = path[4:]
    if path.startswith('\\\\?\\') and not path.lower().startswith('\\\\?\\unc\\'):
        path = path[4:]
    for source, target in sorted((mappings or {}).items(), key=lambda x: -len(x[0])):
        if path.casefold() == source.casefold() or path.casefold().startswith(source.casefold() + '\\'):
            path = target + path[len(source):]
            break
    absolute = bool(re.match(r'^[A-Za-z]:\\', path) or path.startswith('\\\\'))
    # Device paths and environment variables require a host-specific mapping.
    if not absolute or '%' in path or path.startswith('\\\\?\\'):
        return {'original': original, 'normalized': path.lower(), 'resolved': False}
    return {'original': original, 'normalized': ntpath.normpath(path).lower(), 'resolved': True}


def normalize_time(value):
    text = str(value or '').strip()
    try:
        stamp = datetime.fromisoformat(text.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            return {'original': text, 'utc': None, 'status': 'timezone_unknown'}
        return {'original': text, 'utc': stamp.astimezone(timezone.utc).isoformat(), 'status': 'known'}
    except ValueError:
        return {'original': text, 'utc': None, 'status': 'missing' if not text else 'invalid'}


def normalize_record(row, config):
    row = dict(row)
    if row.get('source_layer'):
        row['evidence_kind'] = row['source_layer']
        row['timestamp'] = row.get('event_time')
    required = ('case_id', 'host_id', 'snapshot_id', 'artifact_type', 'source_file', 'source_record')
    if any(not str(row.get(k, '')).strip() for k in required):
        raise ValueError('Each record needs ' + ', '.join(required))
    if row['case_id'] != config['case_id'] or row['host_id'] != config['host_id']:
        raise ValueError('Record case/host differs from selected configuration')
    if row.get('evidence_kind') not in ('memory', 'disk'):
        raise ValueError('evidence_kind must be memory or disk')
    result = dict(row)
    result['path_info'] = normalize_path(row.get('path'), config.get('path_mappings'))
    result['time_info'] = normalize_time(row.get('timestamp'))
    result['process_time_info'] = normalize_time(row.get('process_create_time'))
    result['sha256'] = str(row.get('sha256') or '').strip().casefold()
    if result['sha256'] and not re.fullmatch(r'[0-9a-f]{64}', result['sha256']):
        raise ValueError('Invalid SHA-256')
    result['md5'] = str(row.get('md5') or '').strip().lower()
    if result['md5'] and not re.fullmatch(r'[0-9a-f]{32}', result['md5']):
        raise ValueError('Invalid MD5')
    result['record_id'] = row.get('artifact_id') or hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()[:24]
    return result


def correlate(records, window_seconds=300):
    memory = [r for r in records if r.get('evidence_kind') == 'memory']
    disk = [r for r in records if r.get('evidence_kind') == 'disk']
    indexes = {key: defaultdict(list) for key in ('hash', 'md5', 'path', 'name')}
    for index, row in enumerate(disk):
        if row.get('sha256'):
            indexes['hash'][row['sha256']].append(index)
        if row.get('md5'):
            indexes['md5'][row['md5']].append(index)
        path = row['path_info']
        if path['resolved']:
            indexes['path'][path['normalized']].append(index)
        if path['normalized']:
            indexes['name'][ntpath.basename(path['normalized'])].append(index)
    links = []
    for left in memory:
        path = left['path_info']
        candidates = set(indexes['hash'].get(left.get('sha256'), []))
        candidates.update(indexes['md5'].get(left.get('md5'), []))
        candidates.update(indexes['path'].get(path['normalized'], []))
        if path['normalized']:
            candidates.update(indexes['name'].get(ntpath.basename(path['normalized']), []))
        for index in sorted(candidates):
            right = disk[index]
            if (left['case_id'], left['host_id']) != (right['case_id'], right['host_id']):
                continue
            lp, rp = left['path_info'], right['path_info']
            same_hash = bool(left.get('sha256') and left['sha256'] == right.get('sha256'))
            same_md5 = bool(left.get('md5') and left['md5'] == right.get('md5'))
            hash_conflict = bool((left.get('sha256') and right.get('sha256') and not same_hash) or
                                 (left.get('md5') and right.get('md5') and not same_md5))
            full_path = lp['resolved'] and rp['resolved'] and lp['normalized'] == rp['normalized']
            basename = bool(lp['normalized'] and rp['normalized'] and
                            ntpath.basename(lp['normalized']) == ntpath.basename(rp['normalized']))
            if not (same_hash or same_md5 or full_path or basename):
                continue
            reasons, limits = [], []
            if same_hash:
                reasons.append('equal_sha256')
            if same_md5:
                reasons.append('equal_md5')
                limits.append('MD5 is a legacy content identifier; corroborate with SHA-256 where possible.')
            if full_path:
                reasons.append('equal_resolved_full_path')
            if not same_hash and not same_md5 and not full_path:
                reasons.append('basename_only')
                limits.append('Basename is not a unique file identity.')
            if hash_conflict:
                limits.append('Different hashes: these records do not establish the same file content.')
            lt, rt = left['time_info']['utc'], right['time_info']['utc']
            delta = abs((datetime.fromisoformat(lt) - datetime.fromisoformat(rt)).total_seconds()) if lt and rt else None
            if delta is not None and delta <= window_seconds:
                reasons.append('timestamps_within_window')
            else:
                limits.append('Temporal proximity is unavailable or outside the selected window.')
            if left.get('user') and right.get('user') and left['user'].casefold() == right['user'].casefold():
                reasons.append('equal_user')
            if left.get('service_name') and right.get('service_name') and left['service_name'].casefold() == right['service_name'].casefold():
                reasons.append('equal_service_name')
            # PID never establishes a cross-evidence link; creation time is only supporting evidence.
            if (left.get('pid') and left.get('pid') == right.get('pid') and
                left['snapshot_id'] == right['snapshot_id'] and
                left['process_time_info']['utc'] and
                left['process_time_info']['utc'] == right['process_time_info']['utc']):
                reasons.append('same_snapshot_process_identity')
            limits.append('Capture gap and artifact timestamp semantics require analyst review.')
            if right.get('artifact_type') == 'filesystem_metadata':
                limits.append('Disk metadata may describe deleted or residual entries; inspect allocation flags and source records.')
            if left.get('artifact_type') == 'filescan':
                limits.append('Memory file object does not prove process ownership or disk presence.')
            strength = 'strong' if same_hash or same_md5 else 'moderate' if full_path else 'weak'
            if hash_conflict:
                strength = 'weak'
            links.append({'memory_record': left['record_id'], 'disk_record': right['record_id'],
                          'rules': reasons, 'strength': strength, 'limitations': limits,
                          'time_delta_seconds': delta, 'maliciousness': 'not_assessed'})
    return links


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('records', type=Path, help='Documented common-schema CSV export')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding='utf-8'))
    with args.records.open(encoding='utf-8-sig', newline='') as stream:
        incoming = (json.loads(line) for line in stream if line.strip()) if args.records.suffix == '.jsonl' else csv.DictReader(stream)
        records = [normalize_record(row, config) for row in incoming]
    links = correlate(records)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'report_metadata.json').write_text(json.dumps({
        'case_id': config['case_id'], 'host_id': config['host_id'],
        'host_identity_status': config.get('host_identity_status', 'unknown'),
        'capture_gap_status': config.get('capture_gap_status', 'unknown'),
        'path_mapping_basis': config.get('path_mapping_basis', 'unknown'),
        'input_records': str(args.records.resolve()),
        'real_case_validation': 'not_completed',
        'attack_reconstruction': 'not_performed'}, indent=2), encoding='utf-8')
    (args.output / 'records.json').write_text(json.dumps(records, indent=2), encoding='utf-8')
    (args.output / 'correlations.json').write_text(json.dumps(links, indent=2), encoding='utf-8')
    timeline = sorted([{'record_id': r['record_id'], 'utc': r['time_info']['utc'],
                        'timestamp_original': r['time_info']['original'],
                        'semantics': r.get('timestamp_semantics', 'unspecified'),
                        'evidence_kind': r['evidence_kind'], 'artifact_type': r['artifact_type'],
                        'path': r.get('path', ''), 'source_file': r['source_file'],
                        'source_record': r['source_record']} for r in records if r['time_info']['utc']],
                      key=lambda r: (r['utc'], r['record_id']))
    with (args.output / 'evidence_timeline.csv').open('w', newline='', encoding='utf-8') as stream:
        fields = ['record_id', 'utc', 'timestamp_original', 'semantics', 'evidence_kind', 'artifact_type', 'path', 'source_file', 'source_record']
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(timeline)
    with (args.output / 'correlations.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=['memory_record', 'disk_record', 'rules', 'strength', 'limitations', 'time_delta_seconds', 'maliciousness'])
        writer.writeheader()
        writer.writerows({k: json.dumps(v) if isinstance(v, list) else v for k,v in link.items()} for link in links)
    lookup = {r['record_id']:r for r in records}
    table = []
    ranked = sorted(links, key=lambda link: {'strong':0, 'moderate':1, 'weak':2}[link['strength']])
    for link in ranked[:500]:
        left, right = lookup[link['memory_record']], lookup[link['disk_record']]
        values = [link['strength'], left.get('path', ''), right.get('path', ''),
                  '; '.join(link['rules']), left['source_record'], right['source_record'],
                  '; '.join(link['limitations'])]
        table.append('<tr>' + ''.join('<td>' + html.escape(str(v)) + '</td>' for v in values) + '</tr>')
    page = ('<!doctype html><html lang="en"><meta charset="utf-8"><title>MemLink correlations</title>'
            '<style>body{font:15px system-ui;margin:32px;color:#182438}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccd3dd;padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eaf0f7}.note{padding:16px;background:#fff4d6}a{color:#124f99}</style>'
            '<h1>MemLink evidence correlations</h1><p>' + html.escape(config['case_id'] + ' / ' + config['host_id']) + '</p>'
            '<p class="note">Preliminary candidate links. Maliciousness is not assessed. Host identity: ' + html.escape(config.get('host_identity_status', 'unknown')) +
            '. Capture gap: ' + html.escape(config.get('capture_gap_status', 'unknown')) + '. No ATT&amp;CK reconstruction or solution-based validation has been completed.</p>'
            f'<p>{len(records):,} input records; {len(links):,} candidate links. Showing the first {min(500,len(links)):,}. Complete results are in CSV and JSON.</p>'
            '<p><a href="correlations.csv">Correlation CSV</a> · <a href="correlations.json">Correlation JSON</a> · <a href="evidence_timeline.csv">Evidence timeline</a> · <a href="report_metadata.json">Provenance and limitations</a></p>'
            '<p>The evidence timeline retains timestamp semantics; file modification time is not execution time.</p>'
            '<table><thead><tr><th>Strength</th><th>Memory path</th><th>Disk path</th><th>Rules</th><th>Memory record</th><th>Disk record</th><th>Limitations</th></tr></thead><tbody>' + ''.join(table) + '</tbody></table></html>')
    (args.output / 'report.html').write_text(page, encoding='utf-8')
    print(f'{len(records)} records; {len(links)} candidate links')


if __name__ == '__main__':
    main()
