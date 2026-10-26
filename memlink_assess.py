"""Assess process instances from recorded Volatility runs, without malware verdicts."""
import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


def flatten(rows):
    for row in rows:
        yield {k: v for k, v in row.items() if k != '__children'}
        yield from flatten(row.get('__children', []))


def load_runs(roots):
    tables, provenance, statuses = {}, {}, {}
    for root in roots:
        manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
        identity = tuple(manifest[k] for k in ('case_id', 'host_id', 'snapshot_id', 'image_sha256'))
        if statuses and identity != statuses['identity']:
            raise ValueError('Cannot combine runs from different evidence identities')
        statuses['identity'] = identity
        for name, info in manifest['plugins'].items():
            statuses[name] = info['status']
            if info['status'] in ('success', 'success_empty'):
                from memlink_pipeline import sha256
                source = Path(info['source_file'])
                if sha256(source) != info['sha256']:
                    raise ValueError(f'Artifact changed since extraction: {source}')
                tables[name] = list(flatten(json.loads(source.read_text(encoding='utf-8-sig'))))
                provenance[name] = str(source)
            else:
                tables.pop(name, None)
                provenance.pop(name, None)
    return tables, provenance, statuses


def assess(tables, provenance):
    active = tables.get('windows.pslist', [])
    scanned = tables.get('windows.psscan', [])
    instances = {}
    for source, rows in [('windows.pslist', active), ('windows.psscan', scanned)]:
        for number, row in enumerate(rows, 1):
            key = (row.get('PID'), row.get('CreateTime'), row.get('ImageFileName'))
            item = instances.setdefault(key, {'row': row, 'sources': []})
            item['sources'].append(f'{provenance[source]}#flattened-row={number};offset={row.get("Offset(V)", row.get("Offset(P)"))}')
            item[source] = True
    pid_instances = Counter(key[0] for key in instances)
    output = []
    for (pid, created, name), item in instances.items():
        reasons = []
        row = item['row']
        if not item.get('windows.pslist'):
            reasons.append('scan_only_exited_object' if row.get('ExitTime') else 'scan_only_object_activity_unresolved')
        if row.get('ExitTime') and item.get('windows.pslist'):
            reasons.append('exit_recorded_in_listed_object')
        if pid_instances[pid] > 1:
            reasons.append('multiple_process_instances_share_pid; ancillary_PID_joins_ambiguous')
        malfind = [r for r in tables.get('windows.malfind', []) if r.get('PID') == pid]
        flags = [r for r in tables.get('windows.ldrmodules', []) if r.get('PID') == pid and
                 any(r.get(k) is False for k in ('InLoad', 'InInit', 'InMem'))]
        commands = [r.get('Args', r.get('CommandLine')) for r in tables.get('windows.cmdline', []) if r.get('PID') == pid]
        region_review = []
        for region in malfind:
            start, end = region.get('Start VPN'), region.get('End VPN')
            matches = [v for v in tables.get('windows.vadinfo', []) if v.get('PID') == pid and
                       isinstance(start, int) and isinstance(end, int) and
                       isinstance(v.get('Start VPN'), int) and isinstance(v.get('End VPN'), int) and
                       v['Start VPN'] <= start and end <= v['End VPN']]
            region_review.append({'start': start, 'end': end, 'protection': region.get('Protection'),
                                  'vad_matches': len(matches),
                                  'backing_paths': [v.get('File') for v in matches if v.get('File')],
                                  'backing_status': 'file_path_reported' if any(v.get('File') for v in matches) else 'no_backing_path_reported' if matches else 'not_assessed_no_vad_match'})
        if malfind:
            reasons.append('malfind_flagged_regions_require_context')
        if flags:
            reasons.append('loader_flags_require_context')
        parents = [r for r in active if r.get('PID') == row.get('PPID')]
        if not parents and row.get('PPID') not in (0, None):
            reasons.append('parent_unavailable; termination_or_capture_gap_possible')
        output.append({'pid': pid, 'process': name, 'create_time': created, 'exit_time': row.get('ExitTime'),
                       'ppid': row.get('PPID'), 'in_pslist': bool(item.get('windows.pslist')),
                       'in_psscan': bool(item.get('windows.psscan')), 'pid_instance_count': pid_instances[pid],
                       'malfind_protections': dict(Counter(r.get('Protection') for r in malfind)),
                       'malfind_vad_review': region_review,
                       'loader_flag_rows': len(flags), 'command_lines': commands,
                       'assessment': 'needs_analyst_review' if reasons else 'no_flags_in_available_checks',
                       'analyst_verdict': 'not_reviewed', 'reasons': reasons, 'source_references': item['sources'],
                       'limitations': 'PID-bearing ancillary artifacts are observations, not certain instance ownership. Missing VAD backing paths do not prove file absence or malicious injection.'})
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', nargs='+', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    tables, sources, statuses = load_runs(args.runs)
    if not tables.get('windows.pslist'):
        raise ValueError('Valid nonempty pslist required for assessment')
    rows = assess(tables, sources)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'process_assessment.json').write_text(json.dumps({'input_statuses': statuses, 'processes': rows}, indent=2), encoding='utf-8')
    listed = {(r.get('Base'), r.get('Size'), r.get('Name')) for r in tables.get('windows.modules', [])}
    drivers = [dict(row, assessment='scan_only_module_review; unloaded_or_residual_possible')
               for row in tables.get('windows.modscan', [])
               if (row.get('Base'), row.get('Size'), row.get('Name')) not in listed]
    (args.output / 'driver_review.json').write_text(json.dumps({
        'status': 'assessed' if 'windows.modules' in tables and 'windows.modscan' in tables else 'not_assessed_missing_artifacts',
        'source_files': {k:v for k,v in sources.items() if k in ('windows.modules', 'windows.modscan')},
        'scan_only_records': drivers if 'windows.modules' in tables else []}, indent=2), encoding='utf-8')
    with (args.output / 'process_assessment.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows({k: json.dumps(v) if isinstance(v, (dict, list)) else v for k,v in row.items()} for row in rows)
    print(f'{len(rows)} process instances assessed; analyst verdicts pending')


if __name__ == '__main__':
    main()
