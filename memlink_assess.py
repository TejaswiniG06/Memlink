"""Assess process instances from recorded Volatility runs, without malware verdicts."""
import argparse
import csv
import json
import ntpath
from collections import Counter, defaultdict
from pathlib import Path

from memlink_core import normalize_path


def artifact_pid(row):
    """Accept documented PID/Pid field variants without hiding contradictions."""
    values = []
    for field in ('PID', 'Pid'):
        value = row.get(field)
        if value is None:
            continue
        if isinstance(value, bool) or not str(value).isdecimal():
            raise ValueError(f'Invalid {field}: {value}')
        values.append(int(value))
    if len(set(values)) > 1:
        raise ValueError('Conflicting PID and Pid values')
    return values[0] if values else None


def flatten(rows):
    for row in rows:
        yield {k: v for k, v in row.items() if k != '__children'}
        yield from flatten(row.get('__children', []))


def relocate(path, path_map=None):
    """Translate a stored source path prefix (e.g. a drive letter) to where the file is now; hashes still verify content."""
    text = str(path)
    normalized = ntpath.normpath(text)
    for source, target in (path_map or []):
        prefix = ntpath.normpath(source).rstrip('\\')
        if normalized.casefold() == prefix.casefold():
            return Path(target)
        if normalized.casefold().startswith(prefix.casefold() + '\\'):
            return Path(target) / normalized[len(prefix) + 1:].replace('\\', '/')
    return Path(text)


def load_runs(roots, path_map=None):
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
                source = relocate(info['source_file'], path_map)
                if sha256(source) != info['sha256']:
                    raise ValueError(f'Artifact changed since extraction: {source}')
                tables[name] = list(flatten(json.loads(source.read_text(encoding='utf-8-sig'))))
                provenance[name] = str(source)
            else:
                tables.pop(name, None)
                provenance.pop(name, None)
    return tables, provenance, statuses


def _same_path(left, right, mappings):
    first, second = normalize_path(left, mappings), normalize_path(right, mappings)
    return first['resolved'] and second['resolved'] and first['normalized'] == second['normalized']


def _pid_instance_counts(tables):
    keys = set()
    for name in ('windows.pslist', 'windows.psscan'):
        for row in tables.get(name, []):
            keys.add((artifact_pid(row), row.get('CreateTime'), row.get('ImageFileName')))
    return Counter(key[0] for key in keys)


def loader_review(tables, provenance=None, mappings=None):
    """Review every ldrmodules row that has a loader flag other than True.

    Baselines B01 and B02 (rules/assessment.v1.draft.json) only explain one
    list-absence pattern, and only when the required context is verified. Every
    row is retained and no row becomes a verdict. Unmet checks are recorded.
    """
    provenance = provenance or {}
    vads = defaultdict(list)
    for row in tables.get('windows.vadinfo', []):
        pid, start = artifact_pid(row), row.get('Start VPN')
        if pid is not None and isinstance(start, int):
            vads[(pid, start)].append(row)
    mains, names = {}, {}
    for row in tables.get('windows.dlllist', []):
        mains.setdefault(artifact_pid(row), row)
    for name in ('windows.pslist', 'windows.psscan'):
        for row in tables.get(name, []):
            names.setdefault(artifact_pid(row), row.get('ImageFileName'))
    instances = _pid_instance_counts(tables)
    reviewed = []
    for number, row in enumerate(tables.get('windows.ldrmodules', []), 1):
        pid, base = artifact_pid(row), row.get('Base')
        flags = {key: row.get(key) for key in ('InLoad', 'InInit', 'InMem')}
        if all(value is True for value in flags.values()):
            continue
        pattern = (flags['InLoad'], flags['InInit'], flags['InMem'])
        matches = vads.get((pid, base), [])
        vad = matches[0] if len(matches) == 1 else None
        main = mains.get(pid)
        mapped = row.get('MappedPath')
        baseline, checks = None, {}
        if pattern == (True, False, True):
            candidate = 'B01'
            image = ntpath.basename(str(main.get('Path') or '')).casefold() if main else ''
            checks = {'single_process_instance_for_pid': instances.get(pid) == 1,
                      'base_equals_first_loaded_main_image': bool(main) and main.get('Base') == base,
                      'main_image_path_verified_against_mapped_path': bool(main) and _same_path(main.get('Path'), mapped, mappings),
                      'image_name_agrees_with_process_record': bool(image) and bool(names.get(pid)) and image.startswith(str(names[pid]).casefold())}
        elif pattern == (False, False, False):
            candidate = 'B02'
            protection = str(vad.get('Protection') or '').strip().upper() if vad else ''
            checks = {'single_process_instance_for_pid': instances.get(pid) == 1,
                      'single_vad_at_base': vad is not None,
                      'vad_file_equals_mapped_path': bool(vad) and bool(mapped) and str(vad.get('File') or '').casefold() == str(mapped).casefold(),
                      'vad_not_private_memory': bool(vad) and vad.get('PrivateMemory') == 0,
                      'vad_protection_recorded': bool(protection),
                      'vad_protection_without_execute': bool(protection) and 'EXECUTE' not in protection}
        else:
            candidate = None
            checks = {'baseline_defined_for_flag_pattern': False}
        if candidate and all(checks.values()):
            baseline = candidate
        reviewed.append({'pid': pid, 'process': row.get('Process'), 'base': base, 'mapped_path': mapped, 'flags': flags,
                         'vad_protection': vad.get('Protection') if vad else None,
                         'vad_private_memory': vad.get('PrivateMemory') if vad else None,
                         'vad_file': vad.get('File') if vad else None,
                         'baseline': baseline,
                         'verified_checks': sorted(k for k, ok in checks.items() if ok) if baseline else [],
                         'unmet_checks': sorted(k for k, ok in checks.items() if not ok),
                         'review_status': 'explained_by_baseline' if baseline else 'requires_context_review',
                         'baseline_effect': ('explains loader-list absence pattern only; the record and all other findings are retained' if baseline else None),
                         'source_reference': f"{provenance.get('windows.ldrmodules')}#flattened-row={number}"})
    return reviewed


def assess(tables, provenance, mappings=None):
    active = tables.get('windows.pslist', [])
    scanned = tables.get('windows.psscan', [])
    instances = {}
    for source, rows in [('windows.pslist', active), ('windows.psscan', scanned)]:
        for number, row in enumerate(rows, 1):
            key = (artifact_pid(row), row.get('CreateTime'), row.get('ImageFileName'))
            item = instances.setdefault(key, {'row': row, 'sources': []})
            item['sources'].append(f'{provenance[source]}#flattened-row={number};offset={row.get("Offset(V)", row.get("Offset(P)"))}')
            item[source] = True
    pid_instances = Counter(key[0] for key in instances)
    loader_rows = defaultdict(list)
    for entry in loader_review(tables, provenance, mappings):
        loader_rows[entry['pid']].append(entry)
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
        malfind = [r for r in tables.get('windows.malfind', []) if artifact_pid(r) == pid]
        flags = [r for r in tables.get('windows.ldrmodules', []) if artifact_pid(r) == pid and
                 any(r.get(k) is False for k in ('InLoad', 'InInit', 'InMem'))]
        commands = [r.get('Args', r.get('CommandLine')) for r in tables.get('windows.cmdline', []) if artifact_pid(r) == pid]
        region_review = []
        for region in malfind:
            start, end = region.get('Start VPN'), region.get('End VPN')
            matches = [v for v in tables.get('windows.vadinfo', []) if artifact_pid(v) == pid and
                       isinstance(start, int) and isinstance(end, int) and
                       isinstance(v.get('Start VPN'), int) and isinstance(v.get('End VPN'), int) and
                       v['Start VPN'] <= start and end <= v['End VPN']]
            region_review.append({'start': start, 'end': end, 'protection': region.get('Protection'),
                                  'vad_matches': len(matches),
                                  'backing_paths': [v.get('File') for v in matches if v.get('File')],
                                  'backing_status': 'file_path_reported' if any(v.get('File') for v in matches) else 'no_backing_path_reported' if matches else 'not_assessed_no_vad_match'})
        if malfind:
            reasons.append('malfind_flagged_regions_require_context')
        explained = [r for r in loader_rows.get(pid, []) if r['baseline']]
        unexplained = [r for r in loader_rows.get(pid, []) if not r['baseline']]
        if unexplained:
            reasons.append('loader_flags_require_context')
        parents = [r for r in active if artifact_pid(r) == row.get('PPID')]
        if not parents and row.get('PPID') not in (0, None):
            reasons.append('parent_unavailable; termination_or_capture_gap_possible')
        output.append({'pid': pid, 'process': name, 'create_time': created, 'exit_time': row.get('ExitTime'),
                       'ppid': row.get('PPID'), 'in_pslist': bool(item.get('windows.pslist')),
                       'in_psscan': bool(item.get('windows.psscan')), 'pid_instance_count': pid_instances[pid],
                       'malfind_protections': dict(Counter(r.get('Protection') for r in malfind)),
                       'malfind_vad_review': region_review,
                       'loader_flag_rows': len(flags), 'loader_rows_explained_by_baseline': len(explained),
                       'loader_rows_requiring_review': len(unexplained),
                       'loader_baselines_applied': sorted({r['baseline'] for r in explained}),
                       'command_lines': commands,
                       'assessment': 'needs_analyst_review' if reasons else 'no_flags_in_available_checks',
                       'analyst_verdict': 'not_reviewed', 'reasons': reasons, 'source_references': item['sources'],
                       'limitations': 'PID-bearing ancillary artifacts are observations, not certain instance ownership. Missing VAD backing paths do not prove file absence or malicious injection.'})
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', nargs='+', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--config', type=Path, help='Case configuration; its path_mappings enable verified path comparison')
    args = parser.parse_args()
    mappings = json.loads(args.config.read_text(encoding='utf-8-sig')).get('path_mappings') if args.config else None
    tables, sources, statuses = load_runs(args.runs)
    if not tables.get('windows.pslist'):
        raise ValueError('Valid nonempty pslist required for assessment')
    rows = assess(tables, sources, mappings)
    args.output.mkdir(parents=True, exist_ok=False)
    loader = loader_review(tables, sources, mappings)
    (args.output / 'loader_review.json').write_text(json.dumps({
        'path_mappings_used': mappings or {}, 'flagged_rows': len(loader),
        'explained_by_baseline': dict(Counter(r['baseline'] for r in loader if r['baseline'])),
        'requiring_context_review': sum(1 for r in loader if not r['baseline']),
        'rows': loader}, indent=2), encoding='utf-8')
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
