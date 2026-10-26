"""Export memory module path observations with PID and source references."""
import argparse
import csv
import json
import re
from pathlib import Path
from memlink_assess import load_runs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('runs', nargs='+', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    tables, sources, statuses = load_runs(args.runs)
    identity = statuses['identity']
    if tuple(config[k] for k in ('case_id', 'host_id', 'snapshot_id')) != identity[:3]:
        raise ValueError('Configured case identity differs from extraction')
    processes = {}
    for row in tables.get('windows.pslist', []):
        processes.setdefault(row['PID'], []).append(row)
    fields = ['case_id', 'host_id', 'snapshot_id', 'evidence_kind', 'artifact_type',
              'source_file', 'source_record', 'path', 'pid', 'process_create_time',
              'timestamp', 'timestamp_semantics', 'process_name', 'ownership_status',
              'service_name', 'service_state', 'service_start', 'raw_binary', 'raw', 'source_tool']
    with args.output.open('x', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for number, row in enumerate(tables.get('windows.dlllist', []), 1):
            matches = processes.get(row.get('PID'), [])
            if not row.get('Path'):
                continue
            writer.writerow(dict(case_id=identity[0], host_id=identity[1], snapshot_id=identity[2],
                evidence_kind='memory', artifact_type='loaded_module',
                source_file=sources['windows.dlllist'], source_record=f'flattened-row={number};base={row.get("Base")}',
                path=row['Path'], pid=row.get('PID'), process_name=row.get('Process'),
                process_create_time=matches[0].get('CreateTime') if len(matches)==1 else '',
                timestamp=row.get('LoadTime') or '', timestamp_semantics='module_load_time',
                raw=json.dumps(row), source_tool='volatility.dlllist',
                ownership_status='pid_bearing_module_observation; process_instance_requires_review'))
        for number, row in enumerate(tables.get('windows.svcscan', []), 1):
            binary = row.get('Binary (Registry)') or row.get('Binary') or ''
            match = re.match(r'^(?:"([^\"]+\.exe)"|(.+?\.exe))(?:\s|$)', binary, re.I)
            if not match:
                continue
            path = match.group(1) or match.group(2)
            # Unquoted executable paths containing spaces can resolve ambiguously.
            if not match.group(1) and ' ' in path:
                continue
            writer.writerow(dict(case_id=identity[0], host_id=identity[1], snapshot_id=identity[2],
                evidence_kind='memory', artifact_type='service_configuration_in_memory',
                source_file=sources['windows.svcscan'], source_record=f'flattened-row={number};offset={row.get("Offset")}',
                path=path, pid=row.get('PID'), service_name=row.get('Name'),
                service_state=row.get('State'), service_start=row.get('Start'), raw_binary=binary,
                raw=json.dumps(row), source_tool='volatility.svcscan',
                ownership_status='service_configuration_observation; not_proof_of_process_execution'))


if __name__ == '__main__':
    main()
