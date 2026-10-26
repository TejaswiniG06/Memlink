"""Ingest a documented RegRipper services CSV section from Autopsy output."""
import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path


HEADER = 'Time,Name,DisplayName,ImagePath/ServiceDll,Type,Start,ObjectName'


def service_rows(text):
    active = False
    for number, line in enumerate(text.splitlines(), 1):
        if line.strip() == HEADER:
            active = True
            continue
        if not active:
            continue
        if not line.strip() or line.startswith('---'):
            active = False
            continue
        row = next(csv.reader([line]))
        if len(row) < 7:
            continue
        try:
            stamp = datetime.strptime(row[0], '%a %b %d %H:%M:%S %Y Z').replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
        yield number, row, stamp, line


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('export', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--hive-source-reference', required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    fields = ['case_id', 'host_id', 'snapshot_id', 'artifact_type', 'evidence_kind', 'source_file',
              'source_record', 'path', 'timestamp', 'timestamp_semantics', 'service_name',
              'service_start', 'service_account', 'service_type', 'raw_record', 'hive_source_reference']
    with args.output.open('x', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        count = 0
        for number, row, stamp, raw in service_rows(args.export.read_text(encoding='utf-8-sig', errors='replace')):
            writer.writerow(dict(case_id=config['case_id'], host_id=config['host_id'],
                snapshot_id=config['disk_snapshot_id'], artifact_type='registry_service_configuration',
                evidence_kind='disk', source_file=str(args.export.resolve()), source_record=f'line={number}',
                path=row[3], timestamp=stamp, timestamp_semantics='service_key_last_write_not_install_or_execution_time',
                service_name=row[1], service_start=row[5], service_account=row[6], service_type=row[4],
                raw_record=raw, hive_source_reference=args.hive_source_reference))
            count += 1
    if count == 0:
        raise ValueError('No recognized service rows; source format may differ or extraction may have failed')
    print(f'{count} disk registry service records exported')
