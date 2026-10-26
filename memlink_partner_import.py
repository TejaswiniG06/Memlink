"""Import Team Schrodinger findings without changing their verdict or confidence."""
import argparse
import csv
import json
from pathlib import Path


REQUIRED = {'finding_id', 'case_id', 'host_id', 'source_file', 'source_record',
            'path', 'method', 'confidence', 'verdict'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('findings', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    with args.findings.open(encoding='utf-8-sig', newline='') as source:
        reader = csv.DictReader(source)
        if not REQUIRED <= set(reader.fieldnames or []):
            raise ValueError(f'Missing partner fields: {sorted(REQUIRED-set(reader.fieldnames or []))}')
        rows = list(reader)
    records, seen = [], set()
    for row in rows:
        if (row['case_id'], row['host_id']) != (config['case_id'], config['host_id']):
            raise ValueError('Partner finding has different case/host identity')
        key = (row['source_file'], row['source_record'], row['finding_id'])
        if key in seen:
            raise ValueError('Duplicate partner finding: ' + row['finding_id'])
        seen.add(key)
        record = dict(row)
        record.update(evidence_kind='disk', artifact_type='partner_finding',
                      snapshot_id=row.get('snapshot_id') or config['disk_snapshot_id'],
                      finding_origin='Team Schrodinger',
                      imported_verdict_status='original_partner_verdict_not_independently_validated')
        records.append(record)
    fields = list(dict.fromkeys(k for row in records for k in row))
    if not fields:
        fields = sorted(REQUIRED) + ['evidence_kind', 'artifact_type', 'snapshot_id']
    with args.output.open('x', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)
    print(f'{len(records)} partner findings imported; original fields retained')


if __name__ == '__main__':
    main()
