"""Publish a small index only after real-record collection validation succeeds."""
import argparse
import json
import ntpath
import sqlite3
from pathlib import Path


def publish(root,config_path):
    manifest=json.loads((root/'manifest.json').read_text())
    validation=json.loads((root/'validation.json').read_text())
    if validation['status']!='passed' or validation['sha256']!=manifest['sha256']:
        raise ValueError('Collection has not passed validation')
    config=json.loads(config_path.read_text())
    if config['host_id'] != manifest['host_id'] or config['case_id'] != manifest['case_id']:
        raise ValueError('Configuration identity does not match the collection')
    manifest['configuration']=config
    connection=sqlite3.connect((root/'source_snapshot.db').as_uri()+'?mode=ro',uri=True)
    connection.row_factory=sqlite3.Row
    manifest['disk_image_metadata']=[dict(row) for row in connection.execute('select * from tsk_image_info')]
    manifest['disk_segment_references']=[dict(row) for row in connection.execute('select * from tsk_image_names')]
    names={ntpath.normpath(row['name']).casefold() for row in manifest['disk_segment_references']}
    if ntpath.normpath(config['disk_image']).casefold() not in names or len(manifest['disk_image_metadata'])!=1:
        raise ValueError('Disk source identity does not match the selected single-host configuration')
    connection.close()
    manifest['timezone_note']='Autopsy image timezone is analyst display configuration, not verified victim timezone. Original UTC/raw values retained.'
    (root/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    (root/'normalization_config.json').write_text(json.dumps(config,indent=2),encoding='utf-8')
    lines=[f"# Unified {config['host_id']} evidence collection",'',
           f"**{manifest['total_records']:,} normalized artifact observations. Validation: passed.**",'',
           'Main file: [evidence.jsonl](evidence.jsonl). One JSON object per artifact observation.',
           'Supporting files: [manifest](manifest.json), [validation](validation.json), [configuration](normalization_config.json).','',
           '| Source | Records |','|---|---:|']
    lines += [f'| {key} | {count:,} |' for key,count in manifest['counts'].items()]
    lines += ['', '## Meaning of completeness','',
              'All selected successful memory exports, all filesystem rows and all parsed artifacts in the database snapshot, plus the selected registry-service export. Zero rejected records.',
              'This does not claim exhaustive recovery from the original images. Windows event-log entries, scheduled-task definitions and full NTFS SI/FN pairs have not yet been parsed into this collection.',
              'Duplicate observations, process remnants and deleted entries remain traceable; record counts are not counts of unique files or malicious findings.',
              'Validation checks schema, source counts and integrity on real evidence. It does not measure malware-detection accuracy.', '',
              'A read-only source snapshot is retained as `source_snapshot.db`. The original images and case database were not modified.',
              '', 'SHA-256: `'+manifest['sha256']+'`.']
    if not (root/'README.md').exists():
        with (root/'README.md').open('x',encoding='utf-8') as target:target.write('\n'.join(lines)+'\n')
    print(f"Published {manifest['total_records']:,} verified records: {root/'evidence.jsonl'}")


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('collection',type=Path);parser.add_argument('config',type=Path)
    args=parser.parse_args();publish(args.collection,args.config)
