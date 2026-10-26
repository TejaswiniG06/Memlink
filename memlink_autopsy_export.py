"""Read-only export of Autopsy SQLite filesystem metadata to the shared schema.

This consumes forensic-tool output, not raw disk images. Filesystem timestamps
are not claimed to be complete NTFS SI/FN timestamp pairs.
"""
import argparse
import csv
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


FIELDS = ['case_id', 'host_id', 'snapshot_id', 'artifact_type', 'evidence_kind',
          'source_file', 'source_record', 'path', 'sha256', 'user', 'pid',
          'timestamp', 'timestamp_semantics', 'process_create_time', 'original_path',
          'fs_obj_id', 'meta_addr', 'meta_seq', 'size', 'mtime', 'atime', 'ctime',
          'crtime', 'dir_flags', 'meta_flags', 'ingest_status', 'path_mapping_status', 'md5', 'raw', 'source_tool']


def export(database, config, output, ingest_status):
    snapshot_id = config.get('disk_snapshot_id')
    if not isinstance(snapshot_id, str) or not snapshot_id.strip():
        raise ValueError('disk_snapshot_id must identify the disk acquisition in the configuration')
    output.mkdir(parents=True, exist_ok=False)
    connection = sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute('BEGIN')
    rows = connection.execute('SELECT * FROM tsk_files ORDER BY obj_id')
    count = 0
    with (output / 'filesystem.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            original = (row['parent_path'] or '') + row['name']
            mount = config.get('autopsy_fs_mounts', {}).get(str(row['fs_obj_id']))
            path = mount.rstrip('\\/') + '\\' + original.lstrip('/').replace('/', '\\') if mount else original
            stamp = datetime.fromtimestamp(row['mtime'], timezone.utc).isoformat() if row['mtime'] else ''
            record = {k: row[k] for k in ('fs_obj_id', 'meta_addr', 'meta_seq', 'size', 'mtime', 'atime', 'ctime', 'crtime', 'dir_flags', 'meta_flags')}
            record.update(case_id=config['case_id'], host_id=config['host_id'],
                          snapshot_id=snapshot_id,
                          artifact_type='filesystem_metadata', evidence_kind='disk',
                          source_file=str(database.resolve()), source_record='tsk_files.obj_id=' + str(row['obj_id']),
                          original_path=original, path=path, sha256=row['sha256'] or '',
                          timestamp=stamp, timestamp_semantics='filesystem_mtime_not_execution_time',
                          ingest_status=ingest_status,
                          path_mapping_status='explicit_fs_mount' if mount else 'unresolved_volume')
            record.update(md5=row['md5'] or '', raw=json.dumps(dict(row)), source_tool='autopsy.tsk_files')
            writer.writerow(record)
            count += 1
    connection.close()
    (output / 'export_manifest.json').write_text(json.dumps({
        'database': str(database.resolve()), 'records': count, 'ingest_status': ingest_status,
        'exported_utc': datetime.now(timezone.utc).isoformat(),
        'limitations': ['Read transaction provides a consistent snapshot; ongoing ingestion may add records.',
                        'No NTFS SI/FN completeness or timestamp-manipulation verdict is inferred.',
                        'Volume-to-drive mappings require explicit configuration.',
                        'Generic blackboard artifacts are not yet imported.']}, indent=2), encoding='utf-8')
    print(f'{count} filesystem records exported ({ingest_status})')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('database', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--ingest-status', required=True, choices=['partial', 'complete'])
    args = parser.parse_args()
    export(args.database, json.loads(args.config.read_text()), args.output, args.ingest_status)
