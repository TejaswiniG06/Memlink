"""Shared typed artifact contract for MemLink and ForgeScan."""
import argparse
import csv
import json
import ntpath
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ('artifact_id', 'host_id', 'source_layer', 'source_tool', 'artifact_type',
          'path', 'filename', 'pid', 'ppid', 'md5', 'mtime', 'atime', 'ctime',
          'crtime', 'size', 'allocated', 'tamper_score', 'ttp_ids', 'raw')


def integer(value):
    if value is None or str(value).strip().lower() in ('', 'none', 'null'):
        return None
    if isinstance(value, bool) or not re.fullmatch(r'-?\d+', str(value).strip()):
        raise ValueError(f'Expected integer or null: {value}')
    return int(value)


def timestamp(value, epoch=False):
    if value is None or str(value).strip().lower() in ('', 'none', 'null'):
        return None
    try:
        if epoch:
            number = int(value)
            return datetime.fromtimestamp(number, timezone.utc).isoformat() if number else None
        stamp = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return stamp.astimezone(timezone.utc).isoformat() if stamp.tzinfo else None
    except (ValueError, OverflowError, OSError):
        return None


def standardize(row, config):
    from memlink_core import normalize_path
    layer = row.get('source_layer') or row.get('evidence_kind')
    if layer not in ('memory', 'disk'):
        raise ValueError('source_layer must be disk or memory')
    if row.get('host_id') != config['host_id'] or row.get('case_id') != config['case_id']:
        raise ValueError('Case/host identity mismatch')
    for key in ('snapshot_id', 'source_file', 'source_record'):
        if not row.get(key):
            raise ValueError('Missing provenance field: ' + key)
    detail = row.get('artifact_type')
    category = {'filesystem_metadata': 'file', 'loaded_module': 'module',
                'service_configuration_in_memory': 'service',
                'registry_service_configuration': 'service'}.get(detail, detail)
    original_path = row.get('path') or ''
    path = normalize_path(original_path, config.get('path_mappings'))
    md5 = str(row.get('md5') or '').strip().lower() or None
    if md5 and not re.fullmatch('[0-9a-f]{32}', md5):
        raise ValueError('Invalid MD5')
    raw = row.get('raw')
    raw = json.loads(raw) if isinstance(raw, str) and raw.strip() else None if raw == '' else raw
    if raw is None:
        raw = dict(row)
    if not isinstance(raw, dict):
        raise ValueError('raw must be a JSON object')
    source_tool = row.get('source_tool') or ('autopsy.tsk_files' if detail == 'filesystem_metadata' else
                  'volatility.dlllist' if detail == 'loaded_module' else
                  'volatility.svcscan' if detail == 'service_configuration_in_memory' else
                  'autopsy.regripper.services' if detail == 'registry_service_configuration' else None)
    if not source_tool:
        raise ValueError('source_tool required for this artifact category')
    allocated = None
    if detail == 'filesystem_metadata':
        flags = integer(row.get('meta_flags'))
        if flags is not None and flags & 3 in (1, 2):
            allocated = flags & 3 == 1
    if row.get('allocated') in (True, False):
        allocated = row['allocated']
    identity = '\0'.join(str(row[k]) for k in ('case_id', 'host_id', 'snapshot_id', 'source_file', 'source_record'))
    output = dict(artifact_id=str(uuid.uuid5(uuid.NAMESPACE_URL, identity)), host_id=row['host_id'],
                  source_layer=layer, source_tool=source_tool, artifact_type=category,
                  path=path['normalized'] or None, filename=ntpath.basename(path['normalized']) or None,
                  pid=integer(row.get('pid')), ppid=integer(row.get('ppid')), md5=md5,
                  size=integer(row.get('size')), allocated=allocated,
                  tamper_score=None, ttp_ids=None, raw=raw)
    for key in ('mtime', 'atime', 'ctime', 'crtime'):
        output[key] = timestamp(row.get(key), epoch=detail == 'filesystem_metadata')
    output.update(case_id=row['case_id'], snapshot_id=row['snapshot_id'], source_file=row['source_file'],
                  source_record=row['source_record'], artifact_detail=detail,
                  original_path=original_path, path_resolved=path['resolved'],
                  timestamp_status='Unknown/invalid timestamps retained in raw; no timezone guessed.')
    output.update(event_time=timestamp(row.get('timestamp')),
                  timestamp_semantics=row.get('timestamp_semantics') or None,
                  process_create_time=timestamp(row.get('process_create_time')),
                  service_name=row.get('service_name') or None,
                  sha256=row.get('sha256') or None)
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    count = 0
    if args.output.exists():
        raise ValueError('Refusing to overwrite output')
    pending = args.output.with_suffix(args.output.suffix + '.partial')
    with args.input.open(encoding='utf-8-sig', newline='') as source, pending.open('x', encoding='utf-8') as target:
        for row in csv.DictReader(source):
            target.write(json.dumps(standardize(row, config)) + '\n')
            count += 1
    pending.replace(args.output)
    print(f'{count} typed shared-schema artifacts written')
