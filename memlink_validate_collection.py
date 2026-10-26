"""Validate the actual unified evidence export, without assigning detection accuracy."""
import argparse
import hashlib
import json
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from memlink_schema import FIELDS
from memlink_collection import walk
from memlink_pipeline import sha256
from memlink_core import normalize_path


def validate(root):
    manifest=json.loads((root/'manifest.json').read_text())
    counts=Counter();ids=set();digest=hashlib.sha256();issues=[];total=0
    with (root/'evidence.jsonl').open('rb') as source:
        for number,line in enumerate(source,1):
            digest.update(line);row=json.loads(line);total+=1
            if not set(FIELDS)<=set(row):issues.append([number,'missing_fields'])
            uuid.UUID(row['artifact_id'])
            if row['artifact_id'] in ids:issues.append([number,'duplicate_uuid'])
            ids.add(row['artifact_id'])
            if row['host_id']!=manifest['host_id'] or row['case_id']!=manifest['case_id']:issues.append([number,'identity_mismatch'])
            if row['source_layer'] not in ('memory','disk'):issues.append([number,'invalid_layer'])
            if not isinstance(row['raw'],dict):issues.append([number,'raw_not_object'])
            for field in ('pid','ppid','size'):
                if row[field] is not None and type(row[field]) is not int:issues.append([number,'invalid_'+field])
            if row['allocated'] is not None and type(row['allocated']) is not bool:issues.append([number,'allocation_not_boolean'])
            for field in ('mtime','atime','ctime','crtime','event_time','process_create_time'):
                if row.get(field) is not None:
                    stamp=datetime.fromisoformat(row[field])
                    if stamp.utcoffset() is None or stamp.utcoffset().total_seconds()!=0:issues.append([number,'not_UTC_'+field])
            if row['path'] and (row['path']!=row['path'].lower() or '/' in row['path']):issues.append([number,'path_not_normalized'])
            if manifest.get('configuration'):
                config=manifest['configuration'];original=row.get('original_path') or ''
                if row.get('artifact_detail')=='filesystem_metadata':
                    mount=config.get('autopsy_fs_mounts',{}).get(str(row['raw'].get('fs_obj_id')))
                    original=mount.rstrip('\\/')+'\\'+original.lstrip('/').replace('/','\\') if mount else original
                if row['path']!=(normalize_path(original,config.get('path_mappings'))['normalized'] or None):issues.append([number,'path_source_inconsistency'])
            if not row.get('source_file') or not row.get('source_record'):issues.append([number,'missing_source_reference'])
            counts[row['source_layer']+':'+row['source_tool']]+=1
    if dict(counts)!=manifest['counts']:issues.append(['collection','count_mismatch'])
    if total!=manifest['total_records']:issues.append(['collection','total_mismatch'])
    if digest.hexdigest()!=manifest['sha256']:issues.append(['collection','hash_mismatch'])
    for category,coverage in manifest['coverage'].items():
        expected=coverage.get('source_rows',coverage.get('source_rows_including_children'))
        if expected is not None and coverage['normalized_rows']!=expected:issues.append([category,'source_coverage_mismatch'])
    for source in manifest['sources']:
        if source.get('plugin'):
            path=Path(source['source'])
            if sha256(path)!=source['sha256']:issues.append([str(path),'source_hash_changed'])
            source_count=sum(1 for _ in walk(json.loads(path.read_text(encoding='utf-8-sig'))))
            key='memory:volatility.'+source['plugin'].split('.')[-1]
            if counts[key]!=source_count:issues.append([key,'source_row_count_mismatch'])
    result={'status':'passed' if not issues else 'failed','records_validated':total,
            'sha256':digest.hexdigest(),'issues':issues,
            'meaning':'Schema, integrity and selected-source coverage validation of real evidence. Not detector accuracy or maliciousness evaluation.'}
    with (root/'validation.json').open('x',encoding='utf-8') as target:json.dump(result,target,indent=2)
    layers=Counter()
    for key,count in counts.items():layers[key.split(':',1)[0]]+=count
    lines=['# DC01 unified normalized evidence','',
           'Status: '+result['status']+'. '+str(total)+' artifact observations; no detection-accuracy claim.',
           '', 'Authoritative evidence: `evidence.jsonl` (one typed artifact per line).',
           'Supporting files: `manifest.json`, `validation.json`, `source_snapshot.db`, `rejected_records.jsonl`.',
           '', '## Coverage','', '| Source | Records |','|---|---:|']
    lines += ['| '+key+' | '+str(count)+' |' for key,count in counts.items()]
    lines += ['', '## Limits','']+['- '+item for item in manifest['limitations']]
    lines += ['', 'Not yet parsed as structured entries: '+', '.join(manifest.get('not_yet_parsed_categories',[]))+'.',
              '', 'Raw observations and source IDs are retained. Process remnants, duplicate scans and deleted records are not silently discarded.',
              'No source image or original case database was modified by this collection build.',
              '', 'SHA-256: `'+digest.hexdigest()+'`.']
    with (root/'README.md').open('x',encoding='utf-8') as target:target.write('\n'.join(lines)+'\n')
    print(json.dumps(result,indent=2))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('collection',type=Path)
    result=validate(parser.parse_args().collection)
    if result['issues']:raise SystemExit(1)
