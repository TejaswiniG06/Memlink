"""Populate unambiguous blackboard time fields in an existing derived collection."""
import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
from memlink_pipeline import sha256


def finalize(root):
    manifest_path=root/'manifest.json';manifest=json.loads(manifest_path.read_text())
    source=root/'evidence.jsonl'
    if sha256(source)!=manifest['sha256']:raise ValueError('Collection changed before finalization')
    pending=root/'evidence.enriched.partial';digest=hashlib.sha256();changed=0
    mapping={'TSK_DATETIME_CREATED':'crtime','TSK_DATETIME_MODIFIED':'mtime',
             'TSK_DATETIME_ACCESSED':'atime','TSK_DATETIME_CHANGED':'ctime','TSK_DATETIME':'event_time'}
    with source.open('rb') as incoming,pending.open('xb') as outgoing:
        for line in incoming:
            if b'autopsy.blackboard.' in line:
                row=json.loads(line);before=dict(row)
                for attribute,field in mapping.items():
                    values=set(row.get('artifact_timestamps',{}).get(attribute,[]))-{None}
                    if len(values)==1:row[field]=next(iter(values))
                if row.get('event_time'):row['timestamp_semantics']=row['autopsy_artifact_type']+':TSK_DATETIME'
                if row!=before:
                    changed+=1;line=(json.dumps(row,ensure_ascii=True,separators=(',',':'))+'\n').encode()
            outgoing.write(line);digest.update(line)
    (root/'manifest.pre-finalization.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    pending.replace(source)
    manifest['pre_finalization_sha256']=manifest['sha256'];manifest['sha256']=digest.hexdigest()
    manifest['blackboard_time_records_enriched']=changed
    manifest['not_yet_parsed_categories']=['Windows event-log entries','scheduled-task definitions','separate NTFS STANDARD_INFORMATION / FILE_NAME timestamp pairs']
    connection=sqlite3.connect((root/'source_snapshot.db').as_uri()+'?mode=ro',uri=True)
    connection.row_factory=sqlite3.Row
    manifest['disk_image_metadata']=[dict(row) for row in connection.execute('select * from tsk_image_info')]
    manifest['disk_segment_references']=[dict(row) for row in connection.execute('select * from tsk_image_names')]
    connection.close()
    manifest_path.write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('Blackboard timestamp records enriched:',changed)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('collection',type=Path)
    finalize(parser.parse_args().collection)
