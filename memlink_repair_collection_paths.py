"""Repair equal-length lowercase formatting failures in derived JSONL records only."""
import argparse
import json
from pathlib import Path
from memlink_pipeline import sha256
import ntpath
from memlink_core import normalize_path


def repair_from_original(root,config_path):
    config=json.loads(config_path.read_text());manifest=json.loads((root/'manifest.json').read_text())
    patches=[];offset=0
    with (root/'evidence.jsonl').open('rb') as source:
        for number,line in enumerate(source,1):
            row=json.loads(line);original=row.get('original_path') or ''
            if row.get('artifact_detail')=='filesystem_metadata':
                mount=config.get('autopsy_fs_mounts',{}).get(str(row['raw'].get('fs_obj_id')))
                original=mount.rstrip('\\/')+'\\'+original.lstrip('/').replace('/','\\') if mount else original
            info=normalize_path(original,config.get('path_mappings'));expected=info['normalized'] or None
            if row['path']!=expected:
                raw=dict(row['raw']);row['path']=expected;row['filename']=ntpath.basename(expected) if expected else None
                row['path_resolved']=info['resolved']
                ending=b'\r\n' if line.endswith(b'\r\n') else b'\n'
                content=json.dumps(row,ensure_ascii=True,separators=(',',':')).encode()
                if len(content)>len(line)-len(ending):
                    content=json.dumps(row,ensure_ascii=False,separators=(',',':')).encode('utf-8')
                if len(content)>len(line)-len(ending) or row['raw']!=raw:raise ValueError('Full rebuild required')
                replacement=content+b' '*(len(line)-len(ending)-len(content))+ending
                if json.loads(replacement)!=row:raise ValueError('Serialization altered values')
                patches.append((offset,line,replacement))
            offset+=len(line)
    with (root/'evidence.jsonl').open('r+b') as target:
        for offset,original,replacement in patches:
            target.seek(offset)
            if target.read(len(original))!=original:raise ValueError('Record changed during repair')
            target.seek(offset);target.write(replacement)
    manifest['pre_source_path_repair_sha256']=manifest['sha256'];manifest['sha256']=sha256(root/'evidence.jsonl')
    manifest['original_path_consistency_repairs']=len(patches)
    (root/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    for name,backup in [('validation.json','validation.before-source-path-repair.json'),('README.md','README.before-source-path-repair.md')]:
        if (root/name).exists():(root/name).rename(root/backup)
    print('Original-path consistency repairs:',len(patches),flush=True)


def repair(root):
    validation=json.loads((root/'validation.json').read_text())
    manifest=json.loads((root/'manifest.json').read_text())
    if validation['sha256']!=manifest['sha256']:raise ValueError('Validation/source identity differs')
    if any(issue[1]!='path_not_normalized' for issue in validation['issues']):
        raise ValueError('This repair handles only path lowercase failures')
    wanted={issue[0] for issue in validation['issues']}
    patches=[];offset=0
    with (root/'evidence.jsonl').open('rb') as source:
        for number,line in enumerate(source,1):
            if number in wanted:
                row=json.loads(line)
                if row['source_tool']!='volatility.filescan':raise ValueError('Unexpected source for this repair')
                original_raw=dict(row['raw'])
                row['path']=row['path'].lower()
                if row['filename']:row['filename']=row['filename'].lower()
                ending=b'\r\n' if line.endswith(b'\r\n') else b'\n'
                replacement=json.dumps(row,ensure_ascii=True,separators=(',',':')).encode()+ending
                if len(replacement)!=len(line) or row['raw']!=original_raw:
                    raise ValueError('Repair requires a full rebuild; refusing an unsafe byte edit')
                patches.append((offset,line,replacement))
            offset+=len(line)
            if number>=max(wanted):break
    if len(patches)!=len(wanted):raise ValueError('Missing target records')
    with (root/'evidence.jsonl').open('r+b') as target:
        for offset,original,replacement in patches:
            target.seek(offset)
            if target.read(len(original))!=original:raise ValueError('Record changed during repair')
            target.seek(offset);target.write(replacement)
    manifest['pre_path_repair_sha256']=manifest['sha256']
    manifest['sha256']=sha256(root/'evidence.jsonl')
    manifest['unicode_lowercase_repair_records']=len(patches)
    (root/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    for name,backup in [('validation.json','validation.initial-failed.json'),('README.md','README.initial-failed.md')]:
        path=root/name
        if path.exists():path.rename(root/backup)
    print('Derived paths repaired without changing raw data:',len(patches),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('collection',type=Path)
    parser.add_argument('--from-original',type=Path)
    args=parser.parse_args()
    if args.from_original:repair_from_original(args.collection,args.from_original)
    else:repair(args.collection)
