"""Build one provenance-preserving collection from all available extracted artifacts."""
import argparse
import base64
import csv
import hashlib
import json
import ntpath
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from memlink_schema import standardize, timestamp, FIELDS
from memlink_pipeline import sha256
from memlink_registry_export import service_rows


CATEGORIES = {
    'pslist':'process', 'psscan':'process', 'pstree':'process', 'cmdline':'command_line',
    'envars':'environment', 'getsids':'security_identifier', 'malfind':'memory_region',
    'vadinfo':'memory_region', 'ldrmodules':'module', 'dlllist':'module',
    'modules':'kernel_module', 'modscan':'kernel_module', 'svcscan':'service',
    'netscan':'network_connection', 'handles':'handle', 'filescan':'file_object', 'info':'host_metadata'
}


def walk(rows, prefix=''):
    for index, row in enumerate(rows):
        pointer = prefix + '/' + str(index)
        yield pointer, row
        yield from walk(row.get('__children', []), pointer + '/__children')


def executable(command):
    match = re.match(r'^(?:"([^"]+\.exe)"|([^\s]+\.exe))(?:\s|$)', str(command or ''), re.I)
    return (match.group(1) or match.group(2)) if match else None


def base(config, layer, source, reference, kind, tool, raw):
    return dict(case_id=config['case_id'],host_id=config['host_id'],
                snapshot_id=config['snapshot_id'] if layer=='memory' else config['disk_snapshot_id'],
                evidence_kind=layer,artifact_type=kind,source_tool=tool,
                source_file=str(source),source_record=reference,raw=raw)


def memory_record(config, plugin, source, pointer, raw):
    short = plugin.split('.')[-1]
    row = base(config,'memory',source,'json-pointer='+pointer,CATEGORIES[short],'volatility.'+short,raw)
    row.update(pid=raw.get('PID',raw.get('Pid')),ppid=raw.get('PPID'))
    path = None
    if short in ('pstree','dlllist','modules','modscan'):
        path = raw.get('Path')
    elif short=='ldrmodules': path=raw.get('MappedPath')
    elif short=='vadinfo': path=raw.get('File')
    elif short=='filescan' or (short=='handles' and raw.get('Type')=='File'): path=raw.get('Name')
    elif short=='svcscan': path=executable(raw.get('Binary (Registry)') or raw.get('Binary'))
    elif short=='cmdline': path=executable(raw.get('Args'))
    row['path']=path
    row['size']=raw.get('Size')
    if short in ('malfind','vadinfo') and isinstance(raw.get('Start VPN'),int) and isinstance(raw.get('End VPN'),int):
        row['size']=max(0,raw['End VPN']-raw['Start VPN']+1)
    if short in ('pslist','psscan','pstree'):
        row.update(crtime=raw.get('CreateTime'),process_create_time=raw.get('CreateTime'),
                   timestamp=raw.get('CreateTime'),timestamp_semantics='process_creation_time')
    elif short=='dlllist': row.update(timestamp=raw.get('LoadTime'),timestamp_semantics='module_load_time')
    elif short=='netscan': row.update(timestamp=raw.get('Created'),timestamp_semantics='scanned_network_object_creation_time_not_capture_liveness')
    result=standardize(row,config)
    result.update(process_name=raw.get('ImageFileName') or raw.get('Process') or raw.get('Owner'),
                  process_exit_time=timestamp(raw.get('ExitTime')),
                  source_json_pointer=pointer)
    if short=='netscan':
        result.update(local_address=raw.get('LocalAddr'),local_port=raw.get('LocalPort'),
                      remote_address=raw.get('ForeignAddr'),remote_port=raw.get('ForeignPort'),
                      network_state=raw.get('State'),protocol=raw.get('Proto'),
                      liveness='not_established_by_scanning_alone')
    if short=='svcscan': result.update(service_name=raw.get('Name'),service_state=raw.get('State'),service_start=raw.get('Start'))
    if short=='filescan': result['ownership_limitation']='File object; not proof of disk presence, ownership or benignness.'
    if short in ('malfind','vadinfo'): result.update(region_start=raw.get('Start VPN'),region_end=raw.get('End VPN'),protection=raw.get('Protection'))
    return result


def filesystem_records(connection,config,source):
    for raw_row in connection.execute('SELECT * FROM tsk_files ORDER BY obj_id'):
        raw=dict(raw_row)
        original=(raw.get('parent_path') or '')+raw['name']
        mount=config.get('autopsy_fs_mounts',{}).get(str(raw['fs_obj_id']))
        path=mount.rstrip('\\/')+'\\'+original.lstrip('/').replace('/','\\') if mount else original
        row=base(config,'disk',source,'tsk_files.obj_id='+str(raw['obj_id']),'filesystem_metadata','autopsy.tsk_files',raw)
        row.update(path=path,size=raw['size'],md5=raw['md5'],sha256=raw['sha256'],meta_flags=raw['meta_flags'])
        for field in ('mtime','atime','ctime','crtime'):row[field]=raw[field]
        result=standardize(row,config)
        result.update(original_path=original,fs_obj_id=raw['fs_obj_id'],
                      ntfs_record_number=raw['meta_addr'],ntfs_sequence=raw['meta_seq'],
                      timestamp_semantics='filesystem_MACB_not_complete_NTFS_SI_FN_pairs',
                      filesystem_record_type=raw['type'])
        yield result


def jsonable(row):
    return {key:base64.b64encode(value).decode() if isinstance(value,bytes) else value for key,value in dict(row).items()}


def blackboard_records(connection,config,source):
    attributes=defaultdict(list)
    query='SELECT a.*,t.type_name FROM blackboard_attributes a JOIN blackboard_attribute_types t ON a.attribute_type_id=t.attribute_type_id ORDER BY a.artifact_id,a.rowid'
    for row in connection.execute(query):attributes[row['artifact_id']].append(jsonable(row))
    for row in connection.execute('SELECT a.*,t.type_name FROM blackboard_artifacts a JOIN blackboard_artifact_types t ON a.artifact_type_id=t.artifact_type_id ORDER BY a.artifact_id'):
        raw=jsonable(row);raw['attributes']=attributes[row['artifact_id']]
        values=defaultdict(list)
        for attr in raw['attributes']:
            value=next((attr[k] for k in ('value_text','value_int64','value_int32','value_double','value_byte') if attr.get(k) is not None),None)
            values[attr['type_name']].append(value)
        name=row['type_name']
        kind='web_artifact' if name.startswith('TSK_WEB_') else 'usb_artifact' if name=='TSK_DEVICE_ATTACHED' else 'disk_observation'
        record=base(config,'disk',source,'blackboard_artifacts.artifact_id='+str(row['artifact_id']),kind,'autopsy.blackboard.'+name,raw)
        paths=values.get('TSK_PATH',[])
        record['path']=paths[0] if paths else None
        result=standardize(record,config)
        time_fields={'TSK_DATETIME_CREATED':'crtime','TSK_DATETIME_MODIFIED':'mtime',
                     'TSK_DATETIME_ACCESSED':'atime','TSK_DATETIME_CHANGED':'ctime'}
        for attribute,field in time_fields.items():
            times={timestamp(v,epoch=True) for v in values.get(attribute,[])}-{None}
            if len(times)==1:result[field]=next(iter(times))
        event_times={timestamp(v,epoch=True) for v in values.get('TSK_DATETIME',[])}-{None}
        if len(event_times)==1:
            result.update(event_time=next(iter(event_times)),timestamp_semantics=name+':TSK_DATETIME')
        result.update(autopsy_artifact_type=name,source_file_object_id=row['obj_id'],
                      attributes_by_name=dict(values),
                      artifact_timestamps={key:[timestamp(v,epoch=True) for v in vals] for key,vals in values.items() if key.startswith('TSK_DATETIME')},
                      binary_attribute_encoding='base64; original value_type retained')
        yield result


def build(config,runs,database,output,info=None,registry=None):
    output.mkdir(parents=True,exist_ok=False)
    sources=[];counts=Counter();coverage={};ids=set();rejected=0
    selected={}
    for root in runs:
        manifest=json.loads((root/'manifest.json').read_text(encoding='utf-8'))
        for key,expected in [('case_id',config['case_id']),('host_id',config['host_id']),('snapshot_id',config['snapshot_id']),('image_sha256',config['memory_sha256'])]:
            if manifest[key]!=expected:raise ValueError('Memory identity mismatch: '+key)
        for name,entry in manifest['plugins'].items():selected[name]=entry
    if info:
        selected['windows.info']={'status':'success','source_file':str(info),'sha256':sha256(info),'provenance_note':'Initial standalone extraction; no original run manifest.'}
    pending=output/'evidence.jsonl.partial'
    errors=output/'rejected_records.jsonl'
    def emit(record,stream):
        if not set(FIELDS)<=set(record):raise ValueError('Missing standard fields')
        if record['artifact_id'] in ids:raise ValueError('Duplicate artifact UUID')
        ids.add(record['artifact_id']);counts[record['source_layer']+':'+record['source_tool']]+=1
        stream.write(json.dumps(record,ensure_ascii=True,separators=(',',':'))+'\n')
    with pending.open('x',encoding='utf-8') as stream,errors.open('x',encoding='utf-8') as reject:
        def attempt(factory,reference):
            nonlocal rejected
            try:emit(factory(),stream)
            except (ValueError,TypeError,OverflowError) as error:
                rejected+=1;reject.write(json.dumps({'source':reference,'error':str(error)})+'\n')
        for plugin in config['plugins']:
            entry=selected.get(plugin)
            coverage[plugin]={'status':entry['status'] if entry else 'unavailable_not_extracted','normalized_rows':0}
            if not entry or entry['status'] not in ('success','success_empty'):continue
            source=Path(entry['source_file'])
            if sha256(source)!=entry['sha256']:raise ValueError('Source artifact hash mismatch: '+str(source))
            data=json.loads(source.read_text(encoding='utf-8-sig'))
            sources.append({'source':str(source),'sha256':entry['sha256'],'plugin':plugin,'status':entry['status']})
            expected_rows=0
            for pointer,raw in walk(data):
                expected_rows+=1
                attempt(lambda p=pointer,r=raw:memory_record(config,plugin,source,p,r),str(source)+'#'+pointer)
            coverage[plugin]['normalized_rows']=counts['memory:volatility.'+plugin.split('.')[-1]]
            coverage[plugin]['source_rows_including_children']=expected_rows
            print(plugin,coverage[plugin]['normalized_rows'],flush=True)
        snapshot=output/'source_snapshot.db'
        live=sqlite3.connect(database.resolve().as_uri()+'?mode=ro',uri=True,timeout=10)
        backup=sqlite3.connect(snapshot);live.backup(backup);backup.close();live.close()
        connection=sqlite3.connect(snapshot.as_uri()+'?mode=ro',uri=True);connection.row_factory=sqlite3.Row
        image_names=[row[0] for row in connection.execute('select name from tsk_image_names')]
        expected_image=ntpath.normpath(config['disk_image']).casefold()
        if expected_image not in {ntpath.normpath(name).casefold() for name in image_names}:
            raise ValueError('Autopsy snapshot does not reference the configured disk image')
        if connection.execute('select count(*) from tsk_image_info').fetchone()[0]!=1:
            raise ValueError('Multi-image cases require explicit host/data-source partitioning')
        sources.append({'source':str(database),'snapshot':str(snapshot),'sha256':sha256(snapshot),'ingest_jobs':[dict(x) for x in connection.execute('select * from ingest_jobs')]})
        for record in filesystem_records(connection,config,database):emit(record,stream)
        for record in blackboard_records(connection,config,database):emit(record,stream)
        coverage['autopsy.tsk_files']={'source_rows':connection.execute('select count(*) from tsk_files').fetchone()[0],'normalized_rows':counts['disk:autopsy.tsk_files']}
        coverage['autopsy.blackboard']={'source_rows':connection.execute('select count(*) from blackboard_artifacts').fetchone()[0],'normalized_rows':sum(n for k,n in counts.items() if k.startswith('disk:autopsy.blackboard.'))}
        connection.close()
        for source in registry or []:
            n=0
            for line,values,stamp,raw in service_rows(source.read_text(encoding='utf-8-sig',errors='replace')):
                row=base(config,'disk',source,'line='+str(line),'registry_service_configuration','autopsy.regripper.services',{'csv_values':values,'original_line':raw})
                row.update(path=executable(values[3]) or values[3],timestamp=stamp,timestamp_semantics='service_key_last_write_not_execution')
                result=standardize(row,config);result.update(service_name=values[1],service_start=values[5],service_account=values[6]);emit(result,stream);n+=1
            sources.append({'source':str(source),'sha256':sha256(source),'rows':n})
    manifest={'case_id':config['case_id'],'host_id':config['host_id'],'created_utc':datetime.now(timezone.utc).isoformat(),
              'configuration':config,
              'status':'complete_for_available_extracted_sources' if not rejected else 'incomplete_rejected_records',
              'total_records':sum(counts.values()),'rejected_records':rejected,'counts':dict(counts),'coverage':coverage,'sources':sources,
              'not_yet_parsed_categories':['Windows event-log entries','scheduled-task definitions','separate NTFS STANDARD_INFORMATION / FILE_NAME timestamp pairs'],
              'limitations':['Complete collection of the selected extracted outputs, not proof every recoverable disk/memory artifact was extracted.',
                             'Missing parsed event logs, scheduled tasks or NTFS SI/FN pairs are not invented from filesystem filenames.',
                             'Repeated observations across tools/reruns remain distinct; artifact counts are not unique objects or malicious findings.',
                             'No maliciousness or ground-truth accuracy is assigned by normalization.']}
    if not rejected:
        pending.replace(output/'evidence.jsonl');manifest['sha256']=sha256(output/'evidence.jsonl')
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps({'records':sum(counts.values()),'rejected':rejected,'status':manifest['status']}),flush=True)
    return manifest


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config',type=Path);parser.add_argument('--runs',type=Path,nargs='+',required=True)
    parser.add_argument('--database',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--info',type=Path);parser.add_argument('--registry',type=Path,nargs='*')
    args=parser.parse_args()
    result=build(json.loads(args.config.read_text()),args.runs,args.database,args.output,args.info,args.registry)
    if result['rejected_records']:raise SystemExit(1)
