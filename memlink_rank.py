"""Deterministic, rule-based candidate ranking (spec rules/assessment.v1.draft.json).

Three things are kept apart in every finding:
  observation   - what the records say, each with a source reference
  correlation   - how records were linked and how strong each link is
  maliciousness - always 'not_assessed'; ranking tiers are review priority only
Evidence families/groups come from the spec; an unmapped family contributes zero.
Predicates that need analyst review are satisfied only by a review entry whose
status is exactly 'reviewed' (with reviewer and basis). Nothing is inferred
from case-specific names, addresses or hashes.
"""
import argparse
import base64
import binascii
import csv
import hashlib
import json
import ntpath
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from memlink_assess import artifact_pid, load_runs, loader_review
from memlink_core import normalize_path

INTERPRETERS = {'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'}
# Implementation assumption (spec does not enumerate it): groups that count as
# action-relevant corroboration per action. Pending a spec amendment.
RELEVANT_GROUPS = {
    'A01': {'service_install_event', 'service_configuration', 'disk_file_state', 'memory_runtime'},
    'A02': {'memory_runtime', 'service_install_event', 'shell_state'},
    'A03': {'memory_runtime', 'memory_network_state'},
    'A05': {'memory_runtime'},
}
NOT_EVALUABLE = {
    'A04': 'no verified main-image content comparison input (memory image bytes vs backing file) is collected',
    'A06': 'no verified file identity (volume + MFT record/sequence) links memory handles to deleted disk records',
    'A07': 'no scheduled-task or Run-key records are collected',
    'A08': 'no separate NTFS SI/FN timestamps or partner detector output are collected',
}
IDENTITY_ORDER = ['comparable_content_hash', 'verified_volume_file_reference', 'resolved_full_path',
                  'service_name_and_context', 'basename', 'unresolved']
TEMPORAL_ORDER = ['compatible_known', 'unknown', 'contradicted']
LINK_STRENGTH = {'comparable_content_hash': 'strong', 'verified_volume_file_reference': 'strong',
                 'resolved_full_path': 'moderate', 'service_name_and_context': 'contextual',
                 'basename': 'weak', 'unresolved': 'none'}

_DOWNLOAD = re.compile(r'downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|certutil[^|&]*-urlcache|bitsadmin[^|&]*/transfer|\bcurl\b|\bwget\b', re.I)
_EXECUTE = re.compile(r'\biex\b|invoke-expression|start-process|\bstart\s+/?b?\s*\S+\.exe|\|\s*(?:iex|cmd|powershell)', re.I)
_CREDENTIAL = re.compile(r'sekurlsa|mimikatz|comsvcs[^|&]*minidump|ntds\.dit|lsass[^|&]*(?:dump|minidump)|procdump[^|&]*lsass', re.I)
_PIPE_WRITE = re.compile(r'echo\b[^>]*>\s*\\\\\.\\pipe\\', re.I)
_ENCODED = re.compile(r'(?:^|\s)-(?:e|ec|enc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})', re.I)


def parse_time(value):
    """UTC datetime from ISO text; accepts 7-digit fractions on any Python."""
    if not value:
        return None
    text = re.sub(r'(\.\d{6})\d+', r'\1', str(value).strip().replace('Z', '+00:00'))
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def command_behaviors(command):
    """Closed set of command behaviours; encoded content is decoded, never executed."""
    text, found = str(command or ''), set()
    if _PIPE_WRITE.search(text):
        found.add('pipe_write')
    if _DOWNLOAD.search(text) and _EXECUTE.search(text):
        found.add('download_and_execute')
    for blob in _ENCODED.findall(text):
        try:
            decoded = base64.b64decode(blob, validate=True).decode('utf-16-le')
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        found.add('encoded_command')
        if _DOWNLOAD.search(decoded) and _EXECUTE.search(decoded):
            found.add('encoded_download_and_execute')
        if _CREDENTIAL.search(decoded):
            found.add('encoded_credential_access')
    return found


def first_token(command):
    text = str(command or '').strip()
    token = text[1:text.find('"', 1)] if text.startswith('"') and text.find('"', 1) > 0 else text.split(' ')[0]
    return token


def is_interpreter(command):
    return ntpath.basename(first_token(command)).casefold() in INTERPRETERS


def canonical_command(command, mappings):
    text = str(command or '').strip().strip('"')
    lowered = text.casefold()
    for prefix in ('%systemroot%', '\\systemroot', 'systemroot'):
        if lowered.startswith(prefix):
            text = 'c:\\windows' + text[len(prefix):]
            break
    return ' '.join(text.replace('"', '').casefold().split())


class Spec:
    def __init__(self, path):
        self.path = path
        data = json.loads(Path(path).read_text(encoding='utf-8-sig'))
        self.version = data['specification_version']
        self.status = data['status']
        self.family = data['evidence_families']
        self.group = data['independence_policy']['groups']
        self.ranking = data['ranking']
        self.unmapped = Counter()

    def classify(self, source_key):
        family = self.family.get(source_key)
        if family is None:
            self.unmapped[source_key] += 1
            return None, None
        return family, self.group.get(family)


class Finding:
    def __init__(self, spec, action, subject):
        self.spec, self.action, self.subject = spec, action, subject
        self.id = 'F-%s-%s' % (action, hashlib.sha1(('%s|%s' % (action, subject)).encode()).hexdigest()[:10])
        self.observations, self.links, self.evidence = [], [], []
        self.predicates, self.contradictions, self.notes = {}, [], []
        self.identity, self.temporal = 'unresolved', 'unknown'
        self.review_needed = []

    def add(self, source_key, ref, text):
        family, group = self.spec.classify(source_key)
        self.evidence.append({'source': source_key, 'family': family, 'group': group, 'ref': ref})
        self.observations.append({'text': text, 'ref': ref, 'family': family})

    def link(self, method, left, right, detail=None):
        self.links.append({'method': method, 'strength': LINK_STRENGTH[method], 'from': left, 'to': right, 'detail': detail})
        if IDENTITY_ORDER.index(method) < IDENTITY_ORDER.index(self.identity):
            self.identity = method

    def predicate(self, name, satisfied, basis, review_key=None):
        self.predicates[name] = {'satisfied': bool(satisfied), 'basis': basis}
        if review_key and not satisfied:
            self.review_needed.append({'subject': self.subject, 'predicate': review_key})

    def groups(self):
        relevant = RELEVANT_GROUPS.get(self.action, set())
        return sorted({e['group'] for e in self.evidence if e['group'] in relevant})

    def tier(self):
        if not any(p['satisfied'] for p in self.predicates.values()):
            return 3
        if (len(self.groups()) >= 2 and self.identity in IDENTITY_ORDER[:3] and self.temporal == 'compatible_known'
                and not self.contradictions):
            return 1
        return 2

    def sort_key(self):
        return (self.tier(), -len(self.groups()), IDENTITY_ORDER.index(self.identity),
                TEMPORAL_ORDER.index(self.temporal), self.id)

    def as_dict(self):
        return {'finding_id': self.id, 'action': self.action, 'subject': self.subject, 'tier': self.tier(),
                'tier_meaning': 'review priority only; not a maliciousness verdict',
                'observation': self.observations,
                'correlation': {'identity': self.identity, 'links': self.links, 'corroboration_groups': self.groups(),
                                'corroboration_group_count': len(self.groups()), 'temporal': self.temporal,
                                'contradictions': self.contradictions},
                'predicates': self.predicates,
                'maliciousness': {'verdict': 'not_assessed', 'note': 'ranking never assigns a verdict'},
                'evidence': self.evidence, 'notes': self.notes}


def reviewed(reviews, subject, predicate):
    for item in reviews:
        if (item.get('subject') == subject and item.get('predicate') == predicate and item.get('status') == 'reviewed'
                and item.get('reviewer') and item.get('basis')):
            return True
    return False


def load_service_events(path):
    events = []
    with Path(path).open(encoding='utf-8-sig') as stream:
        for number, line in enumerate(stream, 1):
            if line.strip():
                record = json.loads(line)['raw']['event']
                if record.get('event_id') == 7045:
                    data = {item['name']: item['value'] for item in record['data']}
                    events.append({'record_id': record['record_id'], 'utc': record['utc'], 'name': data.get('ServiceName'),
                                   'image_path': data.get('ImagePath'), 'type': data.get('ServiceType'),
                                   'account': data.get('AccountName'), 'ref': '%s#line=%d' % (path, number)})
    return events


def disk_paths(evidence_path, wanted, mappings):
    """Stream the normalized collection; keep filesystem records whose resolved path is wanted."""
    found = {}
    with Path(evidence_path).open(encoding='utf-8-sig') as stream:
        for number, line in enumerate(stream, 1):
            if '"source_tool":"autopsy.tsk_files"' not in line:
                continue
            record = json.loads(line)
            norm = normalize_path(record.get('original_path') or record.get('path'), mappings)
            if norm['resolved'] and norm['normalized'] in wanted:
                found.setdefault(norm['normalized'], []).append(
                    {'ref': '%s#line=%d' % (evidence_path, number), 'allocated': record.get('allocated'),
                     'md5': record.get('md5'), 'path': norm['normalized'],
                     'mft': [(record.get('raw') or {}).get('meta_addr'), (record.get('raw') or {}).get('meta_seq')]})
    return found


def process_instances(tables):
    items = defaultdict(dict)
    for name in ('windows.pslist', 'windows.psscan'):
        for row in tables.get(name, []):
            key = (artifact_pid(row), row.get('CreateTime'), row.get('ImageFileName'))
            items[artifact_pid(row)][key] = row
    return items


def executable_path(command):
    token = first_token(command)
    return token if re.match(r'^(?:[a-zA-Z]:\\|\\)', token) or token.casefold().startswith('%systemroot%') else None


def build_service_findings(spec, events, tables, provenance, mappings, disk, capture, reviews):
    svc = {}
    for number, row in enumerate(tables.get('windows.svcscan', []), 1):
        svc.setdefault(str(row.get('Name') or '').casefold(), []).append((number, row))
    instances = process_instances(tables)
    out = []
    for event in events:
        finding = Finding(spec, 'A01', 'service|%s|record=%s' % (str(event['name']).casefold(), event['record_id']))
        finding.add('windows.Get-WinEvent|service_install_event', event['ref'],
                    'Service %r installed with ImagePath %r (type %s, account %s) at %s' % (
                        event['name'], event['image_path'], event['type'], event['account'], event['utc']))
        matches = svc.get(str(event['name']).casefold(), [])
        if len(matches) == 1:
            number, row = matches[0]
            ref = '%s#flattened-row=%d' % (provenance.get('windows.svcscan'), number)
            finding.add('volatility.svcscan', ref, 'svcscan configuration: Binary=%r Binary(Registry)=%r start=%s state=%s pid=%s' % (
                row.get('Binary'), row.get('Binary (Registry)'), row.get('Start'), row.get('State'), row.get('PID')))
            configured = row.get('Binary (Registry)') or row.get('Binary')
            if canonical_command(configured, mappings) == canonical_command(event['image_path'], mappings):
                finding.link('service_name_and_context', 'install_event', 'svcscan',
                             'same service name and identical command after systemroot expansion')
            else:
                finding.contradictions.append('service_command_differs_between_event_and_svcscan')
            pid = artifact_pid(row)
            if pid is not None and len(instances.get(pid, {})) == 1:
                proc = next(iter(instances[pid].values()))
                finding.add('volatility.pslist', '%s#pid=%s' % (provenance.get('windows.pslist'), pid),
                            'Hosting process %s PID %s created %s' % (proc.get('ImageFileName'), pid, proc.get('CreateTime')))
        elif len(matches) > 1:
            finding.contradictions.append('ambiguous_svcscan_match')
        else:
            finding.notes.append('no_svcscan_record_found_in_available_inventory')
        path = executable_path(event['image_path'])
        norm = normalize_path(path, mappings) if path else None
        if norm and norm['resolved'] and not is_interpreter(event['image_path']):
            for item in disk.get(norm['normalized'], []):
                finding.add('autopsy.tsk_files', item['ref'], 'Disk record at %s (allocated=%s)' % (item['path'], item['allocated']))
                finding.link('resolved_full_path', 'install_event', 'disk_record', item['path'])
        started, installed = parse_time(event['utc']), None
        if capture and started:
            # capture time is recorded to whole seconds: a difference inside that resolution is unknown, not contradicted
            gap = (started - capture).total_seconds()
            finding.temporal = 'compatible_known' if gap <= 0 else ('unknown' if gap < 1 else 'contradicted')
            if finding.temporal == 'contradicted':
                finding.contradictions.append('install_event_after_memory_capture')
        behaviors = command_behaviors(event['image_path'])
        interp = is_interpreter(event['image_path'])
        finding.predicate('A01.1_interpreter_pipe_write_or_download_execute',
                          interp and bool(behaviors & {'pipe_write', 'download_and_execute'}),
                          'interpreter=%s behaviors=%s' % (interp, sorted(behaviors)))
        finding.predicate('A01.2_reviewed_malicious_content',
                          reviewed(reviews, finding.subject, 'reviewed_malicious_content'),
                          'requires a review entry with status reviewed', review_key='reviewed_malicious_content')
        out.append(finding)
    return out


def build_command_findings(spec, tables, provenance, reviews):
    out = []
    instances = process_instances(tables)
    for number, row in enumerate(tables.get('windows.cmdline', []), 1):
        pid, args = artifact_pid(row), row.get('Args')
        behaviors = command_behaviors(args)
        if not behaviors:
            continue
        finding = Finding(spec, 'A02', 'cmdline|pid=%s|row=%d' % (pid, number))
        finding.add('volatility.cmdline', '%s#flattened-row=%d' % (provenance.get('windows.cmdline'), number),
                    'Process %s PID %s command line %r' % (row.get('Process'), pid, args))
        if len(instances.get(pid, {})) == 1:
            finding.link('service_name_and_context', 'cmdline', 'pslist', 'single process instance for PID')
        finding.predicate('A02.1_encoded_command_download_execute_or_credential_access',
                          bool(behaviors & {'encoded_download_and_execute', 'encoded_credential_access'}), sorted(behaviors))
        finding.predicate('A02.2_explicit_download_and_execute', 'download_and_execute' in behaviors, sorted(behaviors))
        out.append(finding)
    return out


def build_region_findings(spec, tables, provenance, threads, thread_ref, reviews):
    out = []
    instances = process_instances(tables)
    for number, region in enumerate(tables.get('windows.malfind', []), 1):
        if region.get('PrivateMemory') != 1 or 'EXECUTE' not in str(region.get('Protection') or '').upper():
            continue
        pid, start, end = artifact_pid(region), region.get('Start VPN'), region.get('End VPN')
        finding = Finding(spec, 'A03', 'region|pid=%s|start=%s' % (pid, hex(start) if isinstance(start, int) else start))
        finding.add('volatility.malfind', '%s#flattened-row=%d' % (provenance.get('windows.malfind'), number),
                    'Private %s region %s-%s in %s PID %s' % (region.get('Protection'), start, end, region.get('Process'), pid))
        proc = next(iter(instances[pid].values())) if len(instances.get(pid, {})) == 1 else None
        if proc:
            finding.link('service_name_and_context', 'malfind', 'pslist', 'single process instance for PID')
        else:
            finding.contradictions.append('process_instance_ambiguous_or_absent')
        overlap = [t for t in threads if artifact_pid(t) == pid and isinstance(t.get('Win32StartAddress'), int)
                   and isinstance(start, int) and isinstance(end, int) and start <= t['Win32StartAddress'] <= end]
        for item in overlap:
            finding.add('volatility.threads', '%s#tid=%s' % (thread_ref, item.get('TID')),
                        'Thread %s Win32 start address %s inside region (created %s)' % (
                            item.get('TID'), hex(item['Win32StartAddress']), item.get('CreateTime')))
        finding.temporal = 'unknown'
        if proc and overlap and parse_time(proc.get('CreateTime')):
            created = parse_time(proc['CreateTime'])
            times = [parse_time(t.get('CreateTime')) for t in overlap]
            if all(times):
                finding.temporal = 'compatible_known' if all(t >= created for t in times) else 'contradicted'
        finding.predicate('A03.1_thread_start_in_region_and_reviewed_payload_structure',
                          bool(overlap) and reviewed(reviews, finding.subject, 'payload_structure'),
                          'thread_overlap=%d; payload structure requires a review entry' % len(overlap),
                          review_key='payload_structure')
        finding.predicate('A03.2_reviewed_injection_payload_evidence',
                          reviewed(reviews, finding.subject, 'injection_payload_evidence'),
                          'requires a review entry with status reviewed', review_key='injection_payload_evidence')
        out.append(finding)
    return out


def build_loader_findings(spec, loader_rows, reviews):
    out = []
    for row in loader_rows:
        if row['review_status'] != 'requires_context_review':
            continue
        finding = Finding(spec, 'A05', 'loader|pid=%s|base=%s' % (row['pid'], hex(row['base']) if isinstance(row['base'], int) else row['base']))
        finding.add('volatility.ldrmodules', row['source_reference'],
                    '%s PID %s flags %s mapped %s; unmet baseline checks %s' % (
                        row['process'], row['pid'], row['flags'], row['mapped_path'], row['unmet_checks']))
        finding.predicate('A05.1_visibility_disagreement_survives_baseline_unloading_and_stale_review',
                          reviewed(reviews, finding.subject, 'survives_review'),
                          'requires a review entry with status reviewed', review_key='survives_review')
        out.append(finding)
    return out


def rank(findings):
    return sorted(findings, key=Finding.sort_key)


def write_outputs(output, ranked, spec, metadata, not_evaluable):
    output.mkdir(parents=True, exist_ok=False)
    rows = [f.as_dict() for f in ranked]
    (output / 'ranked_findings.json').write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding='utf-8')
    with (output / 'ranked_findings.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.writer(stream)
        writer.writerow(['rank', 'finding_id', 'tier', 'action', 'subject', 'corroboration_groups', 'identity', 'temporal',
                         'satisfied_predicates', 'contradictions', 'maliciousness'])
        for position, f in enumerate(ranked, 1):
            writer.writerow([position, f.id, f.tier(), f.action, f.subject, ';'.join(f.groups()), f.identity, f.temporal,
                             ';'.join(k for k, v in f.predicates.items() if v['satisfied']), ';'.join(f.contradictions), 'not_assessed'])
    template = [dict(item, status='not_reviewed', reviewer=None, basis=None, source_refs=[], finding_id=f.id)
                for f in ranked for item in f.review_needed]
    (output / 'review_template.json').write_text(json.dumps(template, indent=2), encoding='utf-8')
    metadata.update({'tier_counts': dict(Counter(f.tier() for f in ranked)), 'finding_count': len(ranked),
                     'unmapped_families': dict(spec.unmapped), 'actions_not_evaluable': not_evaluable})
    (output / 'run_metadata.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')


def analyze(runs, spec_path, config, service_events, threads_path=None, disk_evidence=None, reviews=None, path_map=None):
    """Pure computation of findings: same inputs always give the same ordered findings."""
    mappings = config.get('path_mappings') or {}
    capture = parse_time(config.get('memory_capture_utc'))
    spec = Spec(spec_path)
    tables, provenance, statuses = load_runs([Path(r) for r in runs], path_map)
    reviews = reviews or []
    threads = []
    if threads_path:
        threads = [r for r in json.loads(Path(threads_path).read_text(encoding='utf-8-sig')) if isinstance(r, dict)]
    events = load_service_events(service_events)
    wanted = {n['normalized'] for n in (normalize_path(executable_path(e['image_path']), mappings) for e in events
                                         if executable_path(e['image_path']) and not is_interpreter(e['image_path'])) if n['resolved']}
    disk = disk_paths(disk_evidence, wanted, mappings) if disk_evidence else {}
    loader_rows = loader_review(tables, provenance, mappings)
    findings = (build_service_findings(spec, events, tables, provenance, mappings, disk, capture, reviews)
                + build_command_findings(spec, tables, provenance, reviews)
                + build_region_findings(spec, tables, provenance, threads, threads_path, reviews)
                + build_loader_findings(spec, loader_rows, reviews))
    return {'findings': findings, 'ranked': rank(findings), 'spec': spec, 'tables': tables, 'provenance': provenance,
            'statuses': statuses, 'loader_rows': loader_rows, 'events': events, 'capture': capture, 'mappings': mappings}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Deterministic rule-based ranking of candidate actions; no verdicts.')
    parser.add_argument('runs', nargs='+', help='memory run directories')
    parser.add_argument('--spec', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--service-events', required=True)
    parser.add_argument('--threads', help='Volatility threads JSON')
    parser.add_argument('--disk-evidence', help='normalized collection evidence.jsonl')
    parser.add_argument('--reviews', help='analyst review JSON; only status=reviewed counts')
    parser.add_argument('--path-map', action='append', default=[], metavar='SRC=DST', help='translate stored source path prefixes')
    parser.add_argument('--output', required=True)
    parser.add_argument('--mode', choices=['development'], default='development',
                        help='frozen evaluation mode is intentionally not available before the freeze step')
    args = parser.parse_args(argv)
    config = json.loads(Path(args.config).read_text(encoding='utf-8-sig'))
    reviews = json.loads(Path(args.reviews).read_text(encoding='utf-8-sig')) if args.reviews else []
    path_map = [tuple(item.split('=', 1)) for item in args.path_map]
    result = analyze(args.runs, args.spec, config, args.service_events, args.threads, args.disk_evidence, reviews, path_map)
    spec, statuses, findings = result['spec'], result['statuses'], result['findings']
    ranked = rank(findings)
    inputs = {'spec': args.spec, 'config': args.config, 'service_events': args.service_events, 'threads': args.threads,
              'reviews': args.reviews}
    metadata = {'run_mode': args.mode, 'frozen': False, 'specification_version': spec.version, 'specification_status': spec.status,
                'run_utc': datetime.now(timezone.utc).isoformat(), 'extraction_statuses': statuses,
                'memory_capture_utc': config.get('memory_capture_utc'), 'reviews_supplied': len(reviews),
                'code_sha256': {name: sha256_file(Path(__file__).with_name(name))
                                for name in ('memlink_rank.py', 'memlink_assess.py', 'memlink_core.py')},
                'input_sha256': {k: sha256_file(v) for k, v in inputs.items() if v},
                'relevant_groups_assumption': {k: sorted(v) for k, v in RELEVANT_GROUPS.items()},
                'disk_evidence_used': args.disk_evidence}
    write_outputs(Path(args.output), ranked, spec, metadata, NOT_EVALUABLE)
    print('%d findings ranked; tiers %s; mode=development; no maliciousness verdicts' % (len(ranked), dict(Counter(f.tier() for f in ranked))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
