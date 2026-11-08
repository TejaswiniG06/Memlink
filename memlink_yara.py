"""Signature (YARA) corroboration as an independent, metadata-only layer.

    python -B memlink_yara.py sanitize --raw <vadyarascan json> --rules <rules.yar> --vadinfo <windows.vadinfo.json>
                                       --ranked <ranking/ranked_findings.json> --output <new folder>

* The raw plugin output (which contains matched bytes) is read once and never copied; only the rule
  name, string id, process, address and matched length are kept.
* A match is "verified" only if its address falls inside a VAD of the same process in the recorded
  vadinfo output. Unverified matches are kept but flagged and never used.
* Matches are compared with the behavioral findings (same process and address range) and shown as
  corroboration. They never change a tier, a predicate or a conclusion.
"""
import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def to_int(value):
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def flatten(rows):
    for row in rows:
        yield {k: v for k, v in row.items() if k != '__children'}
        yield from flatten(row.get('__children') or [])


def candidate_regions(ranked):
    """(pid, start, end, finding_id) for A03 findings, from the malfind observation text."""
    regions = []
    for finding in ranked:
        if finding['action'] != 'A03':
            continue
        pid_text, _, start_text = finding['subject'].partition('|pid=')[2].partition('|start=')
        pid, start = to_int(pid_text), to_int(start_text)
        end = None
        for observation in finding['observation']:
            text = observation['text']
            if text.startswith('Private ') and ' region ' in text:
                span = text.split(' region ', 1)[1].split(' in ', 1)[0]
                end = to_int(span.split('-')[1]) if '-' in span else None
        regions.append((pid, start, end, finding['finding_id']))
    return regions


def sanitize(raw_rows, vad_rows, ranked, rules_sha256):
    vads = defaultdict(list)
    for row in vad_rows:
        pid, start, end = to_int(row.get('PID')), to_int(row.get('Start VPN')), to_int(row.get('End VPN'))
        if None not in (pid, start, end):
            vads[pid].append((start, end, row))
    regions = candidate_regions(ranked)
    matches = []
    for row in flatten(raw_rows):
        pid, address = to_int(row.get('PID')), to_int(row.get('Offset'))
        value = row.get('Value')
        entry = {'rule': row.get('Rule'), 'component': row.get('Component'), 'pid': pid, 'address': address,
                 'address_hex': hex(address) if address is not None else None,
                 'matched_length': len(str(value)) if value is not None else None, 'vad': None, 'verified': False,
                 'candidate_finding': None}
        for start, end, vad in vads.get(pid, []):
            if address is not None and start <= address <= end:
                entry['vad'] = {'start': hex(start), 'end': hex(end), 'protection': vad.get('Protection'),
                                'private': vad.get('PrivateMemory'), 'file': vad.get('File')}
                entry['verified'] = True
                break
        for r_pid, r_start, r_end, finding_id in regions:
            if r_pid == pid and r_start is not None and r_end is not None and address is not None and r_start <= address <= r_end:
                entry['candidate_finding'] = finding_id
        matches.append(entry)
    matches.sort(key=lambda m: (m['pid'] if m['pid'] is not None else -1, m['address'] if m['address'] is not None else -1, str(m['rule']), str(m['component'])))
    verified = [m for m in matches if m['verified']]
    by_finding = defaultdict(set)
    for m in verified:
        if m['candidate_finding']:
            by_finding[m['candidate_finding']].add(m['rule'])
    findings_with = {f['finding_id'] for f in ranked if f['finding_id'] in by_finding}
    a03 = [f for f in ranked if f['action'] == 'A03']
    summary = {'matches': len(matches), 'verified_matches': len(verified), 'unverified_matches': len(matches) - len(verified),
               'rules_hit': dict(Counter(m['rule'] for m in verified)),
               'processes_with_matches': sorted({m['pid'] for m in verified if m['pid'] is not None}),
               'a03_candidates': len(a03), 'a03_candidates_with_signature': len([f for f in a03 if f['finding_id'] in findings_with]),
               'matches_outside_any_candidate_region': len([m for m in verified if not m['candidate_finding']]),
               'rules_sha256': rules_sha256,
               'note': 'Signature corroboration only. Rules were written from public knowledge of the family, so matches on this known case are expected and not blind validation. Matches never change a tier or conclusion.'}
    per_finding = {fid: sorted(rules) for fid, rules in by_finding.items()}
    return {'summary': summary, 'matches': matches, 'per_finding': per_finding}


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('sanitize')
    s.add_argument('--raw', required=True)
    s.add_argument('--rules', required=True)
    s.add_argument('--vadinfo', required=True)
    s.add_argument('--ranked', required=True)
    s.add_argument('--coverage', help='JSON describing which processes were scanned, timed out or not attempted')
    s.add_argument('--output', required=True, help='new folder')
    args = parser.parse_args(argv)
    raw = json.loads(Path(args.raw).read_text(encoding='utf-8-sig'))
    vad = list(flatten(json.loads(Path(args.vadinfo).read_text(encoding='utf-8-sig'))))
    ranked = json.loads(Path(args.ranked).read_text(encoding='utf-8'))
    result = sanitize(raw, vad, ranked, sha256_file(args.rules))
    if args.coverage:
        result['summary']['coverage'] = json.loads(Path(args.coverage).read_text(encoding='utf-8-sig'))
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'yara_matches.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result['summary'], indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
