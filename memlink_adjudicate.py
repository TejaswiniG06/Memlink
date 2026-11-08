"""Evidence-backed adjudication layer, separate from the ranking engine.

Ranking (memlink_rank.py) says what to look at first. This module records and
*checks* conclusions about each candidate: malicious_supported, benign_supported
or indeterminate. Safeguards enforced here:
  * every cited record must resolve to a real record and contain the quoted text;
  * ranking tiers, ground-truth files, reports and published solutions are not evidence;
  * malicious_supported needs verified behavioral/content evidence of >=2 kinds;
  * benign_supported needs a verified identity/baseline/context line and may not
    contradict a satisfied suspicion predicate;
  * claimed confidence cannot exceed what the verified evidence supports;
  * ATT&CK ids only on malicious_supported and only from a closed per-action list;
  * every ranked finding must be accounted for - nothing silently drops out;
  * authorship is recorded; assistant-drafted conclusions are never marked user-confirmed.
"""
import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

from memlink_assess import flatten, relocate

VERDICTS = ('malicious_supported', 'benign_supported', 'indeterminate')
KINDS = {'behavioral', 'content', 'network', 'temporal', 'identity', 'baseline', 'context', 'logon'}
POSITIVE_BENIGN_KINDS = {'identity', 'baseline', 'context'}
MALICIOUS_CORE_KINDS = {'behavioral', 'content'}
CONFIDENCE = ('low', 'moderate', 'high')
FORBIDDEN_SOURCE = re.compile(r'(^|[\\/])(evaluation|reports)[\\/]|ground[_-]?truth|solution|\.pdf($|#)|dc01-coreupdater', re.I)
ATTACK_ALLOWED = {'A01': {'T1543.003', 'T1569.002', 'T1134.001'}, 'A02': {'T1059'}, 'A03': {'T1055', 'T1620'}, 'A05': set()}
AUTHOR_KINDS = ('assistant', 'user')
STATUSES = ('drafted_pending_user_confirmation', 'user_confirmed')


_OFFSETS = {}


def _line_offsets(path):
    """Byte offset of each line, built once per file so large inputs are scanned once."""
    key = str(path)
    if key not in _OFFSETS:
        offsets, position = [], 0
        with path.open('rb') as stream:
            for raw in stream:
                offsets.append(position)
                position += len(raw)
        _OFFSETS[key] = offsets
    return _OFFSETS[key]


class RefError(Exception):
    pass


def translate(path, maps):
    return relocate(path, maps)


def record_text(file, locator, root, maps):
    """Return (record text, layer) for a cited record."""
    if FORBIDDEN_SOURCE.search(str(file)):
        raise RefError('forbidden evidence source: %s' % file)
    path = translate(file, maps)
    if not path.is_absolute():
        path = Path(root) / path
    if not path.is_file():
        raise RefError('file not found: %s' % file)
    name = path.name.lower()
    if 'line' in locator:
        offsets = _line_offsets(path)
        if not 1 <= locator['line'] <= len(offsets):
            raise RefError('line %s not found in %s' % (locator['line'], file))
        with path.open('rb') as stream:
            stream.seek(offsets[locator['line'] - 1])
            line = stream.readline().decode('utf-8-sig', errors='replace')
        return line, infer_layer(str(file), line)
    data = json.loads(path.read_text(encoding='utf-8-sig'))
    if 'index' in locator:
        items = data if isinstance(data, list) else None
        if items is None or not 0 <= locator['index'] < len(items):
            raise RefError('index %s not found in %s' % (locator['index'], file))
        return json.dumps(items[locator['index']], ensure_ascii=False), infer_layer(str(file), '')
    if 'flat' in locator:
        rows = list(flatten(data))
        if not 1 <= locator['flat'] <= len(rows):
            raise RefError('flattened row %s not found in %s' % (locator['flat'], file))
        return json.dumps(rows[locator['flat'] - 1], ensure_ascii=False), infer_layer(str(file), '')
    raise RefError('unsupported locator %r for %s' % (locator, name))


def infer_layer(file, text):
    """Provenance layer: event-log records (even if the evtx sits on disk) are their own layer."""
    lowered = file.lower()
    if '"source_tool":"autopsy.tsk_files"' in text.replace('": "', '":"'):
        return 'disk'
    if 'get-winevent' in text.lower() or any(k in lowered for k in ('event', 'security')):
        return 'eventlog'
    if any(k in lowered for k in ('memory_runs', 'pid3724_regions', 'threads')):
        return 'memory'
    return 'other'


def verify_item(item, root, maps):
    problems = []
    if item.get('kind') not in KINDS:
        problems.append('evidence %s: kind %r not allowed (ranking tier and verdicts are not evidence)' % (item.get('id'), item.get('kind')))
        return None, problems
    expects = item.get('expect') or []
    if not expects:
        problems.append('evidence %s: needs at least one quoted expect string' % item.get('id'))
        return None, problems
    try:
        text, layer = record_text(item['file'], item['locator'], root, maps)
    except (RefError, KeyError, json.JSONDecodeError, OSError) as error:
        problems.append('evidence %s: %s' % (item.get('id'), error))
        return None, problems
    lowered = text.casefold()
    for needle in expects:
        if str(needle).casefold() not in lowered and str(needle).casefold().replace('\\', '\\\\') not in lowered:
            problems.append('evidence %s: record does not contain %r' % (item.get('id'), needle))
    if problems:
        return None, problems
    return {'id': item['id'], 'kind': item['kind'], 'layer': layer, 'file': item['file'], 'locator': item['locator'],
            'statement': item.get('statement')}, []


def strength(verified):
    kinds, layers = {v['kind'] for v in verified}, {v['layer'] for v in verified}
    if len(verified) >= 3 and len(kinds) >= 3 and len(layers) >= 2:
        return 'high'
    if len(verified) >= 2 and len(kinds) >= 2:
        return 'moderate'
    return 'low' if verified else 'none'


def validate_entry(entry, finding, root, maps):
    errors, verified = [], []
    verdict = entry.get('verdict')
    if verdict not in VERDICTS:
        errors.append('verdict must be one of %s' % (VERDICTS,))
    if entry.get('author_kind') not in AUTHOR_KINDS or entry.get('status') not in STATUSES:
        errors.append('author_kind/status missing or invalid')
    if entry.get('author_kind') == 'assistant' and entry.get('status') == 'user_confirmed':
        errors.append('assistant-authored entries cannot be marked user_confirmed')
    if not entry.get('conclusion') or not entry.get('limitations'):
        errors.append('conclusion and limitations are required')
    for item in entry.get('evidence') or []:
        ok, problems = verify_item(item, root, maps)
        errors += problems
        if ok:
            verified.append(ok)
    ids = [i.get('id') for i in entry.get('evidence') or []]
    if len(ids) != len(set(ids)):
        errors.append('duplicate evidence ids')
    computed = strength(verified)
    kinds = {v['kind'] for v in verified}
    claimed = entry.get('confidence')
    if verdict in ('malicious_supported', 'benign_supported'):
        if claimed not in CONFIDENCE:
            errors.append('confidence required')
        elif CONFIDENCE.index(claimed) > (CONFIDENCE.index(computed) if computed in CONFIDENCE else -1):
            errors.append('claimed confidence %s exceeds verified evidence strength %s' % (claimed, computed))
        if not entry.get('alternatives_considered'):
            errors.append('alternatives_considered required for a supported verdict')
        else:
            for alt in entry['alternatives_considered']:
                if not alt.get('alternative') or not alt.get('disposition'):
                    errors.append('each alternative needs alternative and disposition')
    if verdict == 'malicious_supported':
        if computed not in ('moderate', 'high') or not kinds & MALICIOUS_CORE_KINDS:
            errors.append('malicious_supported needs >=2 verified evidence kinds including behavioral or content')
        if entry.get('attack'):
            allowed = ATTACK_ALLOWED.get(finding['action'], set())
            for mapping in entry['attack']:
                if mapping.get('technique') not in allowed:
                    errors.append('technique %s not allowed for %s' % (mapping.get('technique'), finding['action']))
                if not set(mapping.get('supported_by') or []) <= set(ids) or not mapping.get('supported_by'):
                    errors.append('attack mapping must cite verified evidence ids')
    else:
        if entry.get('attack'):
            errors.append('attack mapping only on malicious_supported')
    if verdict == 'benign_supported':
        if computed not in ('moderate', 'high') or not kinds & POSITIVE_BENIGN_KINDS:
            errors.append('benign_supported needs >=2 verified kinds including identity, baseline or context')
        if any(p['satisfied'] for p in finding['predicates'].values()):
            errors.append('benign_supported conflicts with a satisfied suspicion predicate; use indeterminate or malicious_supported')
        if kinds & MALICIOUS_CORE_KINDS and 'content' in kinds and entry.get('content_shows_suspicious'):
            errors.append('benign_supported cannot cite suspicious content')
    if verdict == 'indeterminate' and not (entry.get('reason') and entry.get('would_resolve')):
        errors.append('indeterminate needs reason and would_resolve')
    return errors, verified, computed


def adjudicate(ranked, doc, root, maps):
    by_subject = {f['subject']: f for f in ranked}
    by_id = {f['finding_id']: f for f in ranked}
    entries, errors = {}, []
    for entry in doc.get('entries', []):
        for subject in entry.get('subjects', []):
            if subject not in by_subject:
                errors.append('unknown subject %s' % subject)
                continue
            if subject in entries:
                errors.append('duplicate adjudication for %s' % subject)
                continue
            entries[subject] = entry
    results, unassessed = [], []
    for finding in ranked:
        entry = entries.get(finding['subject'])
        if entry is None:
            unassessed.append(finding['finding_id'])
            continue
        own = dict(entry)
        own['evidence'] = list(entry.get('evidence') or []) + [
            dict(e, id='%s:%s' % (finding['finding_id'], e['id'])) for e in
            (entry.get('member_evidence') or {}).get(finding['subject'], [])]
        problems, verified, computed = validate_entry(own, finding, root, maps)
        counted = entry.get('counted_with')
        if counted:
            other = by_id.get(counted)
            other_entry = entries.get(other['subject']) if other else None
            if other_entry is None or other_entry.get('verdict') != entry.get('verdict') or counted == finding['finding_id']:
                problems.append('counted_with must name another finding with the same verdict')
        results.append({'finding_id': finding['finding_id'], 'action': finding['action'], 'subject': finding['subject'],
                        'review_priority_tier': finding['tier'], 'verdict': entry.get('verdict'),
                        'confidence': entry.get('confidence'), 'verified_evidence_strength': computed,
                        'conclusion': entry.get('conclusion'), 'counted_with': counted,
                        'alternatives_considered': entry.get('alternatives_considered'), 'limitations': entry.get('limitations'),
                        'reason': entry.get('reason'), 'would_resolve': entry.get('would_resolve'),
                        'attack': entry.get('attack'), 'evidence_verified': verified,
                        'author_kind': entry.get('author_kind'), 'status': entry.get('status'), 'validation_errors': problems})
    return results, unassessed, errors


def write_outputs(output, results, unassessed, doc_errors, meta):
    output.mkdir(parents=True, exist_ok=False)
    (output / 'adjudicated_findings.json').write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding='utf-8')
    with (output / 'adjudicated_findings.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.writer(stream)
        writer.writerow(['finding_id', 'action', 'subject', 'review_priority_tier', 'verdict', 'confidence', 'verified_evidence_strength',
                         'counted_with', 'status', 'validation_errors', 'conclusion'])
        for r in results:
            writer.writerow([r['finding_id'], r['action'], r['subject'], r['review_priority_tier'], r['verdict'], r['confidence'],
                             r['verified_evidence_strength'], r['counted_with'], r['status'], '; '.join(r['validation_errors']), r['conclusion']])
    invalid = [r['finding_id'] for r in results if r['validation_errors']]
    counted = [r for r in results if not r['counted_with']]
    meta.update({'findings_adjudicated': len(results), 'unassessed_finding_ids': unassessed, 'document_errors': doc_errors,
                 'entries_with_validation_errors': invalid,
                 'verdict_counts_unique_conclusions': dict(Counter(r['verdict'] for r in counted)),
                 'verdict_counts_all_findings': dict(Counter(r['verdict'] for r in results)),
                 'valid': not (invalid or doc_errors)})
    (output / 'adjudication_metadata.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    return meta


def write_report(output, ranked, results, meta):
    """Markdown report: review priority (rank/tier) beside the evidence-backed verdict."""
    by_id = {r['finding_id']: r for r in results}
    lines = ['# MemLink adjudication report (development, not frozen)', '',
             'Authorship: %s. Status: %s. Verdicts are separate from the review-priority tier.' % (
                 ', '.join(sorted({r['author_kind'] for r in results})), ', '.join(sorted({r['status'] for r in results}))), '',
             'Findings adjudicated: %d; unassessed: %d; validation errors: %d.' % (
                 len(results), len(meta['unassessed_finding_ids']), len(meta['entries_with_validation_errors'])),
             'Unique conclusions: %s.' % meta['verdict_counts_unique_conclusions'], '']
    disagreements = [r for r in results if (r['verdict'] == 'malicious_supported' and r['review_priority_tier'] == 3)]
    for title, verdict in (('Malicious supported', 'malicious_supported'), ('Indeterminate', 'indeterminate'), ('Benign supported', 'benign_supported')):
        lines += ['## %s' % title, '']
        for position, finding in enumerate(ranked, 1):
            r = by_id[finding['finding_id']]
            if r['verdict'] != verdict:
                continue
            lines.append('- **#%d %s** (%s, tier %s, confidence %s, evidence %s)%s: %s' % (
                position, r['subject'], r['action'], r['review_priority_tier'], r['confidence'] or 'n/a', r['verified_evidence_strength'],
                ' [counted with %s]' % r['counted_with'] if r['counted_with'] else '', r['conclusion']))
            if verdict == 'indeterminate':
                lines.append('  - Reason: %s Would resolve: %s' % (r['reason'], r['would_resolve']))
            if r['attack']:
                lines.append('  - ATT&CK (supported): %s' % ', '.join(m['technique'] for m in r['attack']))
        lines.append('')
    lines += ['## Rank and verdict disagreements', '']
    lines += ['- %s: tier %s but %s - no closed predicate is satisfied, yet convergent evidence supports the verdict.' % (
        r['subject'], r['review_priority_tier'], r['verdict']) for r in disagreements] or ['- none']
    (output / 'adjudication_report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Validate and report evidence-backed adjudications; ranking is unchanged.')
    parser.add_argument('--ranked', required=True)
    parser.add_argument('--adjudications', required=True)
    parser.add_argument('--root', required=True, help='base directory for relative evidence paths')
    parser.add_argument('--map', action='append', default=[], metavar='SRC=DST', help='path prefix translation for stored Windows paths')
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    ranked = json.loads(Path(args.ranked).read_text(encoding='utf-8'))
    doc = json.loads(Path(args.adjudications).read_text(encoding='utf-8-sig'))
    maps = [tuple(item.split('=', 1)) for item in args.map]
    results, unassessed, doc_errors = adjudicate(ranked, doc, args.root, maps)
    from memlink_rank import sha256_file
    meta = {'mode': 'development', 'frozen': False, 'ranked_sha256': sha256_file(args.ranked),
            'adjudications_sha256': sha256_file(args.adjudications), 'code_sha256': sha256_file(__file__)}
    meta = write_outputs(Path(args.output), results, unassessed, doc_errors, meta)
    write_report(Path(args.output), ranked, results, meta)
    print('%d adjudicated; unassessed %d; valid=%s; unique conclusions %s' % (
        len(results), len(unassessed), meta['valid'], meta['verdict_counts_unique_conclusions']))
    return 0 if meta['valid'] and not unassessed else 1


if __name__ == '__main__':
    sys.exit(main())
