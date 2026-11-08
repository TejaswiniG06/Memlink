import json
import tempfile
import unittest
from pathlib import Path

import memlink_adjudicate as ad

HERE = Path(__file__).resolve().parent


def finding(action='A01', satisfied=False, subject='s1', fid='F-1', tier=3):
    return {'finding_id': fid, 'action': action, 'subject': subject, 'tier': tier,
            'predicates': {'p': {'satisfied': satisfied, 'basis': 'x'}}}


class AdjudicationTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(dir=str(HERE))
        self.root = Path(self.folder.name)
        (self.root / 'events.jsonl').write_text('{"a":"alpha"}\n{"tool":"windows.Get-WinEvent","b":"beta pipe"}\n', encoding='utf-8')
        (self.root / 'rows.json').write_text(json.dumps([{'name': 'one', 'v': 1}, {'name': 'two', 'v': 2}]), encoding='utf-8')
        (self.root / 'disk.jsonl').write_text('{"source_tool":"autopsy.tsk_files","path":"c:\\\\x.exe"}\n', encoding='utf-8')

    def tearDown(self):
        self.folder.cleanup()

    def item(self, kind, tag, file='events.jsonl', locator=None, expect=('beta',)):
        return {'id': tag, 'kind': kind, 'file': file, 'locator': locator or {'line': 2}, 'expect': list(expect), 'statement': tag}

    def entry(self, verdict, items, **extra):
        base = {'subjects': ['s1'], 'verdict': verdict, 'author_kind': 'assistant', 'status': 'drafted_pending_user_confirmation',
                'evidence': items, 'conclusion': 'c', 'limitations': 'l',
                'alternatives_considered': [{'alternative': 'a', 'disposition': 'd'}]}
        base.update(extra)
        return base

    def check(self, entry, f=None):
        return ad.validate_entry(entry, f or finding(), str(self.root), [])

    def test_citations_must_resolve_and_contain_quoted_text(self):
        for bad in (self.item('behavioral', 'x', expect=('missing text',)), self.item('behavioral', 'x', locator={'line': 99}),
                    self.item('behavioral', 'x', file='nope.jsonl'), self.item('behavioral', 'x', expect=())):
            errors, verified, _ = self.check(self.entry('indeterminate', [bad], reason='r', would_resolve='w'))
            self.assertTrue(errors, bad)
            self.assertEqual(verified, [])

    def test_ranking_tier_ground_truth_and_reports_are_not_evidence(self):
        errors, _, _ = self.check(self.entry('indeterminate', [self.item('ranking_tier', 'x')], reason='r', would_resolve='w'))
        self.assertTrue(any('not allowed' in e for e in errors))
        for forbidden in ('evaluation/dc01_service_ground_truth.json', 'reports/DC01-coreupdater.md', 'notes/solution.txt', 'a.pdf'):
            with self.assertRaises(ad.RefError):
                ad.record_text(forbidden, {'line': 1}, str(self.root), [])

    def test_malicious_needs_verified_behavioral_or_content_evidence(self):
        weak = [self.item('context', 'a'), self.item('temporal', 'b', file='rows.json', locator={'index': 0}, expect=('one',))]
        errors, _, _ = self.check(self.entry('malicious_supported', weak, confidence='moderate'))
        self.assertTrue(any('behavioral or content' in e for e in errors))
        strong = [self.item('behavioral', 'a'), self.item('temporal', 'b', file='rows.json', locator={'index': 0}, expect=('one',))]
        errors, _, strength = self.check(self.entry('malicious_supported', strong, confidence='moderate'))
        self.assertEqual((errors, strength), ([], 'moderate'))

    def test_claimed_confidence_cannot_exceed_verified_strength(self):
        strong = [self.item('behavioral', 'a'), self.item('temporal', 'b', file='rows.json', locator={'index': 0}, expect=('one',))]
        errors, _, _ = self.check(self.entry('malicious_supported', strong, confidence='high'))
        self.assertTrue(any('exceeds' in e for e in errors))

    def test_benign_needs_positive_context_and_cannot_contradict_a_satisfied_predicate(self):
        items = [self.item('context', 'a'), self.item('identity', 'b', file='rows.json', locator={'index': 1}, expect=('two',))]
        self.assertEqual(self.check(self.entry('benign_supported', items, confidence='moderate'))[0], [])
        errors, _, _ = self.check(self.entry('benign_supported', items, confidence='moderate'), finding(satisfied=True))
        self.assertTrue(any('satisfied suspicion predicate' in e for e in errors))
        only_temporal = [self.item('temporal', 'a'), self.item('temporal', 'b', file='rows.json', locator={'index': 1}, expect=('two',))]
        errors, _, _ = self.check(self.entry('benign_supported', only_temporal, confidence='low'))
        self.assertTrue(errors)

    def test_indeterminate_needs_reason_and_resolution_and_attack_only_on_malicious(self):
        self.assertTrue(self.check(self.entry('indeterminate', []))[0])
        self.assertEqual(self.check(self.entry('indeterminate', [], reason='r', would_resolve='w'))[0], [])
        errors, _, _ = self.check(self.entry('indeterminate', [], reason='r', would_resolve='w', attack=[{'technique': 'T1055', 'supported_by': []}]))
        self.assertTrue(any('only on malicious' in e for e in errors))

    def test_attack_mapping_is_closed_per_action_and_cites_evidence(self):
        items = [self.item('behavioral', 'a'), self.item('temporal', 'b', file='rows.json', locator={'index': 0}, expect=('one',))]
        bad = self.entry('malicious_supported', items, confidence='moderate', attack=[{'technique': 'T1071', 'supported_by': ['a']}])
        self.assertTrue(any('not allowed' in e for e in self.check(bad)[0]))
        uncited = self.entry('malicious_supported', items, confidence='moderate', attack=[{'technique': 'T1543.003', 'supported_by': ['zzz']}])
        self.assertTrue(any('verified evidence ids' in e for e in self.check(uncited)[0]))
        good = self.entry('malicious_supported', items, confidence='moderate', attack=[{'technique': 'T1543.003', 'supported_by': ['a']}])
        self.assertEqual(self.check(good)[0], [])

    def test_assistant_authorship_cannot_be_marked_user_confirmed(self):
        errors, _, _ = self.check(self.entry('indeterminate', [], reason='r', would_resolve='w', status='user_confirmed'))
        self.assertTrue(any('user_confirmed' in e for e in errors))

    def test_every_finding_is_accounted_for_and_counted_with_must_match(self):
        ranked = [finding(subject='s1', fid='F-1'), finding(subject='s2', fid='F-2')]
        doc = {'entries': [self.entry('indeterminate', [], reason='r', would_resolve='w')]}
        results, unassessed, errors = ad.adjudicate(ranked, doc, str(self.root), [])
        self.assertEqual((len(results), unassessed, errors), (1, ['F-2'], []))
        both = [self.entry('indeterminate', [], reason='r', would_resolve='w', counted_with='F-2'),
                self.entry('benign_supported', [self.item('context', 'a'), self.item('identity', 'b', file='rows.json', locator={'index': 1}, expect=('two',))],
                           confidence='moderate', subjects=['s2'])]
        results, _, _ = ad.adjudicate(ranked, {'entries': both}, str(self.root), [])
        self.assertTrue(any('counted_with' in e for e in results[0]['validation_errors']))
        unknown = ad.adjudicate(ranked, {'entries': [self.entry('indeterminate', [], reason='r', would_resolve='w', subjects=['nope'])]}, str(self.root), [])
        self.assertIn('unknown subject nope', unknown[2])

    def test_layer_inference_keeps_event_logs_apart_from_disk_files(self):
        self.assertEqual(ad.infer_layer('x.jsonl', '{"tool": "windows.Get-WinEvent"}'), 'eventlog')
        self.assertEqual(ad.infer_layer('x.jsonl', '{"source_tool": "autopsy.tsk_files"}'), 'disk')
        self.assertEqual(ad.infer_layer('memory_runs/a/windows.pslist.json', ''), 'memory')

    def test_line_lookup_uses_offsets_and_handles_bom_free_lines(self):
        text, layer = ad.record_text('disk.jsonl', {'line': 1}, str(self.root), [])
        self.assertIn('autopsy.tsk_files', text)
        self.assertEqual(layer, 'disk')


if __name__ == '__main__':
    unittest.main()
