import json
import tempfile
import unittest
from pathlib import Path

import memlink_dashboard as dash
import memlink_rank as rk
import memlink_run as run
from memlink_assess import relocate

HERE = Path(__file__).resolve().parent


class DashboardTests(unittest.TestCase):
    def test_excerpt_drops_byte_dumps_and_truncates(self):
        text = json.dumps({'PID': 1, 'Hexdump': 'aa ' * 500, 'note': 'x' * 400, 'raw': {'Disasm': 'zz', 'k': 'v'}})
        out = dash.excerpt_text(text)
        self.assertNotIn('Hexdump', out)
        self.assertNotIn('Disasm', out)
        self.assertIn('...', out)
        self.assertLessEqual(len(dash.excerpt_text(json.dumps({'a': ['y' * 170] * 50}))), dash.MAX_EXCERPT + 20)

    def test_render_cannot_break_out_of_the_data_script(self):
        page = dash.render({'meta': {}, 'findings': [{'conclusion': '</script><b>x</b>'}], 'traces': [], 'checks': []})
        self.assertEqual(page.count('</script>'), 2)  # data block and code block only
        self.assertIn('<\\/script>', page)

    def test_trace_step_must_contain_its_quoted_text(self):
        with tempfile.TemporaryDirectory(dir=str(HERE)) as folder:
            root = Path(folder)
            (root / 'rec.jsonl').write_text('{"a":"alpha"}\n', encoding='utf-8')
            (root / 'ranking').mkdir()
            (root / 'adjudication').mkdir()
            (root / 'ranking' / 'ranked_findings.json').write_text('[]', encoding='utf-8')
            (root / 'ranking' / 'run_metadata.json').write_text('{}', encoding='utf-8')
            (root / 'adjudication' / 'adjudicated_findings.json').write_text('[]', encoding='utf-8')
            (root / 'verification_report.json').write_text('{"checks": []}', encoding='utf-8')
            step = {'time': None, 'layer': 'disk', 'label': 'l', 'note': 'n', 'file': 'rec.jsonl', 'locator': {'line': 1}, 'expect': ['alpha']}
            traces = root / 't.json'
            traces.write_text(json.dumps({'traces': [{'id': 't', 'title': 't', 'summary': 's', 'steps': [step]}]}), encoding='utf-8')
            self.assertEqual(len(dash.build_data(root, traces, str(root), [])['traces'][0]['steps']), 1)
            step['expect'] = ['beta']
            traces.write_text(json.dumps({'traces': [{'id': 't', 'title': 't', 'summary': 's', 'steps': [step]}]}), encoding='utf-8')
            with self.assertRaises(SystemExit):
                dash.build_data(root, traces, str(root), [])


class RunHelpersTests(unittest.TestCase):
    def test_relocate_handles_original_evidence_reference_spellings(self):
        maps = [(r'E:\cfreds capstone\MemLink\outputs\DC01', 'evidence_exports')]
        expected = 'evidence_exports/memory_runs/run/windows.psscan.json'
        self.assertEqual(relocate(r'E:\\cfreds capstone\\MemLink\\outputs\\DC01\\memory_runs\\run\\windows.psscan.json', maps).as_posix(), expected)
        self.assertEqual(relocate('E:/cfreds capstone/MemLink/outputs/DC01/memory_runs/run/windows.psscan.json', maps).as_posix(), expected)
        unrelated = 'E:/cfreds capstone/MemLink/outputs/DC010/other.json'
        self.assertEqual(relocate(unrelated, maps), Path(unrelated))

    def test_relocate_maps_a_stored_drive_prefix_without_changing_other_paths(self):
        mapped = relocate('E:\\cfreds capstone\\x\\file.json', [('E:\\cfreds capstone\\', '/mnt/e/')])
        self.assertEqual(mapped.as_posix(), '/mnt/e/x/file.json')
        self.assertEqual(relocate('rel/file.json', [('E:\\', '/mnt/e/')]).as_posix(), 'rel/file.json')

    def test_review_gate_flags_a_satisfied_review_predicate_without_a_reviewed_entry(self):
        spec = rk.Spec(str(HERE.parent / 'rules' / 'assessment.v1.draft.json'))
        finding = rk.Finding(spec, 'A03', 'region|pid=1|start=0x1')
        finding.predicate('A03.2_reviewed_injection_payload_evidence', True, 'forced')
        checks = run.Checks()
        run.predicate_gate([finding], [], checks)
        self.assertEqual(checks.items[0]['status'], 'fail')
        good = [{'subject': finding.subject, 'predicate': 'injection_payload_evidence', 'status': 'reviewed', 'reviewer': 'r', 'basis': 'b'}]
        checks = run.Checks()
        run.predicate_gate([finding], good, checks)
        self.assertEqual(checks.items[0]['status'], 'pass')
        proposed = [dict(good[0], status='proposed')]
        checks = run.Checks()
        run.predicate_gate([finding], proposed, checks)
        self.assertEqual(checks.items[0]['status'], 'fail')

    def test_canonical_hash_is_order_stable_for_keys_but_sensitive_to_content(self):
        self.assertEqual(run.canonical([{'a': 1, 'b': 2}]), run.canonical([{'b': 2, 'a': 1}]))
        self.assertNotEqual(run.canonical([{'a': 1}]), run.canonical([{'a': 2}]))


if __name__ == '__main__':
    unittest.main()
