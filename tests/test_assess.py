import unittest
import json
import tempfile
from pathlib import Path
from memlink_assess import assess, load_runs, artifact_pid
from memlink_pipeline import sha256


class ProcessAssessmentTests(unittest.TestCase):
    def test_loader_pid_alias_retains_flagged_observations(self):
        process = {'PID': 12, 'ImageFileName': 'example.exe', 'PPID': 0}
        loader = {'Pid': 12, 'InLoad': False, 'InInit': False, 'InMem': False}
        rows = assess({'windows.pslist': [process], 'windows.ldrmodules': [loader]},
                      {'windows.pslist': 'list.json'})
        self.assertEqual(rows[0]['loader_flag_rows'], 1)
        self.assertIn('loader_flags_require_context', rows[0]['reasons'])
        self.assertEqual(rows[0]['analyst_verdict'], 'not_reviewed')
        self.assertNotIn('PID', loader)

    def test_conflicting_pid_aliases_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            artifact_pid({'PID': 12, 'Pid': 13})
        self.assertEqual(artifact_pid({'Pid': '12'}), 12)

    def test_failed_retry_does_not_reuse_stale_artifact(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temp:
            root = Path(temp)
            root.resolve().relative_to(Path(__file__).resolve().parent)
            source = root / 'processes.json'
            source.write_text('[{"PID": 4}]')
            identity = dict(case_id='c', host_id='h', snapshot_id='s', image_sha256='abc')
            roots = []
            for name, status in [('first', 'success'), ('retry', 'failed')]:
                folder = root / name
                folder.mkdir()
                (folder / 'manifest.json').write_text(json.dumps(dict(identity, plugins={
                    'windows.pslist': {'status':status, 'source_file':str(source), 'sha256':sha256(source)}})))
                roots.append(folder)
            tables, _, statuses = load_runs(roots)
            self.assertNotIn('windows.pslist', tables)
            self.assertEqual(statuses['windows.pslist'], 'failed')

    def test_terminated_scan_object_and_pid_reuse(self):
        active = {'PID': 5, 'PPID': 0, 'ImageFileName': 'new.exe', 'CreateTime': '2020-09-19T00:00:00Z', 'ExitTime': None}
        old = {'PID': 5, 'PPID': 0, 'ImageFileName': 'old.exe', 'CreateTime': '2020-09-18T00:00:00Z', 'ExitTime': '2020-09-18T01:00:00Z'}
        rows = assess({'windows.pslist': [active], 'windows.psscan': [active, old]}, {'windows.pslist': 'list.json', 'windows.psscan': 'scan.json'})
        self.assertEqual(len(rows), 2)
        self.assertIn('scan_only_exited_object', rows[1]['reasons'])
        self.assertEqual(rows[0]['pid_instance_count'], 2)
        self.assertTrue(all(r['analyst_verdict'] == 'not_reviewed' for r in rows))

    def test_all_malfind_protections_retained(self):
        process = {'PID': 4, 'ImageFileName': 'test', 'PPID': 0}
        rows = assess({'windows.pslist': [process], 'windows.malfind': [{'PID': 4, 'Protection': 'PAGE_EXECUTE_READ'}]}, {'windows.pslist': 'list.json'})
        self.assertEqual(rows[0]['malfind_protections'], {'PAGE_EXECUTE_READ': 1})


if __name__ == '__main__':
    unittest.main()
