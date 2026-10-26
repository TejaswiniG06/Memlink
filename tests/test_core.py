import unittest
from memlink_core import normalize_record, normalize_path, normalize_time, correlate


class CorrelationTests(unittest.TestCase):
    def record(self, kind, **kwargs):
        row = dict(case_id='case', host_id='DC01', snapshot_id='capture',
                   artifact_type='process' if kind == 'memory' else 'mft', evidence_kind=kind,
                   source_file=kind+'.csv', source_record='1', path=r'C:\Windows\test.exe')
        row.update(kwargs)
        return normalize_record(row, {'case_id': row['case_id'], 'host_id': row['host_id']})

    def test_path_match_is_not_maliciousness(self):
        links = correlate([self.record('memory'), self.record('disk')])
        self.assertEqual(links[0]['strength'], 'moderate')
        self.assertEqual(links[0]['maliciousness'], 'not_assessed')

    def test_hosts_and_cases_isolated(self):
        self.assertEqual(correlate([self.record('memory'), self.record('disk', host_id='OTHER')]), [])
        self.assertEqual(correlate([self.record('memory'), self.record('disk', case_id='OTHER')]), [])

    def test_pid_alone_cannot_link(self):
        self.assertEqual(correlate([self.record('memory', pid='1', path=''), self.record('disk', pid='1', path='')]), [])

    def test_basename_is_weak(self):
        link = correlate([self.record('memory'), self.record('disk', path=r'D:\temp\test.exe')])[0]
        self.assertEqual(link['strength'], 'weak')

    def test_device_path_requires_mapping(self):
        self.assertFalse(normalize_path(r'\Device\HarddiskVolume1\test.exe')['resolved'])
        self.assertTrue(normalize_path(r'\Device\HarddiskVolume1\test.exe', {r'\Device\HarddiskVolume1': 'C:'})['resolved'])

    def test_timezone_and_original_preserved(self):
        self.assertEqual(normalize_path('C:\\Temp\\Stra\u00dfe-\u13d0.exe')['normalized'], 'C:\\Temp\\Stra\u00dfe-\u13d0.exe'.lower())
        self.assertIsNone(normalize_time('2020-09-18 10:00:00')['utc'])
        self.assertEqual(normalize_time('2020-09-18T10:00:00-06:00')['utc'], '2020-09-18T16:00:00+00:00')

    def test_hash_conflict_downgrades(self):
        link = correlate([self.record('memory', sha256='a'*64), self.record('disk', sha256='b'*64)])[0]
        self.assertEqual(link['strength'], 'weak')

    def test_md5_can_link_different_paths(self):
        link = correlate([self.record('memory', md5='a'*32), self.record('disk', path=r'D:\other.exe', md5='a'*32)])[0]
        self.assertIn('equal_md5', link['rules'])
        self.assertEqual(link['strength'], 'strong')

    def test_pid_reuse_not_identity(self):
        link = correlate([self.record('memory', pid='5', process_create_time='2020-09-18T00:00:00Z'), self.record('disk', pid='5', process_create_time='2020-09-19T00:00:00Z')])[0]
        self.assertNotIn('same_snapshot_process_identity', link['rules'])

    def test_missing_inputs_not_a_finding(self):
        self.assertEqual(correlate([self.record('memory')]), [])


if __name__ == '__main__':
    unittest.main()
