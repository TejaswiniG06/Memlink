import unittest
from memlink_assess import assess, loader_review

MAP = {'\\Windows': 'C:\\Windows'}


def tables(ldr, dll=(), vad=(), extra=None):
    process = {'PID': 10, 'PPID': 0, 'ImageFileName': 'example.exe', 'CreateTime': '2020-01-01T00:00:00+00:00', 'ExitTime': None}
    data = {'windows.pslist': [process], 'windows.ldrmodules': list(ldr),
            'windows.dlllist': list(dll), 'windows.vadinfo': list(vad)}
    data.update(extra or {})
    return data


def loader(base, path, flags, pid=10):
    keys = ('InLoad', 'InInit', 'InMem')
    return dict(Pid=pid, Process='example.exe', Base=base, MappedPath=path, **dict(zip(keys, flags)))


def vad(base, protection, private=0, file='', pid=10):
    return {'PID': pid, 'Start VPN': base, 'End VPN': base + 0xfff, 'Protection': protection,
            'PrivateMemory': private, 'File': file or None, 'Process': 'example.exe'}


MAIN = {'PID': 10, 'Process': 'example.exe', 'Base': 0x400000, 'Path': 'C:\\Windows\\System32\\example.exe'}
MAIN_ROW = loader(0x400000, '\\Windows\\System32\\example.exe', (True, False, True))
MAIN_VAD = vad(0x400000, 'PAGE_EXECUTE_WRITECOPY', 0, '\\Windows\\System32\\example.exe')
DATA_ROW = loader(0x500000, '\\Windows\\System32\\en-US\\example.exe.mui', (False, False, False))
DATA_VAD = vad(0x500000, 'PAGE_READONLY', 0, '\\Windows\\System32\\en-US\\example.exe.mui')


class LoaderBaselineTests(unittest.TestCase):
    def review(self, ldr, dll=(MAIN,), vads=(), mappings=MAP):
        return loader_review(tables(ldr, dll, vads), {'windows.ldrmodules': 'ldr.json'}, mappings)

    def test_b01_applies_only_with_all_context_verified(self):
        row = self.review([MAIN_ROW], vads=[MAIN_VAD])[0]
        self.assertEqual(row['baseline'], 'B01')
        self.assertEqual(row['unmet_checks'], [])
        self.assertEqual(row['review_status'], 'explained_by_baseline')

    def test_b01_not_applied_without_path_mapping_or_for_other_modules(self):
        self.assertIsNone(self.review([MAIN_ROW], vads=[MAIN_VAD], mappings=None)[0]['baseline'])
        other = loader(0x600000, '\\Windows\\System32\\other.dll', (True, False, True))
        row = self.review([other], vads=[vad(0x600000, 'PAGE_EXECUTE_WRITECOPY', 0, other['MappedPath'])])[0]
        self.assertIsNone(row['baseline'])
        self.assertIn('base_equals_first_loaded_main_image', row['unmet_checks'])

    def test_b01_not_applied_when_pid_has_multiple_instances(self):
        data = tables([MAIN_ROW], [MAIN], [MAIN_VAD])
        data['windows.psscan'] = [dict(data['windows.pslist'][0], CreateTime='2019-01-01T00:00:00+00:00')]
        row = loader_review(data, {}, MAP)[0]
        self.assertIsNone(row['baseline'])
        self.assertIn('single_process_instance_for_pid', row['unmet_checks'])

    def test_b02_applies_to_nonexecutable_file_backed_mapping(self):
        row = self.review([DATA_ROW], vads=[DATA_VAD])[0]
        self.assertEqual(row['baseline'], 'B02')
        self.assertEqual(row['vad_protection'], 'PAGE_READONLY')

    def test_b02_requires_vad_context_not_extension(self):
        row = self.review([DATA_ROW], vads=[])[0]
        self.assertIsNone(row['baseline'])
        self.assertIn('single_vad_at_base', row['unmet_checks'])

    def test_b02_not_applied_to_executable_or_private_regions(self):
        image = loader(0x700000, '\\Windows\\System32\\x.dll', (False, False, False))
        executable = self.review([image], vads=[vad(0x700000, 'PAGE_EXECUTE_WRITECOPY', 0, image['MappedPath'])])[0]
        self.assertIsNone(executable['baseline'])
        self.assertIn('vad_protection_without_execute', executable['unmet_checks'])
        private = loader(0x800000, None, (False, False, False))
        rwx = self.review([private], vads=[vad(0x800000, 'PAGE_EXECUTE_READWRITE', 1)])[0]
        self.assertIsNone(rwx['baseline'])
        self.assertEqual(rwx['review_status'], 'requires_context_review')

    def test_b02_requires_recorded_protection(self):
        for missing in (None, '', '  '):
            row = self.review([DATA_ROW], vads=[dict(DATA_VAD, Protection=missing)])[0]
            self.assertIsNone(row['baseline'])
            self.assertIn('vad_protection_recorded', row['unmet_checks'])
            self.assertIn('vad_protection_without_execute', row['unmet_checks'])

    def test_b02_not_applied_when_pid_reused(self):
        data = tables([DATA_ROW], [MAIN], [DATA_VAD])
        data['windows.psscan'] = [dict(data['windows.pslist'][0], CreateTime='2019-01-01T00:00:00+00:00')]
        row = loader_review(data, {}, MAP)[0]
        self.assertIsNone(row['baseline'])
        self.assertIn('single_process_instance_for_pid', row['unmet_checks'])

    def test_unmatched_flag_pattern_has_no_baseline(self):
        row = self.review([loader(0x900000, '\\Windows\\a.dll', (True, True, False))])[0]
        self.assertIsNone(row['baseline'])
        self.assertIn('baseline_defined_for_flag_pattern', row['unmet_checks'])

    def test_all_true_rows_not_flagged_and_flagged_rows_retained(self):
        good = loader(0xa00000, '\\Windows\\System32\\ok.dll', (True, True, True))
        rows = self.review([good, MAIN_ROW, DATA_ROW], vads=[MAIN_VAD, DATA_VAD])
        self.assertEqual(len(rows), 2)
        self.assertEqual(sorted(r['baseline'] for r in rows), ['B01', 'B02'])

    def test_process_assessment_reports_baselines_without_verdict(self):
        explained = assess(tables([MAIN_ROW, DATA_ROW], [MAIN], [MAIN_VAD, DATA_VAD]), {'windows.pslist': 'l.json'}, MAP)[0]
        self.assertEqual(explained['loader_flag_rows'], 2)  # every row with a non-True flag is retained as an observation
        self.assertEqual(explained['loader_rows_explained_by_baseline'], 2)
        self.assertEqual(explained['loader_rows_requiring_review'], 0)
        self.assertNotIn('loader_flags_require_context', explained['reasons'])
        self.assertEqual(explained['loader_baselines_applied'], ['B01', 'B02'])
        self.assertEqual(explained['analyst_verdict'], 'not_reviewed')
        mixed = assess(tables([DATA_ROW, loader(0x800000, None, (False, False, False))], [MAIN], [DATA_VAD, vad(0x800000, 'PAGE_EXECUTE_READWRITE', 1)]),
                       {'windows.pslist': 'l.json'}, MAP)[0]
        self.assertEqual(mixed['loader_rows_requiring_review'], 1)
        self.assertIn('loader_flags_require_context', mixed['reasons'])


if __name__ == '__main__':
    unittest.main()
