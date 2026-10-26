import unittest
from memlink_registry_export import service_rows, HEADER


class RegistryTests(unittest.TestCase):
    def test_explicit_section_and_timestamp_semantics(self):
        text = 'unrelated\n'+HEADER+'\nSat Sep 19 03:27:49 2020 Z,example,,C:\\Windows\\example.exe,Own_Process,Auto Start,LocalSystem\n\n'
        rows = list(service_rows(text))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 3)
        self.assertEqual(rows[0][2], '2020-09-19T03:27:49+00:00')
        self.assertEqual(list(service_rows(text.replace(HEADER, 'unknown header'))), [])
