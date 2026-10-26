import unittest
import uuid
from memlink_schema import standardize, FIELDS


class SchemaTests(unittest.TestCase):
    def test_typed_real_export_shape(self):
        row = dict(case_id='c',host_id='h',snapshot_id='s',source_file='autopsy.db',
                   source_record='tsk_files.obj_id=1',evidence_kind='disk',artifact_type='filesystem_metadata',
                   path='C:/Windows/Test.EXE',pid='',size='7168',meta_flags='5',mtime='1600485846',
                   md5='a'*32,raw='{"name":"Test.EXE","mtime":1600485846}')
        artifact = standardize(row,dict(case_id='c',host_id='h'))
        self.assertTrue(set(FIELDS) <= set(artifact))
        uuid.UUID(artifact['artifact_id'])
        self.assertEqual(artifact['path'],r'c:\windows\test.exe')
        self.assertIsNone(artifact['pid'])
        self.assertIsNone(artifact['tamper_score'])
        self.assertIs(artifact['allocated'],True)
        self.assertEqual(artifact['raw']['mtime'],1600485846)
        self.assertTrue(artifact['mtime'].endswith('+00:00'))
