import unittest

import memlink_freeze as fz


class FreezeGateTests(unittest.TestCase):
    def test_assistant_drafts_block_the_freeze(self):
        meta = {'valid': True, 'unassessed_finding_ids': []}
        problems = fz.check_ready(meta, [{'status': 'drafted_pending_user_confirmation'}, {'status': 'user_confirmed'}])
        self.assertTrue(any('not user_confirmed' in p for p in problems))

    def test_invalid_or_unassessed_blocks_the_freeze(self):
        problems = fz.check_ready({'valid': False, 'unassessed_finding_ids': ['F-1']}, [{'status': 'user_confirmed'}])
        self.assertEqual(len(problems), 2)

    def test_clean_confirmed_set_is_ready(self):
        self.assertEqual(fz.check_ready({'valid': True, 'unassessed_finding_ids': []}, [{'status': 'user_confirmed'}]), [])


if __name__ == '__main__':
    unittest.main()
