"""First-run history and empty-repository regressions, no network or keys."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import account_review as account
from test_account_review import PublicFake, metadata

class HistoryTests(unittest.TestCase):
    def test_first_use_lists_all_tools_then_filters(self):
        class FirstUse:
            def call(self,path):
                if 'tool_name=' in path:return 404,None
                return 200,[{'tool':{'name':'Security Review Hub Check','version':'1.0.0'},'category':'security-review-hub-check/'}]
        self.assertEqual(account.history(FirstUse(),'owner/central'),{})
    def test_foreign_tool_does_not_mark_repository_as_reviewed(self):
        class C:
            def call(self,path):return 200,[{'tool':{'name':'Other','version':'auto-v1.'+'a'*40},'category':account.category(1),'error':''}]
        self.assertEqual(account.history(C(),'owner/central'),{})
    def test_current_tool_completed_snapshot_is_used(self):
        class C:
            def call(self,path):return 200,[{'tool':{'name':account.TOOL,'version':'auto-v1.'+'a'*40},'category':account.category(1),'error':''}]
        self.assertEqual(account.history(C(),'owner/central'),{account.category(1):'a'*40})
    def test_access_failure_is_not_misreported_as_empty_history(self):
        class C:
            def call(self,path):return 403,None
        with self.assertRaisesRegex(account.CheckError,'http_403'):account.history(C(),'owner/central')
    def test_empty_repository_skips_missing_default_branch(self):
        fake=PublicFake([metadata(1,size=0),metadata(2,size=12)])
        manifest,inventory=account.plan(fake,'owner','owner/central',{})
        self.assertEqual([c['repository'] for c in manifest['cases']],['owner/project2'])
        self.assertEqual(inventory['repositories'][0]['status'],'excluded_empty')
        self.assertFalse(any('/project1/branches/' in p for p in fake.calls))

if __name__=='__main__':unittest.main()
