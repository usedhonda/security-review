"""No network/API secrets: account discovery, bounds and central delivery."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'src'))
import account_review as account


def metadata(n, **changes):
    value={'id':n,'full_name':f'owner/project{n}','owner':{'login':'owner'},'visibility':'public','private':False,'fork':False,'archived':False,'default_branch':'main'}
    value.update(changes);return value


def blob(path='src/auth.py', size=100):
    return {'type':'blob','mode':'100644','path':path,'size':size,'sha':'a'*40}


class PublicFake:
    def __init__(self, records):self.records=records;self.calls=[]
    def get(self,path):
        self.calls.append(path)
        if path.startswith('/users/'):return self.records
        name=path.split('/')[3];item=next(x for x in self.records if x['full_name']=='owner/'+name)
        if '/branches/' in path:return {'commit':{'sha':f"{item['id']:040x}"}}
        if '/git/trees/' in path:return {'truncated':False,'tree':[blob()]}
        return item


class AccountTests(unittest.TestCase):
    def test_public_owned_only_and_exclusions(self):
        records=[metadata(1),metadata(2,private=True,visibility='private'),metadata(3,fork=True),metadata(4,archived=True),metadata(5,owner={'login':'foreign'}),metadata(6,full_name='owner/security-review')]
        result=account.discover(PublicFake(records),'owner','owner/security-review')
        self.assertEqual([x['status'] for x in result],['pending','excluded_fork','excluded_archived','excluded_central'])
    def test_more_than_one_page_is_read(self):
        class P:
            def get(self,path):return [metadata(n) for n in range(1,101)] if path.endswith('page=1') else [metadata(101)]
        self.assertEqual(len(account.discover(P(),'owner','owner/security-review')),101)
    def test_infinite_inventory_fails_instead_of_claiming_complete(self):
        class P:
            def get(self,path):return [metadata(n) for n in range(1,101)]
        with self.assertRaises(account.CheckError):account.discover(P(),'owner','owner/security-review')
    def test_new_repositories_discovered_without_selection(self):
        manifest,inv=account.plan(PublicFake([metadata(1),metadata(2)]),'owner','owner/security-review',{})
        self.assertEqual(len(manifest['cases']),2)
        self.assertEqual([c['repository'] for c in manifest['cases']],['owner/project1','owner/project2'])
    def test_batch_limit_and_deferred_are_explicit(self):
        manifest,inv=account.plan(PublicFake([metadata(n) for n in range(1,6)]),'owner','owner/security-review',{})
        self.assertEqual(len(manifest['cases']),3)
        self.assertEqual(sum(r['status']=='deferred' for r in inv['repositories']),2)
    def test_unchanged_selection_is_not_paid_twice(self):
        manifest,inv=account.plan(PublicFake([metadata(1)]),'owner','owner/security-review',{account.category(1):f'{1:040x}'})
        self.assertEqual(manifest['cases'],[]);self.assertEqual(inv['repositories'][0]['status'],'unchanged_selection')
    def test_new_work_is_prioritized_over_changed_known_repository(self):
        manifest,_=account.plan(PublicFake([metadata(n) for n in range(1,5)]),'owner','owner/security-review',{account.category(1):'b'*40})
        self.assertEqual([x['id'] for x in manifest['cases']],['r2','r3','r4'])
    def test_secrets_traversal_symlinks_binaries_and_generated_are_excluded(self):
        for item in [blob('../a.py'),blob('/a.py'),blob('.env'),blob('node_modules/a.js'),blob('dist/a.js'),blob('key.pem'),blob('x.min.js'),blob('credentials.json'),blob('bad\x00.py'),dict(blob(),mode='120000'),blob('x.png'),blob(size=True)]:
            self.assertFalse(account.source_candidate(item),repr(item))
    def test_file_and_byte_caps(self):
        chosen,total,_,_=account.select_files({'truncated':False,'tree':[blob(f'src/auth{i}.py',50000) for i in range(20)]})
        self.assertEqual(len(chosen),3);self.assertEqual(total,150000)
        with self.assertRaises(account.CheckError):account.select_files({'truncated':True,'tree':[]})
    def test_full_commit_and_blob_pins_are_generated(self):
        manifest,_=account.plan(PublicFake([metadata(1)]),'owner','owner/security-review',{})
        case=manifest['cases'][0];self.assertEqual(case['commit'],f'{1:040x}')
        self.assertEqual(case['files'][0]['git_blob_sha'],'a'*40)
        self.assertTrue(case['source_root'].startswith('../sources/r1-'))
    def test_public_reader_cannot_accept_another_owner(self):
        with self.assertRaises(account.CheckError):account.Public('owner').get('/repos/foreign/project')
    def test_central_report_keeps_actual_target_and_source_location(self):
        row={'id':1,'repository':'owner/project1','commit':'a'*40}
        case={'status':'completed',**row,'coverage':{'complete_for_selection':True,'files':[{'path':'src/auth.py','included_lines':3,'included_ranges':[[1,3]]}]},'review':{'summary':'Selected files reviewed','limitations':['Caller not supplied'],'findings':[{'file':'src/auth.py','start_line':1,'end_line':2,'severity':'high','title':'Hypothesis','evidence':'Requires verification','fix':'Check input'}]}}
        doc=account.report_document(case,row,'https://github.com/owner/security-review/actions/runs/1')
        run=doc['runs'][0];self.assertEqual(run['automationDetails']['id'],account.category(1))
        self.assertIn('owner/project1',run['results'][1]['message']['text'])
        self.assertIn('/blob/'+'a'*40+'/src/auth.py#L1-L2',run['results'][1]['message']['text'])
        self.assertEqual(run['results'][1]['locations'][0]['physicalLocation']['artifactLocation']['uri'],'docs/RESULTS.md')
        case['review']['findings'][0]['end_line']=99
        with self.assertRaises(account.CheckError):account.report_document(case,row,'run')
    def test_incomplete_does_not_clear_previous_findings(self):
        with self.assertRaises(account.CheckError):account.report_document({'status':'incomplete'},{},'run')
    def test_upload_has_no_automatic_post_retry(self):
        class C:
            def __init__(self):self.n=0
            def call(self,*a,**k):self.n+=1;return 500,None
        c=C()
        with self.assertRaises(account.CheckError):account.upload(c,'owner/central','a'*40,'refs/heads/main',{})
        self.assertEqual(c.n,1)

if __name__=='__main__':unittest.main()

class AccountWorkflowTests(unittest.TestCase):
    def test_manual_only_paid_step_and_no_extra_token(self):
        text=(ROOT/'.github/workflows/account-review.yml').read_text()
        self.assertNotIn('REVIEW_GITHUB_TOKEN',text)
        self.assertNotIn('REVIEW_AGE_RECIPIENT',text)
        self.assertNotIn('upload-artifact',text)
        section=text.split('- name: Review up to three repositories',1)[1].split('- name: Deliver',1)[0]
        self.assertIn("github.event_name == 'workflow_dispatch'",section)
        self.assertNotIn('GITHUB_TOKEN',section)
        self.assertNotIn('github.token',section)
        self.assertIn('--max-cost-usd 1.00 --max-calls 3',section)
    def test_no_key_or_repository_inputs_are_required(self):
        text=(ROOT/'.github/workflows/account-review.yml').read_text()
        self.assertIn('workflow_dispatch:',text)
        self.assertNotIn('inputs:',text)
        self.assertIn('persist-credentials: false',text)
    def test_new_entry_page_has_only_start_and_result_links(self):
        spec=importlib.util.spec_from_file_location('entry_builder',ROOT/'scripts/build_pages.py')
        build=importlib.util.module_from_spec(spec);spec.loader.exec_module(build)
        text=build.build('owner/central')
        self.assertIn('https://github.com/owner/central/actions/workflows/account-review.yml',text)
        self.assertIn('https://github.com/owner/central/security/code-scanning',text)
        self.assertNotIn('<input',text);self.assertNotIn('<script',text)
        with self.assertRaises(ValueError):build.build('owner/../../evil')
