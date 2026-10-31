"""Synthetic-only tests for the central inbox feasibility check."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('hub_check', Path(__file__).resolve().parents[1]/'scripts/hub_check.py')
hub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hub)
REPO='owner/security-review'; SHA='a'*40; ID='12345678-1234-1234-1234-123456789abc'

class Fake:
    def __init__(self, anonymous=404, leak=False):
        self.calls=[]; self.anonymous=anonymous; self.leak=leak
    def call(self,path,*,data=None,authenticated=True):
        self.calls.append((path,authenticated,data))
        if data is not None:return 202,{'id':ID}
        if path.endswith(ID):return 200,{'processing_status':'complete'}
        if '/alerts?' in path:return 200,[{'number':1,'rule':{'id':'hub-delivery-check'},'tool':{'name':hub.TOOL}}]
        if path.endswith('/alerts/1'):return self.anonymous,None
        if '/check-runs?' in path:return 200,{'total_count':1,'check_runs':[{'id':7,'output':{'annotations_count':1}}]}
        if '/annotations?' in path:return 200,[{'message': hub.MARKER if self.leak else 'Unit tests only'}]
        raise AssertionError('unexpected request')

class HubCheckTests(unittest.TestCase):
    def test_same_repository_delivery_and_anonymous_denial(self):
        c=Fake();self.assertEqual(hub.check(c,REPO,SHA,'refs/heads/main'),1)
        self.assertTrue(all(p.startswith('/repos/'+REPO+'/') for p,_,_ in c.calls))
        self.assertEqual(sum(data is not None for _,_,data in c.calls),1)
    def test_anonymous_access_stops(self):
        with self.assertRaises(hub.CheckError):hub.check(Fake(anonymous=200),REPO,SHA,'refs/heads/main')
    def test_public_annotation_leak_stops(self):
        with self.assertRaises(hub.CheckError):hub.check(Fake(leak=True),REPO,SHA,'refs/heads/main')
    def test_write_rejection_never_retried(self):
        c=Fake()
        with patch.object(c,'call',return_value=(403,None)) as call:
            with self.assertRaises(hub.CheckError):hub.check(c,REPO,SHA,'refs/heads/main')
            self.assertEqual(call.call_count,1)
    def test_pr_events_and_other_branches_are_rejected(self):
        env={'GITHUB_REPOSITORY':REPO,'GITHUB_SHA':SHA,'GITHUB_REF':'refs/heads/main','DEFAULT_BRANCH':'main','GITHUB_EVENT_NAME':'push'}
        self.assertEqual(hub.configuration(env),(REPO,SHA,'refs/heads/main'))
        for change in ({'GITHUB_EVENT_NAME':'pull_request'}, {'GITHUB_REF':'refs/heads/feature'}, {'GITHUB_REPOSITORY':'owner/repo/../../other'}):
            with self.assertRaises(hub.CheckError):hub.configuration(env|change)
    def test_client_rejects_other_repositories_before_network(self):
        c=hub.Client(REPO,'not-a-real-token')
        with self.assertRaises(hub.CheckError):c.call('/repos/another/repo/code-scanning/sarifs')
    def test_document_has_only_synthetic_data(self):
        doc=hub.document(); self.assertEqual(doc['runs'][0]['tool']['driver']['name'],hub.TOOL)
        self.assertIn(hub.MARKER,doc['runs'][0]['results'][0]['message']['text'])
    def test_redirects_are_not_followed(self):
        with self.assertRaises(hub.CheckError):hub.NoRedirect().redirect_request(None)

if __name__=='__main__':unittest.main()
