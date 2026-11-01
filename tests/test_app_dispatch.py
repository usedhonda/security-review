import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from app_dispatch import validate
from review_event import EventError

GOOD={"action":"security-review-app-v1","client_payload":{"kind":"pull_request","repository":"usedhonda/demo","repository_id":123,"branch":"main","base":"a"*40,"head":"b"*40,"pr":17,"delivery":"4fc0896e-0bea-49b8-9005-f3e21ec89fff"}}
class TestAppValidation(unittest.TestCase):
 def test_valid(self):self.assertEqual(validate(GOOD,"usedhonda","usedhonda/security-review")["pr"],17)
 def test_wrong_owner(self):
  x={"action":GOOD["action"],"client_payload":{**GOOD["client_payload"],"repository":"attacker/demo"}}
  with self.assertRaises(EventError):validate(x,"usedhonda","usedhonda/security-review")
 def test_reject_central(self):
  x={"action":GOOD["action"],"client_payload":{**GOOD["client_payload"],"repository":"usedhonda/security-review"}}
  with self.assertRaises(EventError):validate(x,"usedhonda","usedhonda/security-review")
 def test_reject_bad_sha(self):
  x={"action":GOOD["action"],"client_payload":{**GOOD["client_payload"],"head":"bad"}}
  with self.assertRaises(EventError):validate(x,"usedhonda","usedhonda/security-review")
