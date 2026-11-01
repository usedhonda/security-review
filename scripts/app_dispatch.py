"""Handle authenticated GitHub App repository_dispatch in the central Actions account."""
import json,os,re,sys,tempfile
from pathlib import Path
from account_review import Public, report_document, upload
from hub_check import Client
from review_event import EventError,collect,current_anchor
from security_review.cli import run_experiment
class Remote:
 def __init__(self,owner):self.client=Public(owner)
 def call(self,path):return 200,self.client.get(path)
def validate(event,owner,central):
 if event.get("action")!="security-review-app-v1":raise EventError("dispatch_type")
 d=event.get("client_payload")
 if not isinstance(d,dict):raise EventError("payload")
 r=d.get("repository","")
 if not isinstance(r,str) or not re.fullmatch(re.escape(owner)+r"/[A-Za-z0-9_.-]+",r,re.I) or r.lower()==central.lower():raise EventError("repository_scope")
 if d.get("kind") not in ("push","pull_request"):raise EventError("kind")
 if type(d.get("repository_id")) is not int or d["repository_id"]<=0:raise EventError("repo_id")
 if not isinstance(d.get("branch"),str) or not d["branch"] or len(d["branch"])>256:raise EventError("branch")
 for k in ("base","head"):
  if not isinstance(d.get(k),str) or not re.fullmatch("[a-f0-9]{40}",d[k]) or d[k]=="0"*40:raise EventError("revision")
 if d["kind"]=="pull_request" and (type(d.get("pr")) is not int or d["pr"]<1):raise EventError("pr")
 if not re.fullmatch("[a-f0-9-]{36}",str(d.get("delivery","")),re.I):raise EventError("delivery")
 return d
def run(event,env):
 central=env["GITHUB_REPOSITORY"];owner=env.get("GITHUB_OWNER","usedhonda")
 if central!=owner+"/security-review" or env.get("GITHUB_REF")!="refs/heads/main" or env.get("GITHUB_RUN_ATTEMPT","1")!="1":raise EventError("trusted_run")
 d=validate(event,owner,central);remote=Remote(owner)
 m=remote.client.get("/repos/"+d["repository"])
 if m.get("id")!=d["repository_id"] or m.get("full_name")!=d["repository"] or m.get("private") is not False or m.get("fork") or m.get("archived") or m.get("default_branch")!=d["branch"] or m.get("owner",{}).get("login","").lower()!=owner.lower():raise EventError("metadata_changed")
 scope={"repository":d["repository"],"branch":d["branch"],"base":d["base"],"head":d["head"],"pr":d.get("pr") if d["kind"]=="pull_request" else None,"category":"app-"+d["kind"]+"-"+str(d.get("pr","main"))}
 current_anchor(remote,scope)
 with tempfile.TemporaryDirectory(prefix="review-app-") as path:
  manifest,coverage=collect(remote,scope,Path(path))
  if manifest is None:return {"state":"no_supported_source_changes","calls":0,**coverage},0
  if not env.get("OPENAI_API_KEY"):raise EventError("openai_key_missing")
  report=run_experiment(manifest,Path(path)/"report",live=True,max_cost_usd="0.50",max_calls=1)
  usage=report["budget"];summary={"state":"incomplete","calls":usage["generation_calls_attempted"],"cost":usage["usage_derived_cost_usd"],**coverage}
  if report.get("status")!="completed" or len(report.get("cases",[]))!=1:return summary,2
  current_anchor(remote,scope)
  row={"repository":d["repository"],"commit":d["head"],"id":d["repository_id"]}
  url="https://github.com/"+central+"/actions/runs/"+env["GITHUB_RUN_ID"]
  document=report_document(report["cases"][0],row,url)
  document["runs"][0]["tool"]["driver"]["name"]="Security Review AI App"
  document["runs"][0]["automationDetails"]["id"]="app-review/"+str(d["repository_id"])+"/"+scope["category"]+"/"
  upload(Client(central,env["GITHUB_TOKEN"]),central,env["GITHUB_SHA"],env["GITHUB_REF"],document)
  summary.update(state="reviewed",findings=len(report["cases"][0]["review"]["findings"]))
  return summary,0
def main():
 summary={"state":"not_completed"};status=2
 try:
  data=Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes()
  if len(data)>150000:raise EventError("payload_limit")
  summary,status=run(json.loads(data),os.environ)
 except EventError as e:summary["reason"]=str(e)
 except Exception:summary["reason"]="review_failed"
 print("App review "+json.dumps(summary,sort_keys=True))
 with open(os.environ["GITHUB_STEP_SUMMARY"],"a") as f:f.write("## App review\n\n```json\n"+json.dumps(summary,indent=2)+"\n```\n")
 return status
if __name__=="__main__":sys.exit(main())
