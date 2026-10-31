"""API-free proof of a same-repository, access-controlled result inbox.

Uses only the ephemeral Actions token. No external repository writes, user PAT,
OpenAI request, downloaded source, real finding, or credential value is published.
"""
from __future__ import annotations
import base64
import gzip
import json
import os
import re
import time
from urllib import error, parse, request

TOOL = 'Security Review Hub Check'
MARKER = 'SYNTHETIC-HUB-CHECK-NOT-A-VULNERABILITY'
MAX_BYTES = 2_000_000


class CheckError(Exception):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise CheckError('redirect_refused')


def configuration(env):
    repo, sha, ref = (env.get(x, '') for x in ('GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_REF'))
    if not re.fullmatch(r'[A-Za-z0-9-]+/[A-Za-z0-9_.-]+', repo):
        raise CheckError('invalid_repository')
    if not re.fullmatch(r'[a-f0-9]{40}', sha):
        raise CheckError('invalid_revision')
    if ref != 'refs/heads/' + env.get('DEFAULT_BRANCH', 'main'):
        raise CheckError('default_branch_required')
    if env.get('GITHUB_EVENT_NAME') not in ('push', 'workflow_dispatch'):
        raise CheckError('trusted_event_required')
    return repo, sha, ref


class Client:
    def __init__(self, repo, token):
        self.repo, self.token = repo, token
        self.opener = request.build_opener(request.ProxyHandler({}), NoRedirect())

    def call(self, path, *, data=None, authenticated=True):
        # This client cannot send the Actions token to other repositories or hosts.
        if not path.startswith('/repos/' + self.repo + '/') or any(c in path for c in ('\\', '\r', '\n', '#')):
            raise CheckError('unexpected_endpoint')
        headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'security-review-hub-check', 'X-GitHub-Api-Version': '2022-11-28'}
        if authenticated:
            if not self.token:
                raise CheckError('actions_token_missing')
            headers['Authorization'] = 'Bearer ' + self.token
        payload = None if data is None else json.dumps(data, allow_nan=False).encode()
        if payload is not None:
            headers['Content-Type'] = 'application/json'
        try:
            req = request.Request('https://api.github.com' + path, data=payload, headers=headers)
            with self.opener.open(req, timeout=25) as response:
                body = response.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise CheckError('response_too_large')
                return response.status, json.loads(body)
        except error.HTTPError as exc:
            code = exc.code
            exc.close()
            return code, None
        except (error.URLError, OSError, ValueError):
            raise CheckError('github_transport_failure') from None


def document():
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'runs': [{
        'tool': {'driver': {'name': TOOL, 'version': '1.0.0', 'rules': [{'id': 'hub-delivery-check', 'shortDescription': {'text': 'Synthetic inbox test, not a vulnerability'}, 'defaultConfiguration': {'level': 'note'}}]}},
        'automationDetails': {'id': 'security-review-hub-check/'},
        'results': [{'ruleId': 'hub-delivery-check', 'level': 'note', 'message': {'text': MARKER + '\nThis is an API-free delivery test using synthetic content only.'},
                     'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'docs/RESULTS.md'}, 'region': {'startLine': 1}}}],
                     'partialFingerprints': {'primaryLocationLineHash': 'security-review-hub-delivery-check-v1'}}]
    }]}


def check(client, repo, sha, ref):
    root = '/repos/' + repo
    payload = {'commit_sha': sha, 'ref': ref, 'sarif': base64.b64encode(gzip.compress(json.dumps(document()).encode())).decode(), 'validate': True}
    code, result = client.call(root + '/code-scanning/sarifs', data=payload)
    if code != 202 or not isinstance(result, dict) or not re.fullmatch(r'[a-f0-9-]{36}', str(result.get('id', ''))):
        raise CheckError('sarif_upload_rejected_http_' + str(code))
    status_path = root + '/code-scanning/sarifs/' + result['id']
    state = None
    for _ in range(20):
        code, result = client.call(status_path)
        if code != 200 or not isinstance(result, dict):
            raise CheckError('processing_status_unavailable')
        state = result.get('processing_status')
        if state == 'complete':
            break
        if state != 'pending':
            raise CheckError('sarif_processing_failed')
        time.sleep(3)
    if state != 'complete':
        raise CheckError('sarif_processing_unconfirmed')
    code, alerts = client.call(root + '/code-scanning/alerts?tool_name=' + parse.quote(TOOL) + '&per_page=100')
    if code != 200 or not isinstance(alerts, list):
        raise CheckError('authenticated_alert_read_failed')
    matches = [a for a in alerts if a.get('rule', {}).get('id') == 'hub-delivery-check' and a.get('tool', {}).get('name') == TOOL]
    if not matches or type(matches[0].get('number')) is not int:
        raise CheckError('synthetic_alert_not_found')
    number = matches[0]['number']
    code, _ = client.call(root + '/code-scanning/alerts/' + str(number), authenticated=False)
    if code not in (401, 403, 404):
        raise CheckError('anonymous_alert_read_not_denied')
    code, checks = client.call(root + '/commits/' + sha + '/check-runs?per_page=100', authenticated=False)
    if code != 200 or not isinstance(checks, dict) or checks.get('total_count', 101) > 100:
        raise CheckError('public_check_inspection_unavailable')
    if MARKER in json.dumps(checks):
        raise CheckError('synthetic_content_exposed_in_public_check')
    for item in checks.get('check_runs', []):
        count = item.get('output', {}).get('annotations_count', 0)
        if not count:
            continue
        if type(item.get('id')) is not int or type(count) is not int or count > 100:
            raise CheckError('public_annotation_inspection_incomplete')
        code, annotations = client.call(root + '/check-runs/' + str(item['id']) + '/annotations?per_page=100', authenticated=False)
        if code != 200 or not isinstance(annotations, list):
            raise CheckError('public_annotation_inspection_unavailable')
        if MARKER in json.dumps(annotations):
            raise CheckError('synthetic_content_exposed_in_public_annotations')
    return number


def main():
    try:
        repo, sha, ref = configuration(os.environ)
        number = check(Client(repo, os.environ.get('GITHUB_TOKEN', '')), repo, sha, ref)
        # Only a boolean is inspected. Never transmit, log or serialize the key.
        key_present = bool(os.environ.get('OPENAI_API_KEY', '').strip())
        text = '# Result inbox check\n\nSynthetic delivery: succeeded. No OpenAI API call.\n\n'
        text += 'Authenticated alert read: succeeded. Anonymous alert API access: denied.\n\n'
        text += 'Synthetic detail was absent from inspected public checks and annotations. This is a scoped smoke test, not a general confidentiality guarantee.\n\n'
        text += 'OpenAI API secret configured: **' + ('yes' if key_present else 'no') + '**.\n\n'
        text += '[Open the authenticated result inbox](https://github.com/' + repo + '/security/code-scanning)\n'
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
            stream.write(text)
        print('Synthetic inbox check completed; no paid API request.')
        return 0
    except CheckError as exc:
        # CheckError values in this module are fixed labels, never server bodies.
        print('Inbox check stopped: ' + str(exc))
        return 2
    except Exception:
        print('Inbox check stopped: unexpected_failure; no raw response logged.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
