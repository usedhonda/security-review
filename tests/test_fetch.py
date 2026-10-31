"""Offline tests for source acquisition's trust and resource boundaries."""

from __future__ import annotations

from contextlib import redirect_stderr
from email.message import Message
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib import request, response

from scripts import fetch_cases as fetch

COMMIT = "a" * 40
TREE = "b" * 40
SOURCE = "print('こんにちは')\n".encode("utf-8")


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data, usedforsecurity=False).hexdigest()


class FakeResponse(io.BytesIO):
    def __init__(self, data: bytes, url: str):
        super().__init__(data)
        self.url = url
        self.headers: dict[str, str] = {}

    def geturl(self) -> str:
        return self.url

    def getcode(self) -> int:
        return 200


class FakeOpener:
    def __init__(self, source_files: dict[str, bytes], *, metadata: dict | None = None):
        self.source_files = source_files
        self.metadata = metadata if metadata is not None else {"sha": COMMIT, "tree": {"sha": TREE}, "parents": []}
        self.requests: list[request.Request] = []

    def open(self, req: request.Request, *, timeout: int) -> FakeResponse:
        self.requests.append(req)
        if req.full_url.startswith("https://api.github.com/repos/owner/sample/git/commits/"):
            return FakeResponse(json.dumps(self.metadata).encode(), req.full_url)
        prefix = f"https://raw.githubusercontent.com/owner/sample/{COMMIT}/"
        if not req.full_url.startswith(prefix):
            raise AssertionError("An unapproved URL was requested")
        return FakeResponse(self.source_files[req.full_url[len(prefix):]], req.full_url)


class FetchBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.manifest = self.root / "benchmarks" / "pilot.json"
        self.manifest.parent.mkdir()
        self.target = self.root / ".work" / "sources" / "sample" / "src" / "sample.py"

    def write_manifest(self, *, files=None, source_root="../.work/sources/sample", cases=None):
        if files is None:
            files = [{"path": "src/sample.py", "git_blob_sha": blob_sha(SOURCE), "sha256": hashlib.sha256(SOURCE).hexdigest()}]
        if cases is None:
            cases = [{"id": "sample", "repository": "owner/sample", "commit": COMMIT, "source_root": source_root, "files": files}]
        self.manifest.write_text(json.dumps({"schema_version": 1, "cases": cases}), encoding="utf-8")

    def run_fetch(self, opener):
        return fetch.fetch_manifest(self.manifest, project_root=self.root, opener=opener)

    def test_pinned_source_is_verified_then_reused_without_redownload(self):
        self.write_manifest()
        opener = FakeOpener({"src/sample.py": SOURCE})
        result = self.run_fetch(opener)
        self.assertEqual((result.files, result.source_bytes, result.cache_hits), (1, len(SOURCE), 0))
        self.assertEqual(self.target.read_bytes(), SOURCE)
        self.assertTrue(all(req.get_header("Authorization") is None for req in opener.requests))
        cached_opener = FakeOpener({})
        cached = self.run_fetch(cached_opener)
        self.assertEqual(cached.cache_hits, 1)
        self.assertEqual(len(cached_opener.requests), 1)  # Commit provenance is still checked.

    def test_missing_blob_pin_and_traversal_paths_fail_before_network(self):
        for files in [
            ["src/sample.py"],
            [{"path": "src/sample.py"}],
            *[[{"path": path, "git_blob_sha": blob_sha(SOURCE)}] for path in ("../escape", "/absolute", "src/../escape", "src//sample.py", "./sample.py", "src\\sample.py")],
        ]:
            with self.subTest(files=files):
                self.write_manifest(files=files)
                opener = FakeOpener({})
                with self.assertRaises(fetch.FetchError):
                    self.run_fetch(opener)
                self.assertEqual(opener.requests, [])

    def test_source_root_cannot_escape_or_hide_a_symlink_behind_parent_traversal(self):
        for source_root in ("../../outside", "../src", "../.work/sources", "../.work/sources/link/../sample", "../.work//sources/sample"):
            with self.subTest(source_root=source_root):
                self.write_manifest(source_root=source_root)
                opener = FakeOpener({})
                with self.assertRaises(fetch.FetchError):
                    self.run_fetch(opener)
                self.assertEqual(opener.requests, [])

    def test_downloaded_hash_mismatch_is_not_saved(self):
        self.write_manifest()
        with self.assertRaisesRegex(fetch.FetchError, "Git blob digest"):
            self.run_fetch(FakeOpener({"src/sample.py": b"wrong source\n"}))
        self.assertFalse(self.target.exists())

    def test_corrupt_cache_fails_without_replacement_or_redownload(self):
        self.write_manifest()
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b"corrupt cache\n")
        opener = FakeOpener({})
        with self.assertRaisesRegex(fetch.FetchError, "Git blob digest"):
            self.run_fetch(opener)
        self.assertEqual(self.target.read_bytes(), b"corrupt cache\n")
        self.assertEqual(len(opener.requests), 1)

    def test_optional_sha256_is_also_enforced(self):
        self.write_manifest(files=[{"path": "src/sample.py", "git_blob_sha": blob_sha(SOURCE), "sha256": "0" * 64}])
        with self.assertRaisesRegex(fetch.FetchError, "SHA-256"):
            self.run_fetch(FakeOpener({"src/sample.py": SOURCE}))
        self.assertFalse(self.target.exists())

    def test_symlink_parent_is_rejected_without_writing_outside_cache(self):
        self.write_manifest()
        outside = self.root / "outside"
        outside.mkdir()
        self.target.parent.parent.mkdir(parents=True)
        self.target.parent.symlink_to(outside, target_is_directory=True)
        opener = FakeOpener({})
        with self.assertRaises(fetch.FetchError):
            self.run_fetch(opener)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(len(opener.requests), 1)

    def test_symlink_leaf_is_rejected_without_reading_target(self):
        self.write_manifest()
        outside = self.root / "outside.py"
        outside.write_bytes(SOURCE)
        self.target.parent.mkdir(parents=True)
        self.target.symlink_to(outside)
        opener = FakeOpener({})
        with self.assertRaises(fetch.FetchError):
            self.run_fetch(opener)
        self.assertEqual(outside.read_bytes(), SOURCE)
        self.assertEqual(len(opener.requests), 1)

    def test_redirect_is_blocked_before_following_its_location(self):
        class RedirectTransport(request.HTTPSHandler):
            def __init__(self):
                super().__init__()
                self.urls = []

            def https_open(self, req):
                self.urls.append(req.full_url)
                headers = Message()
                headers["Location"] = "https://example.invalid/untrusted"
                result = response.addinfourl(io.BytesIO(b""), headers, req.full_url, 302)
                result.msg = "Found"
                return result

        transport = RedirectTransport()
        opener = request.build_opener(request.ProxyHandler({}), transport, fetch.NoRedirect())
        url = f"https://raw.githubusercontent.com/owner/sample/{COMMIT}/src/sample.py"
        with self.assertRaisesRegex(fetch.FetchError, "redirects"):
            fetch._http_read(opener, url, 100)
        self.assertEqual(transport.urls, [url])

    def test_tree_metadata_is_not_accepted_as_a_commit(self):
        self.write_manifest()
        opener = FakeOpener({}, metadata={"sha": COMMIT, "tree": [], "truncated": False})
        with self.assertRaisesRegex(fetch.FetchError, "Git commit"):
            self.run_fetch(opener)
        self.assertEqual(len(opener.requests), 1)

    def test_file_size_bound_applies_even_without_content_length(self):
        data = b"x" * (fetch.MAX_FILE_BYTES + 1)
        self.write_manifest(files=[{"path": "src/sample.py", "git_blob_sha": blob_sha(data)}])
        with self.assertRaisesRegex(fetch.FetchError, "fetch limits"):
            self.run_fetch(FakeOpener({"src/sample.py": data}))
        self.assertFalse(self.target.exists())

    def test_case_and_total_size_bounds_are_enforced(self):
        data = b"1234567"
        files = [{"path": path, "git_blob_sha": blob_sha(data)} for path in ("first.py", "second.py")]
        self.write_manifest(files=files)
        with patch.object(fetch, "MAX_CASE_BYTES", 13):
            with self.assertRaisesRegex(fetch.FetchError, "fetch limits"):
                self.run_fetch(FakeOpener({"first.py": data, "second.py": data}))
        metadata_bytes = len(json.dumps(FakeOpener({}).metadata).encode())
        with patch.object(fetch, "MAX_TOTAL_BYTES", metadata_bytes + 13):
            with self.assertRaisesRegex(fetch.FetchError, "fetch limits"):
                self.run_fetch(FakeOpener({"second.py": data}))
        self.assertFalse((self.target.parent.parent / "second.py").exists())

    def test_hash_valid_binary_or_non_utf8_data_is_not_saved(self):
        for data in (b"text\x00binary", b"\xff\xfe", b"text\x1bcontrol"):
            with self.subTest(data=data):
                self.write_manifest(files=[{"path": "src/sample.py", "git_blob_sha": blob_sha(data)}])
                with self.assertRaises(fetch.FetchError):
                    self.run_fetch(FakeOpener({"src/sample.py": data}))
                self.assertFalse(self.target.exists())

    def test_unexpected_exception_details_are_not_printed(self):
        stderr = io.StringIO()
        with patch.object(fetch, "fetch_manifest", side_effect=OSError("private-payload-value")), redirect_stderr(stderr):
            result = fetch.main(["--manifest", "benchmarks/pilot.json"])
        self.assertEqual(result, 2)
        self.assertNotIn("private-payload-value", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
