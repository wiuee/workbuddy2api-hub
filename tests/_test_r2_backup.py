"""Cloudflare R2 backup configuration, S3 signing and archive integration."""

import hashlib
import http.server
import io
import json
import os
import re
import sys
import tempfile
import threading
import unittest
from unittest import mock
import urllib.parse
import xml.sax.saxutils
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import wb_backup
import wb_settings


class FakeR2Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def record(self, body=b""):
        self.server.requests.append({
            "method": self.command,
            "path": self.path,
            "headers": {key.lower(): value for key, value in self.headers.items()},
            "body": body,
        })

    def reply(self, status=200, body=b"", headers=None):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def do_HEAD(self):
        self.record()
        if urllib.parse.urlsplit(self.path).path == "/fixture-bucket":
            self.reply()
        else:
            self.reply(404)

    def do_PUT(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        self.record(body)
        key = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path).lstrip("/")
        bucket, _separator, object_key = key.partition("/")
        if bucket != "fixture-bucket" or not object_key:
            self.reply(404)
            return
        if self.headers.get("X-Amz-Content-Sha256") != hashlib.sha256(body).hexdigest():
            self.reply(400, b"payload hash mismatch")
            return
        etag = hashlib.md5(body).hexdigest()
        self.server.objects[object_key] = {
            "body": body,
            "etag": etag,
            "last_modified": "2026-11-21T09:00:%02dZ" % len(self.server.objects),
        }
        self.reply(headers={"ETag": '"%s"' % etag})

    def do_GET(self):
        self.record()
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path != "/fixture-bucket" or query.get("list-type") != ["2"]:
            self.reply(404)
            return
        prefix = query.get("prefix", [""])[0]
        matching = sorted(key for key in self.server.objects if key.startswith(prefix))
        # Deliberately use tiny pages regardless of the requested max-keys: a
        # handful of fixtures then exercises the client's continuation loop.
        # Reserved characters also prove the token is signed/encoded as a query value.
        token = query.get("continuation-token", ["0"])[0]
        start = int(token.split(" ", 1)[0])
        page_size = min(int(query.get("max-keys", ["1000"])[0]), 3)
        page = matching[start:start + page_size]
        next_offset = start + len(page)
        truncated = next_offset < len(matching)
        rows = []
        for key in page:
            item = self.server.objects[key]
            rows.append(
                "<Contents><Key>%s</Key><LastModified>%s</LastModified>"
                "<ETag>&quot;%s&quot;</ETag><Size>%d</Size></Contents>" % (
                    xml.sax.saxutils.escape(key), item["last_modified"],
                    item["etag"], len(item["body"])))
        next_token = "%d +/=" % next_offset
        suffix = ("<IsTruncated>true</IsTruncated><NextContinuationToken>%s</NextContinuationToken>"
                  % xml.sax.saxutils.escape(next_token)) if truncated else "<IsTruncated>false</IsTruncated>"
        body = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                + "".join(rows) + suffix + "</ListBucketResult>").encode("utf-8")
        self.reply(body=body, headers={"Content-Type": "application/xml"})

    def log_message(self, _format, *_args):
        pass


class R2BackupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="r2-backup-test-")
        self.addCleanup(self._tmp.cleanup)
        self.accounts = os.path.join(self._tmp.name, "accounts")
        self.usage = os.path.join(self._tmp.name, "usage")
        os.makedirs(self.accounts)
        os.makedirs(self.usage)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeR2Handler)
        self.server.objects = {}
        self.server.requests = []
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        self.endpoint = "http://127.0.0.1:%d" % self.server.server_port

    def _stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def save_config(self, **overrides):
        patch = {
            "account_id": "",
            "access_key_id": "test-access",
            "secret_access_key": "test-secret",
            "bucket": "fixture-bucket",
            "prefix": "fixture/backups",
            "endpoint_url": self.endpoint,
            "include_usage": True,
        }
        patch.update(overrides)
        return wb_backup.save_config(self.accounts, patch)

    def test_configuration_is_merged_and_secret_is_redacted(self):
        wb_settings.save(self.accounts, {"unrelated": {"keep": True}})
        panel = self.save_config()
        self.assertTrue(panel["configured"])
        self.assertTrue(panel["secret_access_key_set"])
        self.assertNotIn("secret_access_key", panel)
        self.assertNotIn("test-secret", json.dumps(panel))
        self.assertEqual(panel["resolved_endpoint"], self.endpoint)
        stored = wb_settings.load(self.accounts)
        self.assertEqual(stored["unrelated"], {"keep": True})
        self.assertEqual(stored["r2_backup"]["secret_access_key"], "test-secret")

        self.save_config(secret_access_key="", bucket="fixture-bucket")
        self.assertEqual(wb_backup.load_config(self.accounts)["secret_access_key"],
                         "test-secret")
        with self.assertRaises(ValueError):
            self.save_config(include_usage="false")
        with self.assertRaises(ValueError):
            self.save_config(endpoint_url="http://example.com")
        with self.assertRaises(ValueError):
            self.save_config(account_id="bad.example")

        derived = wb_backup.save_config(self.accounts, {
            "account_id": "0123456789abcdef0123456789abcdef",
            "endpoint_url": "",
        })
        self.assertEqual(
            derived["resolved_endpoint"],
            "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com")

    def test_connection_upload_archive_and_list(self):
        self.save_config()
        with open(os.path.join(self.accounts, "account.json"), "w", encoding="utf-8") as fh:
            json.dump({"uid": "fixture-user", "token": "fixture-token"}, fh)
        with open(os.path.join(self.usage, "requests.jsonl"), "w", encoding="utf-8") as fh:
            fh.write('{"model":"fixture","tokens":1}\n')

        tested = wb_backup.test_connection(self.accounts)
        self.assertTrue(tested["ok"])
        uploaded = wb_backup.backup_now(self.accounts, self.usage, version="9.8.7")
        self.assertTrue(uploaded["ok"])
        self.assertTrue(uploaded["key"].startswith("fixture/backups/"))
        self.assertTrue(uploaded["key"].endswith(".zip"))
        self.assertEqual(uploaded["file_count"], 3)  # settings, account, usage
        self.assertEqual(uploaded["size"], len(self.server.objects[uploaded["key"]]["body"]))

        archive_bytes = self.server.objects[uploaded["key"]]["body"]
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            self.assertIsNone(archive.testzip())
            names = set(archive.namelist())
            self.assertIn("accounts/settings.json", names)
            self.assertIn("accounts/account.json", names)
            self.assertIn("usage/requests.jsonl", names)
            self.assertIn("manifest.json", names)
            self.assertFalse(any(name.startswith("/") or ".." in name.split("/")
                                 for name in names))
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            self.assertEqual(manifest["format"], wb_backup.ARCHIVE_FORMAT)
            self.assertEqual(manifest["version"], "9.8.7")
            self.assertTrue(manifest["include_usage"])
            self.assertEqual(len(manifest["files"]), 3)

        put = next(item for item in self.server.requests if item["method"] == "PUT")
        auth = put["headers"].get("authorization", "")
        self.assertRegex(auth, re.compile(
            r"^AWS4-HMAC-SHA256 Credential=test-access/\d{8}/auto/s3/aws4_request, "
            r"SignedHeaders=.*host.*, Signature=[0-9a-f]{64}$"))
        self.assertNotIn("test-secret", auth)
        self.assertEqual(put["headers"]["content-type"], "application/zip")
        self.assertEqual(int(put["headers"]["content-length"]), len(archive_bytes))

        # A second archive without usage proves the option affects real content.
        self.save_config(include_usage=False, secret_access_key="")
        second = wb_backup.backup_now(self.accounts, self.usage)
        with zipfile.ZipFile(io.BytesIO(self.server.objects[second["key"]]["body"])) as archive:
            self.assertFalse(any(name.startswith("usage/") for name in archive.namelist()))
            self.assertFalse(json.loads(archive.read("manifest.json"))["include_usage"])

        listed = wb_backup.list_backups(self.accounts)
        self.assertEqual(len(listed), 2)
        self.assertEqual({row["key"] for row in listed}, {uploaded["key"], second["key"]})
        self.assertTrue(all(row["size"] > 0 for row in listed))

    def test_list_paginates_before_returning_the_newest_backups(self):
        self.save_config()
        for index in range(7):
            key = "fixture/backups/2026/11/21/workbuddy2api-hub-20261121-0000%02d.zip" % index
            self.server.objects[key] = {
                "body": b"zip", "etag": "etag-%d" % index,
                "last_modified": "2026-11-21T09:00:%02dZ" % index,
            }
        self.server.objects["fixture/backups/unrelated.txt"] = {
            "body": b"no", "etag": "other", "last_modified": "2026-11-21T10:00:00Z",
        }
        rows = wb_backup.list_backups(self.accounts, limit=5)
        self.assertEqual(len(rows), 5)
        self.assertTrue(rows[0]["key"].endswith("000006.zip"))
        self.assertTrue(rows[-1]["key"].endswith("000002.zip"))
        list_requests = [item for item in self.server.requests if item["method"] == "GET"]
        self.assertEqual(len(list_requests), 3)  # 7 backups + unrelated, three per page
        self.assertIn("continuation-token=3%20%2B%2F%3D", list_requests[1]["path"])

    def test_source_files_reject_a_junction_escaping_the_root(self):
        with open(os.path.join(self.accounts, "keep.json"), "w", encoding="utf-8") as fh:
            fh.write("{}")
        linked = os.path.join(self.accounts, "linked")
        os.makedirs(linked)
        with open(os.path.join(linked, "outside.json"), "w", encoding="utf-8") as fh:
            fh.write('{"private":true}')
        outside = os.path.join(self._tmp.name, "outside-root")
        original_realpath = os.path.realpath
        linked_absolute = os.path.normcase(os.path.abspath(linked))

        def fake_realpath(path):
            candidate = os.path.normcase(os.path.abspath(path))
            if candidate == linked_absolute or candidate.startswith(linked_absolute + os.sep):
                relative = os.path.relpath(candidate, linked_absolute)
                return os.path.join(outside, relative)
            return original_realpath(path)

        with mock.patch("wb_backup.os.path.realpath", side_effect=fake_realpath):
            names = [name for _path, name in wb_backup._source_files(
                self.accounts, self.usage, False)]
        self.assertEqual(names, ["accounts/keep.json"])

    def test_dashboard_has_a_dedicated_translated_backup_section(self):
        with open(os.path.join(ROOT, "dashboard.html"), encoding="utf-8") as fh:
            html = fh.read()
        for marker in ('data-cat="backup"', 'data-settings-group="backup"',
                       'id="r2BackupSettings"', "saveR2BackupSettings(this)",
                       "testR2Backup(this)", "runR2Backup(this)",
                       '#pageSettings > div:first-child:not(.page-nav-body)',
                       "'Cloudflare R2 备份': 'Cloudflare R2 backup'",
                       '"Cloudflare R2 备份": "Cloudflare R2 備份"'):
            self.assertIn(marker, html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
