"""Cloudflare R2 backups for accounts and usage data.

The gateway intentionally uses only the Python standard library, so this module
implements the small S3 API surface it needs (HeadBucket, PutObject and
ListObjectsV2) with AWS Signature Version 4. Uploaded archives are streamed from
a temporary file instead of being held in memory.
"""

import datetime
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import ssl
import tempfile
import threading
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile

import wb_settings


CONFIG_KEY = "r2_backup"
DEFAULT_PREFIX = "workbuddy2api-hub"
ARCHIVE_FORMAT = "workbuddy2api-hub-backup-v1"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_LOCK = threading.RLock()
_BACKUP_LOCK = threading.Lock()
_CONFIG_FIELDS = (
    "account_id", "access_key_id", "secret_access_key", "bucket",
    "prefix", "endpoint_url", "include_usage",
)


class R2Error(RuntimeError):
    """An R2 configuration, transport or API error safe to show in the panel."""


class BackupBusy(R2Error):
    """Another manual backup is already running in this process."""


def _stored_text(raw, key, default=""):
    value = raw.get(key, default)
    return value.strip() if isinstance(value, str) else default


def load_config(accounts_dir):
    """Return the complete stored configuration, including the server-only key."""
    raw = wb_settings.load(accounts_dir).get(CONFIG_KEY)
    if not isinstance(raw, dict):
        raw = {}
    return {
        "account_id": _stored_text(raw, "account_id"),
        "access_key_id": _stored_text(raw, "access_key_id"),
        "secret_access_key": _stored_text(raw, "secret_access_key"),
        "bucket": _stored_text(raw, "bucket"),
        "prefix": _stored_text(raw, "prefix", DEFAULT_PREFIX),
        "endpoint_url": _stored_text(raw, "endpoint_url"),
        "include_usage": raw.get("include_usage", True) is not False,
    }


def resolved_endpoint(config):
    custom = str(config.get("endpoint_url") or "").strip().rstrip("/")
    if custom:
        return custom
    account_id = str(config.get("account_id") or "").strip()
    return ("https://%s.r2.cloudflarestorage.com" % account_id) if account_id else ""


def panel_config(accounts_dir):
    """Return the settings view without ever exposing Secret Access Key."""
    config = load_config(accounts_dir)
    secret_set = bool(config["secret_access_key"])
    out = {key: value for key, value in config.items()
           if key != "secret_access_key"}
    out["secret_access_key_set"] = secret_set
    out["secret_access_key_masked"] = "********" if secret_set else ""
    out["resolved_endpoint"] = resolved_endpoint(config)
    out["configured"] = all((
        config["access_key_id"], secret_set, config["bucket"],
        resolved_endpoint(config),
    ))
    return out


def _validate_endpoint(endpoint):
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("R2 endpoint URL is invalid: %s" % exc)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise ValueError("R2 endpoint URL must be an HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("R2 endpoint URL cannot contain credentials, query or fragment")
    if parsed.path not in ("", "/"):
        raise ValueError("R2 endpoint URL cannot contain a path")
    if parsed.scheme == "http":
        host = parsed.hostname.lower()
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            raise ValueError("R2 endpoint URL must use HTTPS outside loopback testing")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("R2 endpoint port is invalid")


def _validate_config(config, require_complete=False):
    for key in ("account_id", "access_key_id", "secret_access_key",
                "bucket", "prefix", "endpoint_url"):
        value = config.get(key) or ""
        if len(value) > 4096 or any(ch in value for ch in ("\r", "\n", "\x00")):
            raise ValueError("R2 backup field %s is invalid" % key)
    account_id = config.get("account_id") or ""
    if account_id and not re.match(r"^[A-Za-z0-9-]{1,128}$", account_id):
        raise ValueError("Cloudflare Account ID contains invalid characters")
    bucket = config.get("bucket") or ""
    if bucket and not re.match(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", bucket):
        raise ValueError("R2 bucket name must be 3-63 lowercase S3-compatible characters")
    if ".." in bucket:
        raise ValueError("R2 bucket name cannot contain consecutive dots")
    prefix = config.get("prefix") or ""
    if len(prefix) > 512 or any(part == ".." for part in prefix.split("/")):
        raise ValueError("R2 object prefix is invalid")
    endpoint = resolved_endpoint(config)
    if endpoint:
        _validate_endpoint(endpoint)
    if require_complete:
        missing = []
        for key, label in (("access_key_id", "Access Key ID"),
                           ("secret_access_key", "Secret Access Key"),
                           ("bucket", "Bucket")):
            if not config.get(key):
                missing.append(label)
        if not endpoint:
            missing.append("Account ID / Endpoint")
        if missing:
            raise R2Error("R2 backup is not configured: " + ", ".join(missing))


def save_config(accounts_dir, patch):
    """Merge and atomically persist the R2 section; a blank secret keeps the old one."""
    if not isinstance(patch, dict):
        raise ValueError("r2_backup must be an object")
    with _LOCK:
        current = load_config(accounts_dir)
        merged = dict(current)
        for key in _CONFIG_FIELDS:
            if key not in patch or key == "include_usage":
                continue
            value = patch.get(key)
            if not isinstance(value, str):
                raise ValueError("R2 backup field %s must be a string" % key)
            value = value.strip()
            if key == "secret_access_key" and not value:
                continue
            if key == "prefix":
                value = value.strip("/")
            merged[key] = value
        if "include_usage" in patch:
            if not isinstance(patch.get("include_usage"), bool):
                raise ValueError("r2_backup.include_usage must be true or false")
            merged["include_usage"] = patch["include_usage"]
        _validate_config(merged)
        data = wb_settings.load(accounts_dir)
        data[CONFIG_KEY] = {key: merged[key] for key in _CONFIG_FIELDS}
        wb_settings.save(accounts_dir, data)
        return panel_config(accounts_dir)


def _hash_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _sign(key, message):
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def _xml_text(element, name):
    for child in list(element):
        if child.tag.rsplit("}", 1)[-1] == name:
            return child.text or ""
    return ""


class R2Client:
    """Minimal path-style S3 client using the Cloudflare R2 `auto` region."""

    def __init__(self, config, timeout=60):
        _validate_config(config, require_complete=True)
        self.config = config
        self.endpoint = resolved_endpoint(config).rstrip("/")
        self.parsed = urllib.parse.urlsplit(self.endpoint)
        self.timeout = timeout

    def _host_header(self):
        host = self.parsed.hostname.lower()
        if ":" in host:
            host = "[%s]" % host
        port = self.parsed.port
        default_port = 443 if self.parsed.scheme == "https" else 80
        return host + ((":%d" % port) if port and port != default_port else "")

    def _request(self, method, key="", query=(), body=None,
                 payload_hash=None, content_type=""):
        bucket = self.config["bucket"]
        path = "/" + urllib.parse.quote(bucket, safe="-_.~")
        if key:
            path += "/" + urllib.parse.quote(key, safe="/-_.~")
        encoded_query = sorted(
            (urllib.parse.quote(str(name), safe="-_.~"),
             urllib.parse.quote(str(value), safe="-_.~"))
            for name, value in query
        )
        canonical_query = "&".join("%s=%s" % pair for pair in encoded_query)
        target = path + (("?" + canonical_query) if canonical_query else "")
        if payload_hash is None:
            payload_hash = hashlib.sha256(b"").hexdigest()
        now = datetime.datetime.now(datetime.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        headers = {
            "Host": self._host_header(),
            "X-Amz-Date": amz_date,
            "X-Amz-Content-Sha256": payload_hash,
        }
        if content_type:
            headers["Content-Type"] = content_type
        if body is not None:
            headers["Content-Length"] = str(os.fstat(body.fileno()).st_size)
        signed_names = sorted(name.lower() for name in headers
                              if name.lower() != "content-length")
        by_lower = {name.lower(): name for name in headers}
        canonical_headers = "".join(
            "%s:%s\n" % (name, " ".join(str(headers[by_lower[name]]).split()))
            for name in signed_names
        )
        signed_headers = ";".join(signed_names)
        canonical_request = "\n".join((
            method, path, canonical_query, canonical_headers,
            signed_headers, payload_hash,
        ))
        scope = "%s/auto/s3/aws4_request" % date_stamp
        string_to_sign = "\n".join((
            "AWS4-HMAC-SHA256", amz_date, scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ))
        date_key = _sign(("AWS4" + self.config["secret_access_key"]).encode("utf-8"),
                         date_stamp)
        region_key = hmac.new(date_key, b"auto", hashlib.sha256).digest()
        service_key = hmac.new(region_key, b"s3", hashlib.sha256).digest()
        signing_key = hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()
        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"),
                             hashlib.sha256).hexdigest()
        headers["Authorization"] = (
            "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
            % (self.config["access_key_id"], scope, signed_headers, signature)
        )
        connection = None
        try:
            if self.parsed.scheme == "https":
                connection = http.client.HTTPSConnection(
                    self.parsed.hostname, self.parsed.port or 443,
                    timeout=self.timeout, context=ssl.create_default_context())
            else:
                connection = http.client.HTTPConnection(
                    self.parsed.hostname, self.parsed.port or 80,
                    timeout=self.timeout)
            connection.request(method, target, body=body, headers=headers)
            response = connection.getresponse()
            content = response.read(MAX_RESPONSE_BYTES + 1)
            if len(content) > MAX_RESPONSE_BYTES:
                raise R2Error("R2 response is too large")
            if not 200 <= response.status < 300:
                code = _xml_text_from_error(content, "Code")
                message = _xml_text_from_error(content, "Message")
                detail = " / ".join(part for part in (code, message) if part)
                raise R2Error("R2 returned HTTP %d%s" % (
                    response.status, (": " + detail[:300]) if detail else ""))
            return response.status, dict(response.getheaders()), content
        except R2Error:
            raise
        except Exception as exc:
            raise R2Error("R2 connection failed: %s: %s" %
                          (type(exc).__name__, str(exc)[:240]))
        finally:
            if connection is not None:
                connection.close()

    def test(self):
        self._request("HEAD")
        return {"ok": True, "bucket": self.config["bucket"],
                "endpoint": self.endpoint}

    def upload(self, archive_path, key):
        payload_hash = _hash_file(archive_path)
        with open(archive_path, "rb") as body:
            _status, headers, _content = self._request(
                "PUT", key=key, body=body, payload_hash=payload_hash,
                content_type="application/zip")
        return (headers.get("ETag") or headers.get("Etag") or "").strip('"')

    def list(self, limit=50):
        prefix = self.config["prefix"].strip("/")
        if prefix:
            prefix += "/"
        backups = []
        continuation = ""
        seen_tokens = set()
        # R2 orders keys lexicographically, while our keys get newer with time.
        # Read every page before sorting so backup 51 does not hide newer backups.
        while True:
            query = [("list-type", "2"), ("max-keys", "1000"),
                     ("prefix", prefix)]
            if continuation:
                query.append(("continuation-token", continuation))
            _status, _headers, content = self._request("GET", query=query)
            try:
                root = ET.fromstring(content)
            except (ET.ParseError, ValueError) as exc:
                raise R2Error("R2 returned an invalid backup list: %s" % exc)
            for item in list(root):
                if item.tag.rsplit("}", 1)[-1] != "Contents":
                    continue
                key = _xml_text(item, "Key")
                if not key.endswith(".zip") or not key.rsplit("/", 1)[-1].startswith(
                        "workbuddy2api-hub-"):
                    continue
                try:
                    size = int(_xml_text(item, "Size") or 0)
                except ValueError:
                    size = 0
                backups.append({
                    "key": key,
                    "size": size,
                    "last_modified": _xml_text(item, "LastModified"),
                    "etag": _xml_text(item, "ETag").strip('"'),
                })
            truncated = _xml_text(root, "IsTruncated").strip().lower() == "true"
            if not truncated:
                break
            continuation = _xml_text(root, "NextContinuationToken").strip()
            if not continuation or continuation in seen_tokens:
                raise R2Error("R2 returned an invalid continuation token")
            seen_tokens.add(continuation)
        backups.sort(key=lambda row: (row["last_modified"], row["key"]), reverse=True)
        return backups[:limit]


def _xml_text_from_error(content, name):
    try:
        return _xml_text(ET.fromstring(content), name)
    except (ET.ParseError, ValueError):
        return ""


def _client(accounts_dir):
    return R2Client(load_config(accounts_dir))


def test_connection(accounts_dir):
    return _client(accounts_dir).test()


def list_backups(accounts_dir, limit=50):
    return _client(accounts_dir).list(limit=limit)


def _inside_real_root(root_real, path):
    """Reject symlinks and Windows junction/reparse points escaping the source root."""
    try:
        path_real = os.path.realpath(path)
        return os.path.normcase(os.path.commonpath((root_real, path_real))) == \
            os.path.normcase(root_real)
    except (OSError, ValueError):
        return False


def _source_files(accounts_dir, usage_dir, include_usage):
    sources = [(accounts_dir, "accounts")]
    if include_usage:
        sources.append((usage_dir, "usage"))
    for root, archive_root in sources:
        if not os.path.isdir(root):
            continue
        root_real = os.path.realpath(root)
        for folder, dirs, files in os.walk(root):
            dirs[:] = sorted(
                name for name in dirs
                if not os.path.islink(os.path.join(folder, name))
                and _inside_real_root(root_real, os.path.join(folder, name)))
            for name in sorted(files):
                path = os.path.join(folder, name)
                if (os.path.islink(path) or not os.path.isfile(path)
                        or not _inside_real_root(root_real, path)):
                    continue
                relative = os.path.relpath(path, root).replace(os.sep, "/")
                yield path, archive_root + "/" + relative


def backup_now(accounts_dir, usage_dir, version=""):
    """Create and upload one ZIP archive; return its public object metadata."""
    if not _BACKUP_LOCK.acquire(False):
        raise BackupBusy("Another R2 backup is already running")
    temporary_path = ""
    try:
        config = load_config(accounts_dir)
        _validate_config(config, require_complete=True)
        created = datetime.datetime.now(datetime.timezone.utc)
        stamp = created.strftime("%Y%m%d-%H%M%S")
        filename = "workbuddy2api-hub-%s-%s.zip" % (stamp, secrets.token_hex(3))
        parts = [config["prefix"].strip("/"), created.strftime("%Y"),
                 created.strftime("%m"), created.strftime("%d"), filename]
        key = "/".join(part for part in parts if part)
        descriptor, temporary_path = tempfile.mkstemp(
            prefix="workbuddy-r2-backup-", suffix=".zip")
        os.close(descriptor)
        entries = []
        with zipfile.ZipFile(temporary_path, "w", zipfile.ZIP_DEFLATED,
                             compresslevel=6) as archive:
            for path, archive_name in _source_files(
                    accounts_dir, usage_dir, config["include_usage"]):
                archive.write(path, archive_name)
                entries.append({"path": archive_name, "size": os.path.getsize(path)})
            if not entries:
                raise R2Error("There is no account or usage data to back up")
            manifest = {
                "format": ARCHIVE_FORMAT,
                "created_at": created.isoformat().replace("+00:00", "Z"),
                "version": str(version or ""),
                "include_usage": config["include_usage"],
                "files": entries,
            }
            archive.writestr("manifest.json", json.dumps(
                manifest, ensure_ascii=False, indent=2).encode("utf-8"))
        size = os.path.getsize(temporary_path)
        etag = R2Client(config).upload(temporary_path, key)
        return {
            "ok": True,
            "key": key,
            "bucket": config["bucket"],
            "endpoint": resolved_endpoint(config),
            "size": size,
            "file_count": len(entries),
            "created_at": manifest["created_at"],
            "etag": etag,
        }
    finally:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass
        _BACKUP_LOCK.release()
