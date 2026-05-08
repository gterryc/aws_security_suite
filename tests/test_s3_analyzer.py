"""
[TST-01-S3] Tests unitarios para s3_analyzer.
"""
import sys
sys.path.insert(0, '.')

import pytest
from tests.conftest import make_collector_output, assert_finding, assert_no_finding, ACCOUNT_ID
from analyzers import s3_analyzer


def _base_bucket(name: str = "test-bucket", **kwargs) -> dict:
    defaults = {
        "name":                 name,
        "public_access_block":  {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
        "acl":                  {"Grants": []},
        "policy":               None,
        "policy_status":        {"IsPublic": False},
        "versioning":           {"Status": "Enabled"},
        "encryption":           {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
        "encryption_type":      "AES256",
        "logging":              {"TargetBucket": "log-bucket"},
        "logging_enabled":      True,
        "replication":          None,
        "lifecycle":            [{"ID": "expire"}],
        "object_lock":          {"ObjectLockEnabled": "Enabled"},
        "website":              None,
        "versioning_enabled":   True,
        "has_lifecycle":        True,
        "is_public":            False,
    }
    defaults.update(kwargs)
    return defaults


def _base_raw(bucket_name: str = "test-bucket", **bucket_kwargs) -> dict:
    return {
        "account_public_access_block": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
        "buckets": {bucket_name: _base_bucket(bucket_name, **bucket_kwargs)},
    }


# ── CIS-S3-2.1.2 Account level block public access ───────────────────────────

class TestAccountPublicAccessBlock:

    def test_fail_when_not_configured(self):
        raw = _base_raw()
        raw["account_public_access_block"] = None
        output   = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.1.2", "FAIL")

    def test_fail_when_partially_enabled(self):
        raw = _base_raw()
        raw["account_public_access_block"] = {
            "BlockPublicAcls": True, "IgnorePublicAcls": False,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        }
        output   = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.1.2", "FAIL")

    def test_pass_when_fully_enabled(self):
        raw    = _base_raw()
        output = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.1.2", "PASS")


# ── CIS-S3-2.1.1 Bucket level block public access ────────────────────────────

class TestBucketPublicAccessBlock:

    def test_fail_when_bucket_not_blocked(self):
        raw = _base_raw(public_access_block={
            "BlockPublicAcls": False, "IgnorePublicAcls": False,
            "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
        })
        output   = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.1.1", "FAIL")

    def test_pass_when_bucket_fully_blocked(self):
        raw    = _base_raw()
        output = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.1.1", "PASS")


# ── CIS-S3-2.1.3 ACL no pública ──────────────────────────────────────────────

class TestBucketPublicACL:

    def test_fail_when_acl_grants_public(self):
        raw = _base_raw(acl={
            "Grants": [{
                "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ",
            }]
        })
        output   = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.1.3", "FAIL")

    def test_fail_when_acl_grants_authenticated_users(self):
        raw = _base_raw(acl={
            "Grants": [{
                "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"},
                "Permission": "WRITE",
            }]
        })
        output   = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.1.3", "FAIL")

    def test_pass_when_no_public_grants(self):
        raw    = _base_raw()
        output = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.1.3", "PASS")


# ── CIS-S3-2.1.4 Política no pública ─────────────────────────────────────────

class TestBucketPublicPolicy:

    def test_fail_when_policy_is_public(self):
        raw = _base_raw(policy_status={"IsPublic": True})
        output   = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.1.4", "FAIL")

    def test_pass_when_policy_not_public(self):
        raw    = _base_raw()
        output = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.1.4", "PASS")


# ── Encriptación SSE ──────────────────────────────────────────────────────────

class TestBucketEncryption:

    def test_fail_when_no_encryption(self):
        raw = _base_raw(encryption=None, encryption_type=None)
        output   = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.1.1-ENC", "FAIL")

    def test_pass_when_aes256(self):
        raw    = _base_raw()
        output = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.1.1-ENC", "PASS")

    def test_pass_when_kms(self):
        raw = _base_raw(
            encryption={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]},
            encryption_type="aws:kms",
        )
        output   = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.1.1-ENC", "PASS")


# ── CIS-S3-2.6 Access logging ─────────────────────────────────────────────────

class TestBucketLogging:

    def test_fail_when_logging_disabled(self):
        raw = _base_raw(logging=None, logging_enabled=False)
        output   = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.6", "FAIL")

    def test_pass_when_logging_enabled(self):
        raw    = _base_raw()
        output = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "CIS-S3-2.6", "PASS")


# ── WAF-S3-SSL-01 SSL only ────────────────────────────────────────────────────

class TestBucketSSLOnly:

    def test_fail_when_no_ssl_policy(self):
        raw = _base_raw(policy=None)
        output   = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "WAF-S3-SSL-01", "FAIL")

    def test_pass_when_ssl_enforced(self):
        import json
        policy = json.dumps({"Statement": [{
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }]})
        raw    = _base_raw(policy=policy)
        output = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "WAF-S3-SSL-01", "PASS")


# ── WAF-S3-WEB-01 Website exposure ────────────────────────────────────────────

class TestBucketWebsite:

    def test_fail_when_website_enabled(self):
        raw = _base_raw(website={"IndexDocument": {"Suffix": "index.html"}})
        output   = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_finding(findings, "WAF-S3-WEB-01", "FAIL")

    def test_no_finding_when_website_disabled(self):
        raw    = _base_raw(website=None)
        output = make_collector_output("s3", raw)
        findings = s3_analyzer.analyze(output)
        assert_no_finding(findings, "WAF-S3-WEB-01", "FAIL")


# ── Test de integración ───────────────────────────────────────────────────────

class TestSecureConfiguration:

    def test_no_critical_fails_with_secure_config(self, s3_raw_secure):
        output   = make_collector_output("s3", s3_raw_secure)
        findings = s3_analyzer.analyze(output)
        critical_fails = [
            f for f in findings
            if f.status.value == "FAIL" and f.severity.value == "CRITICAL"
        ]
        assert len(critical_fails) == 0, (
            f"Expected no CRITICAL fails, got: "
            f"{[(f.control_id, f.message) for f in critical_fails]}"
        )