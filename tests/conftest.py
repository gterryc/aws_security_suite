"""
[TST-01] conftest.py — Fixtures y builders compartidos para todos los tests.

Patrón de uso:
    from tests.conftest import make_collector_output
    output = make_collector_output("iam", raw_data={...})
"""
import pytest
from datetime import datetime, timezone
from schemas.collector_output import CollectorOutput

ACCOUNT_ID = "123456789012"
REGION     = "us-east-1"


def make_collector_output(service: str, raw_data: dict) -> CollectorOutput:
    """Builder central de CollectorOutput para tests."""
    return CollectorOutput(
        service=service,
        account_id=ACCOUNT_ID,
        region=REGION,
        collected_at=datetime.now(timezone.utc),
        raw_data=raw_data,
        errors=[],
    )


def assert_finding(findings, control_id: str, status: str, count: int = None):
    """
    Helper para verificar que existe al menos un finding con
    el control_id y status esperados.
    Si count se especifica, verifica la cantidad exacta.
    """
    matched = [
        f for f in findings
        if f.control_id == control_id and f.status.value == status
    ]
    if count is not None:
        assert len(matched) == count, (
            f"Expected {count} finding(s) with control_id='{control_id}' "
            f"and status='{status}', got {len(matched)}.\n"
            f"All findings: {[(f.control_id, f.status.value) for f in findings]}"
        )
    else:
        assert len(matched) >= 1, (
            f"Expected at least one finding with control_id='{control_id}' "
            f"and status='{status}'.\n"
            f"All findings: {[(f.control_id, f.status.value) for f in findings]}"
        )
    return matched


def assert_no_finding(findings, control_id: str, status: str):
    """Verifica que NO existe ningún finding con ese control_id y status."""
    matched = [
        f for f in findings
        if f.control_id == control_id and f.status.value == status
    ]
    assert len(matched) == 0, (
        f"Expected NO finding with control_id='{control_id}' "
        f"and status='{status}', but found {len(matched)}."
    )


# ── Fixtures de raw_data por servicio ─────────────────────────────────────────

@pytest.fixture
def iam_raw_secure():
    """IAM completamente bien configurado — todos los controles deben PASS."""
    return {
        "password_policy": {
            "MinimumPasswordLength": 14,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "MaxPasswordAge": 90,
            "PasswordReusePrevention": 24,
        },
        "credential_report": [
            {
                "user":                  "<root_account>",
                "access_key_1_active":   "false",
                "access_key_2_active":   "false",
                "mfa_active":            "true",
                "password_enabled":      "not_supported",
                "password_last_used":    "N/A",
            },
        ],
        "root_virtual_mfa":    None,
        "users":               {},
        "groups":              {},
        "roles":               {},
        "customer_policies":   {},
        "access_analyzer":     {"enabled": True, "analyzers": [{"name": "audit-analyzer"}]},
        "support_role_exists": True,
        "user_activity":       {},
        "instance_profiles":   {},
        "saml_providers":      [],
        "oidc_providers":      [],
        "scps":                {"in_organization": False, "policies": []},
    }


@pytest.fixture
def s3_raw_secure():
    """S3 completamente bien configurado."""
    return {
        "account_public_access_block": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        "buckets": {
            "secure-bucket": {
                "name":                "secure-bucket",
                "public_access_block": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "acl":              {"Grants": []},
                "policy":           '{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}',
                "policy_status":    {"IsPublic": False},
                "versioning":       {"Status": "Enabled"},
                "encryption":       {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
                "encryption_type":  "AES256",
                "logging":          {"TargetBucket": "log-bucket"},
                "logging_enabled":  True,
                "replication":      {"Rules": []},
                "lifecycle":        [{"ID": "expire-old"}],
                "object_lock":      {"ObjectLockEnabled": "Enabled"},
                "website":          None,
                "versioning_enabled": True,
                "has_lifecycle":    True,
                "is_public":        False,
            }
        },
    }


@pytest.fixture
def ec2_raw_secure():
    """EC2 completamente bien configurado."""
    return {
        "ebs_encryption_by_default": True,
        "instances": {
            "i-secure001": {
                "state":            "running",
                "public_ip":        None,
                "imdsv2_required":  True,
                "imdsv2_enforced":  True,
                "monitoring":       "enabled",
                "monitoring_enabled": True,
                "ssm_managed":      True,
                "exposure_type":    "private",
                "behind_elb":       False,
                "directly_exposed": False,
            }
        },
        "security_groups": {
            "sg-secure001": {
                "name":            "secure-sg",
                "is_default":      False,
                "inbound_rules":   [],
                "outbound_rules":  [],
                "open_to_world":   False,
                "exposed_port_details": [],
            }
        },
        "vpcs": {
            "vpc-secure001": {
                "is_default":           False,
                "has_flow_logs":        True,
                "flow_logs_all_traffic": True,
            }
        },
        "ebs_volumes":    {"vol-001": {"encrypted": True, "kms_key_id": "arn:aws:kms:us-east-1:123:key/abc"}},
        "ebs_snapshots":  {"snap-001": {"encrypted": True, "is_public": False}},
        "amis":           {},
        "subnets":        {"subnet-001": {"auto_assign_public_ip": False}},
        "network_acls":   {"acl-001": {"entries": [], "is_default": False}},
        "elastic_ips":    [],
        "missing_critical_endpoints": [],
        "summary":        {},
    }