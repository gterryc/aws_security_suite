"""
[TST-01-IAM] Tests unitarios para iam_analyzer.
Cubre controles CIS 1.4 al 1.20 + WAF-IAM-G01.
"""
import sys
sys.path.insert(0, '.')

import pytest
from tests.conftest import make_collector_output, assert_finding, assert_no_finding, ACCOUNT_ID, REGION
from analyzers import iam_analyzer


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _base_raw() -> dict:
    """Raw data base con configuración mínima válida."""
    return {
        "password_policy":   None,
        "credential_report": [],
        "root_virtual_mfa":  None,
        "users":             {},
        "groups":            {},
        "roles":             {},
        "customer_policies": {},
        "access_analyzer":   {"enabled": False, "analyzers": []},
        "support_role_exists": False,
        "user_activity":     {},
        "instance_profiles": {},
        "saml_providers":    [],
        "oidc_providers":    [],
        "scps":              {"in_organization": False, "policies": []},
    }


def _root_entry(**kwargs) -> dict:
    defaults = {
        "user":                "<root_account>",
        "access_key_1_active": "false",
        "access_key_2_active": "false",
        "mfa_active":          "true",
        "password_enabled":    "not_supported",
        "password_last_used":  "N/A",
    }
    defaults.update(kwargs)
    return defaults


def _user_entry(username: str, **kwargs) -> dict:
    defaults = {
        "user":              username,
        "password_enabled":  "true",
        "mfa_active":        "false",
        "password_last_used": "2024-01-01T00:00:00+00:00",
    }
    defaults.update(kwargs)
    return defaults


# ── CIS-IAM-1.4 Root sin access keys ─────────────────────────────────────────

class TestRootNoAccessKeys:

    def test_fail_when_key1_active(self):
        raw = _base_raw()
        raw["credential_report"] = [_root_entry(access_key_1_active="true")]
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.4", "FAIL")

    def test_fail_when_key2_active(self):
        raw = _base_raw()
        raw["credential_report"] = [_root_entry(access_key_2_active="true")]
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.4", "FAIL")

    def test_pass_when_no_active_keys(self):
        raw = _base_raw()
        raw["credential_report"] = [_root_entry()]
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.4", "PASS")


# ── CIS-IAM-1.5 Root MFA ─────────────────────────────────────────────────────

class TestRootMFA:

    def test_fail_when_mfa_inactive(self):
        raw = _base_raw()
        raw["credential_report"] = [_root_entry(mfa_active="false")]
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.5", "FAIL")

    def test_pass_when_mfa_active(self):
        raw = _base_raw()
        raw["credential_report"] = [_root_entry(mfa_active="true")]
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.5", "PASS")


# ── CIS-IAM-1.6 Root hardware MFA ────────────────────────────────────────────

class TestRootVirtualMFA:

    def test_fail_when_using_virtual_mfa(self):
        raw = _base_raw()
        raw["root_virtual_mfa"] = {
            "SerialNumber": f"arn:aws:iam::{ACCOUNT_ID}:mfa/root-account-mfa-device"
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.6", "FAIL")

    def test_pass_when_no_virtual_mfa(self):
        raw = _base_raw()
        raw["root_virtual_mfa"] = None
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.6", "PASS")


# ── CIS-IAM-1.8 al 1.14 Password Policy ──────────────────────────────────────

class TestPasswordPolicy:

    def test_all_fail_when_no_policy(self):
        raw    = _base_raw()
        output = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        for cid in ["CIS-IAM-1.8", "CIS-IAM-1.9", "CIS-IAM-1.10",
                    "CIS-IAM-1.11", "CIS-IAM-1.12", "CIS-IAM-1.13", "CIS-IAM-1.14"]:
            assert_finding(findings, cid, "FAIL")

    def test_fail_when_min_length_too_short(self):
        raw = _base_raw()
        raw["password_policy"] = {"MinimumPasswordLength": 8}
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.8", "FAIL")

    def test_pass_when_min_length_14(self):
        raw = _base_raw()
        raw["password_policy"] = {
            "MinimumPasswordLength":     14,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "RequireSymbols":             True,
            "RequireNumbers":             True,
            "MaxPasswordAge":             90,
            "PasswordReusePrevention":    24,
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.8", "PASS")

    def test_fail_when_max_age_over_90(self):
        raw = _base_raw()
        raw["password_policy"] = {"MaxPasswordAge": 120}
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.13", "FAIL")

    def test_fail_when_reuse_below_24(self):
        raw = _base_raw()
        raw["password_policy"] = {"PasswordReusePrevention": 10}
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.14", "FAIL")


# ── CIS-IAM-1.10 MFA todos los usuarios ──────────────────────────────────────

class TestMFAAllUsers:

    def test_fail_when_user_has_no_mfa(self):
        raw = _base_raw()
        raw["credential_report"] = [_user_entry("alice", password_enabled="true")]
        raw["users"] = {
            "alice": {
                "user":               {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/alice"},
                "mfa_devices":        [],
                "access_keys":        [],
                "attached_policies":  [],
                "inline_policies":    [],
                "groups":             [],
            }
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.10", "FAIL")

    def test_pass_when_user_has_mfa(self):
        raw = _base_raw()
        raw["credential_report"] = [_user_entry("bob", password_enabled="true")]
        raw["users"] = {
            "bob": {
                "user":              {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/bob"},
                "mfa_devices":       [{"SerialNumber": "arn:aws:iam::123:mfa/bob"}],
                "access_keys":       [],
                "attached_policies": [],
                "inline_policies":   [],
                "groups":            [],
            }
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.10", "PASS")

    def test_skip_user_without_console_access(self):
        raw = _base_raw()
        raw["password_policy"] = {"MinimumPasswordLength": 14, "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True, "RequireSymbols": True, "RequireNumbers": True, "MaxPasswordAge": 90, "PasswordReusePrevention": 24}
        raw["credential_report"] = [_user_entry("svc-account", password_enabled="false")]
        raw["users"] = {
            "svc-account": {
                "user":              {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/svc-account"},
                "mfa_devices":       [],
                "access_keys":       [],
                "attached_policies": [],
                "inline_policies":   [],
                "groups":            [],
            }
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        # Usuario sin consola no debe tener CIS-IAM-1.10 FAIL
        assert_no_finding(findings, "CIS-IAM-1.10", "FAIL")


# ── CIS-IAM-1.14 Rotación de access keys ─────────────────────────────────────

class TestAccessKeyRotation:

    def test_fail_when_key_older_than_90_days(self):
        from datetime import datetime, timezone, timedelta
        raw = _base_raw()
        old_date = datetime.now(timezone.utc) - timedelta(days=95)
        raw["users"] = {
            "charlie": {
                "user":              {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/charlie"},
                "mfa_devices":       [],
                "access_keys":       [{
                    "metadata":  {"AccessKeyId": "AKIA123", "Status": "Active", "CreateDate": old_date},
                    "age_days":  95,
                    "last_used": {},
                    "days_since_last_use": 95,
                }],
                "attached_policies": [],
                "inline_policies":   [],
                "groups":            [],
            }
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.14", "FAIL")

    def test_pass_when_key_within_90_days(self):
        from datetime import datetime, timezone, timedelta
        raw = _base_raw()
        recent_date = datetime.now(timezone.utc) - timedelta(days=30)
        raw["users"] = {
            "diana": {
                "user":              {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/diana"},
                "mfa_devices":       [],
                "access_keys":       [{
                    "metadata":  {"AccessKeyId": "AKIA456", "Status": "Active", "CreateDate": recent_date},
                    "age_days":  30,
                    "last_used": {},
                    "days_since_last_use": 30,
                }],
                "attached_policies": [],
                "inline_policies":   [],
                "groups":            [],
            }
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.14", "PASS")

    def test_skip_inactive_keys(self):
        from datetime import datetime, timezone, timedelta
        raw = _base_raw()
        raw["password_policy"] = {"MinimumPasswordLength": 14, "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True, "RequireSymbols": True, "RequireNumbers": True, "MaxPasswordAge": 90, "PasswordReusePrevention": 24}
        old_date = datetime.now(timezone.utc) - timedelta(days=200)
        raw["users"] = {
            "eve": {
                "user":              {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/eve"},
                "mfa_devices":       [],
                "access_keys":       [{
                    "metadata":  {"AccessKeyId": "AKIA789", "Status": "Inactive", "CreateDate": old_date},
                    "age_days":  200,
                    "last_used": {},
                    "days_since_last_use": 200,
                }],
                "attached_policies": [],
                "inline_policies":   [],
                "groups":            [],
            }
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        # Keys inactivas no deben generar FAIL de rotación
        assert_no_finding(findings, "CIS-IAM-1.14", "FAIL")


# ── CIS-IAM-1.15 Usuarios inactivos ──────────────────────────────────────────

class TestInactiveUsers:

    def test_fail_when_user_inactive_90_days(self):
        raw = _base_raw()
        raw["user_activity"] = {
            "ghost": {
                "days_inactive":        95,
                "is_orphaned":          True,
                "has_never_been_active": False,
                "last_activity":        "2023-01-01T00:00:00",
                "password_last_used":   None,
                "last_key_used":        None,
            }
        }
        raw["users"] = {
            "ghost": {
                "user":              {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/ghost"},
                "mfa_devices":       [],
                "access_keys":       [],
                "attached_policies": [],
                "inline_policies":   [],
                "groups":            [],
            }
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.15", "FAIL")

    def test_fail_when_user_never_active(self):
        raw = _base_raw()
        raw["user_activity"] = {
            "newuser": {
                "days_inactive":        None,
                "is_orphaned":          False,
                "has_never_been_active": True,
                "last_activity":        None,
                "password_last_used":   None,
                "last_key_used":        None,
            }
        }
        raw["users"] = {
            "newuser": {
                "user":              {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/newuser"},
                "mfa_devices":       [],
                "access_keys":       [],
                "attached_policies": [],
                "inline_policies":   [],
                "groups":            [],
            }
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.15", "FAIL")


# ── CIS-IAM-1.15 Políticas directas en usuarios ───────────────────────────────

class TestNoPoliciesDirectly:

    def test_fail_when_user_has_attached_policy(self):
        raw = _base_raw()
        raw["users"] = {
            "frank": {
                "user":              {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/frank"},
                "mfa_devices":       [],
                "access_keys":       [],
                "attached_policies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}],
                "inline_policies":   [],
                "groups":            [],
            }
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.15", "FAIL")

    def test_pass_when_user_has_no_direct_policies(self):
        raw = _base_raw()
        raw["users"] = {
            "grace": {
                "user":              {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/grace"},
                "mfa_devices":       [],
                "access_keys":       [],
                "attached_policies": [],
                "inline_policies":   [],
                "groups":            [{"GroupName": "Developers"}],
            }
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.15", "PASS")


# ── CIS-IAM-1.16 Sin políticas *:* ───────────────────────────────────────────

class TestNoStarStarPolicies:

    def test_fail_when_policy_has_star_star(self):
        raw = _base_raw()
        raw["customer_policies"] = {
            "DangerousPolicy": {
                "policy":        {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:policy/DangerousPolicy"},
                "has_star_star": True,
                "document":      {},
            }
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.16", "FAIL")

    def test_pass_when_policy_is_scoped(self):
        raw = _base_raw()
        raw["customer_policies"] = {
            "ScopedPolicy": {
                "policy":        {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:policy/ScopedPolicy"},
                "has_star_star": False,
                "document":      {},
            }
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.16", "PASS")


# ── CIS-IAM-1.17 Support role ─────────────────────────────────────────────────

class TestSupportRole:

    def test_fail_when_no_support_role(self):
        raw = _base_raw()
        raw["support_role_exists"] = False
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.17", "FAIL")

    def test_pass_when_support_role_exists(self):
        raw = _base_raw()
        raw["support_role_exists"] = True
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.17", "PASS")


# ── CIS-IAM-1.20 Access Analyzer ─────────────────────────────────────────────

class TestAccessAnalyzer:

    def test_fail_when_not_enabled(self):
        raw = _base_raw()
        raw["access_analyzer"] = {"enabled": False, "analyzers": []}
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.20", "FAIL")

    def test_pass_when_enabled(self):
        raw = _base_raw()
        raw["access_analyzer"] = {"enabled": True, "analyzers": [{"name": "my-analyzer", "status": "ACTIVE"}]}
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "CIS-IAM-1.20", "PASS")


# ── WAF-IAM-G01 Grupos vacíos ─────────────────────────────────────────────────

class TestGroupsHaveUsers:

    def test_fail_when_group_is_empty(self):
        raw = _base_raw()
        raw["groups"] = {
            "EmptyGroup": {
                "group":             {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:group/EmptyGroup"},
                "users":             [],
                "attached_policies": [],
                "inline_policies":   [],
            }
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "WAF-IAM-G01", "FAIL")

    def test_pass_when_group_has_users(self):
        raw = _base_raw()
        raw["groups"] = {
            "DevTeam": {
                "group":             {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:group/DevTeam"},
                "users":             [{"UserName": "alice"}],
                "attached_policies": [],
                "inline_policies":   [],
            }
        }
        output   = make_collector_output("iam", raw)
        findings = iam_analyzer.analyze(output)
        assert_finding(findings, "WAF-IAM-G01", "PASS")


# ── Test de integración — configuración segura completa ───────────────────────

class TestSecureConfiguration:

    def test_no_critical_fails_with_secure_config(self, iam_raw_secure):
        output   = make_collector_output("iam", iam_raw_secure)
        findings = iam_analyzer.analyze(output)
        critical_fails = [
            f for f in findings
            if f.status.value == "FAIL" and f.severity.value == "CRITICAL"
        ]
        assert len(critical_fails) == 0, (
            f"Expected no CRITICAL fails with secure config, "
            f"got: {[(f.control_id, f.message) for f in critical_fails]}"
        )