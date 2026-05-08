from datetime import datetime, timezone
from typing import Any

from schemas.collector_output import CollectorOutput
from schemas.finding import Finding, Severity, Status, Framework
from utils.logger import get_logger

logger = get_logger(__name__)

SERVICE   = "iam"
FRAMEWORK = Framework.CIS_AWS_1_4


def analyze(output: CollectorOutput) -> list[Finding]:
    """
    [ANZ-01] Evalúa controles CIS/WAF sobre datos recopilados por iam_collector.
    Retorna una lista de Finding con PASS, FAIL o SKIP por control y recurso.
    """
    raw        = output.raw_data
    account_id = output.account_id
    region     = output.region
    findings: list[Finding] = []

    checks = [
        _check_root_no_access_keys,
        _check_root_mfa,
        _check_root_virtual_mfa,
        _check_password_policy,
        _check_mfa_all_users,
        _check_access_key_rotation,
        _check_inactive_users,
        _check_no_root_access_keys,
        _check_no_policies_attached_directly,
        _check_no_star_star_policies,
        _check_support_role,
        _check_access_analyzer,
        _check_groups_have_users,
    ]

    for check in checks:
        try:
            results = check(raw, account_id, region)
            findings.extend(results)
        except Exception as e:
            logger.error(f"IAM: error en {check.__name__} — {e}")

    passed = sum(1 for f in findings if f.status == Status.PASS)
    failed = sum(1 for f in findings if f.status == Status.FAIL)
    logger.info(f"IAM analyzer: {passed} PASS, {failed} FAIL, {len(findings)} total")

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _finding(
    control_id: str,
    control_name: str,
    status: Status,
    severity: Severity,
    resource_id: str,
    region: str,
    account_id: str,
    message: str,
    remediation: str,
    evidence: dict = None,
) -> Finding:
    return Finding(
        control_id=control_id,
        control_name=control_name,
        framework=FRAMEWORK,
        service=SERVICE,
        status=status,
        severity=severity,
        resource_id=resource_id,
        region=region,
        account_id=account_id,
        message=message,
        remediation=remediation,
        evidence=evidence or {},
    )


def _root_arn(account_id: str) -> str:
    return f"arn:aws:iam::{account_id}:root"


# ── Controles ─────────────────────────────────────────────────────────────────

def _check_root_no_access_keys(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 1.4 — Root account no debe tener access keys activas."""
    cid  = "CIS-IAM-1.4"
    name = "Root account has no active access keys"

    for entry in raw.get("credential_report", []):
        if entry.get("user") != "<root_account>":
            continue

        key1_active = entry.get("access_key_1_active", "false").lower() == "true"
        key2_active = entry.get("access_key_2_active", "false").lower() == "true"

        if key1_active or key2_active:
            return [_finding(
                cid, name, Status.FAIL, Severity.CRITICAL,
                _root_arn(account_id), region, account_id,
                "Root account has active access keys. This is a critical security risk.",
                "Delete all access keys associated with the root account via IAM console.",
                {"key1_active": key1_active, "key2_active": key2_active},
            )]
        return [_finding(
            cid, name, Status.PASS, Severity.CRITICAL,
            _root_arn(account_id), region, account_id,
            "Root account has no active access keys.",
            "N/A",
        )]

    return []


def _check_root_mfa(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 1.5 — Root account debe tener MFA habilitado."""
    cid  = "CIS-IAM-1.5"
    name = "Root account MFA enabled"

    for entry in raw.get("credential_report", []):
        if entry.get("user") != "<root_account>":
            continue

        mfa_active = entry.get("mfa_active", "false").lower() == "true"
        status     = Status.PASS if mfa_active else Status.FAIL

        return [_finding(
            cid, name, status,
            Severity.CRITICAL,
            _root_arn(account_id), region, account_id,
            "Root account has MFA enabled." if mfa_active else "Root account does not have MFA enabled.",
            "N/A" if mfa_active else "Enable MFA on the root account using a hardware or virtual MFA device.",
            {"mfa_active": mfa_active},
        )]
    return []


def _check_root_virtual_mfa(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 1.6 — Root account debe usar hardware MFA, no virtual MFA."""
    cid  = "CIS-IAM-1.6"
    name = "Root account uses hardware MFA"

    virtual_mfa = raw.get("root_virtual_mfa")

    if virtual_mfa:
        return [_finding(
            cid, name, Status.FAIL, Severity.HIGH,
            _root_arn(account_id), region, account_id,
            "Root account is using a virtual MFA device. Hardware MFA is recommended.",
            "Replace virtual MFA with a hardware MFA device for the root account.",
            {"serial_number": virtual_mfa.get("SerialNumber")},
        )]
    return [_finding(
        cid, name, Status.PASS, Severity.HIGH,
        _root_arn(account_id), region, account_id,
        "Root account is not using a virtual MFA device.",
        "N/A",
    )]


def _check_password_policy(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 1.8-1.11 — Password policy debe cumplir requisitos mínimos."""
    findings = []
    policy   = raw.get("password_policy")
    resource = f"arn:aws:iam::{account_id}:account-password-policy"

    CONTROLS = [
        ("CIS-IAM-1.8",  "Password minimum length >= 14",
         Severity.MEDIUM, "MinimumPasswordLength", lambda v: v >= 14,
         "Password minimum length is less than 14 characters.",
         "Set password minimum length to at least 14 in IAM password policy."),

        ("CIS-IAM-1.9",  "Password requires uppercase letters",
         Severity.LOW, "RequireUppercaseCharacters", lambda v: v is True,
         "Password policy does not require uppercase characters.",
         "Enable RequireUppercaseCharacters in IAM password policy."),

        ("CIS-IAM-1.10", "Password requires lowercase letters",
         Severity.LOW, "RequireLowercaseCharacters", lambda v: v is True,
         "Password policy does not require lowercase characters.",
         "Enable RequireLowercaseCharacters in IAM password policy."),

        ("CIS-IAM-1.11", "Password requires symbols",
         Severity.LOW, "RequireSymbols", lambda v: v is True,
         "Password policy does not require symbols.",
         "Enable RequireSymbols in IAM password policy."),

        ("CIS-IAM-1.12", "Password requires numbers",
         Severity.LOW, "RequireNumbers", lambda v: v is True,
         "Password policy does not require numbers.",
         "Enable RequireNumbers in IAM password policy."),

        ("CIS-IAM-1.13", "Password expiry <= 90 days",
         Severity.MEDIUM, "MaxPasswordAge", lambda v: 0 < v <= 90,
         "Password expiry is not set or exceeds 90 days.",
         "Set MaxPasswordAge to 90 or fewer days in IAM password policy."),

        ("CIS-IAM-1.14", "Password reuse prevention >= 24",
         Severity.MEDIUM, "PasswordReusePrevention", lambda v: v >= 24,
         "Password reuse prevention is less than 24.",
         "Set PasswordReusePrevention to 24 or more in IAM password policy."),
    ]

    if not policy:
        for cid, cname, severity, _, _, fail_msg, remediation in CONTROLS:
            findings.append(_finding(
                cid, cname, Status.FAIL, severity,
                resource, region, account_id,
                "No IAM password policy is configured. " + fail_msg,
                remediation,
                {"password_policy": None},
            ))
        return findings

    for cid, cname, severity, field, validator, fail_msg, remediation in CONTROLS:
        value  = policy.get(field, 0 if "Length" in field or "Age" in field or "Reuse" in field else False)
        passed = validator(value)
        findings.append(_finding(
            cid, cname,
            Status.PASS if passed else Status.FAIL,
            severity,
            resource, region, account_id,
            f"Password policy {field} = {value}. Control {'passing' if passed else 'failing'}.",
            "N/A" if passed else remediation,
            {field: value},
        ))

    return findings


def _check_mfa_all_users(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 1.10 — Todos los usuarios con contraseña deben tener MFA."""
    cid  = "CIS-IAM-1.10"
    name = "MFA enabled for all IAM users with console access"
    findings = []

    for username, user_data in raw.get("users", {}).items():
        has_password = any(
            entry.get("user") == username and
            entry.get("password_enabled", "false").lower() == "true"
            for entry in raw.get("credential_report", [])
        )
        if not has_password:
            continue

        has_mfa  = len(user_data.get("mfa_devices", [])) > 0
        resource = user_data.get("user", {}).get("Arn", f"arn:aws:iam::{account_id}:user/{username}")

        findings.append(_finding(
            cid, name,
            Status.PASS if has_mfa else Status.FAIL,
            Severity.HIGH,
            resource, region, account_id,
            f"User '{username}' {'has' if has_mfa else 'does not have'} MFA enabled.",
            "N/A" if has_mfa else f"Enable MFA for IAM user '{username}'.",
            {"username": username, "mfa_devices": len(user_data.get("mfa_devices", []))},
        ))

    return findings


def _check_access_key_rotation(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 1.14 — Access keys no deben tener más de 90 días sin rotación."""
    cid      = "CIS-IAM-1.14"
    name     = "Access keys rotated within 90 days"
    findings = []
    max_days = 90

    for username, user_data in raw.get("users", {}).items():
        resource = user_data.get("user", {}).get("Arn", f"arn:aws:iam::{account_id}:user/{username}")

        for key in user_data.get("access_keys", []):
            meta     = key.get("metadata", {})
            key_id   = meta.get("AccessKeyId", "unknown")
            status_k = meta.get("Status", "Inactive")
            age_days = key.get("age_days")

            if status_k != "Active":
                continue

            if age_days is None:
                findings.append(_finding(
                    cid, name, Status.SKIP, Severity.HIGH,
                    resource, region, account_id,
                    f"User '{username}' key '{key_id}' — could not determine key age.",
                    "Verify key creation date manually.",
                    {"key_id": key_id},
                ))
                continue

            passed = age_days <= max_days
            findings.append(_finding(
                cid, name,
                Status.PASS if passed else Status.FAIL,
                Severity.HIGH,
                resource, region, account_id,
                f"User '{username}' key '{key_id}' is {age_days} days old.",
                "N/A" if passed else f"Rotate access key '{key_id}' for user '{username}'.",
                {"key_id": key_id, "age_days": age_days, "threshold_days": max_days},
            ))

    return findings


def _check_inactive_users(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 1.15 — Usuarios sin actividad por más de 90 días deben ser deshabilitados."""
    cid      = "CIS-IAM-1.15"
    name     = "IAM users inactive for 90+ days disabled or removed"
    findings = []

    for username, activity in raw.get("user_activity", {}).items():
        user_data = raw.get("users", {}).get(username, {})
        resource  = user_data.get("user", {}).get("Arn", f"arn:aws:iam::{account_id}:user/{username}")

        if activity.get("has_never_been_active"):
            findings.append(_finding(
                cid, name, Status.FAIL, Severity.MEDIUM,
                resource, region, account_id,
                f"User '{username}' has never been active.",
                f"Review and disable or remove IAM user '{username}' if no longer needed.",
                {"username": username, "days_inactive": None, "never_active": True},
            ))
            continue

        days_inactive = activity.get("days_inactive")
        is_orphaned   = activity.get("is_orphaned", False)

        findings.append(_finding(
            cid, name,
            Status.FAIL if is_orphaned else Status.PASS,
            Severity.MEDIUM,
            resource, region, account_id,
            f"User '{username}' has been inactive for {days_inactive} days.",
            "N/A" if not is_orphaned else f"Disable or remove IAM user '{username}' — inactive for {days_inactive} days.",
            {"username": username, "days_inactive": days_inactive, "last_activity": activity.get("last_activity")},
        ))

    return findings


def _check_no_root_access_keys(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 1.4 (complemento) — verificación explícita en credential report."""
    # Ya cubierto en _check_root_no_access_keys, se omite duplicado
    return []


def _check_no_policies_attached_directly(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 1.15 — No adjuntar políticas directamente a usuarios (usar grupos)."""
    cid      = "CIS-IAM-1.15"
    name     = "IAM policies attached only via groups"
    findings = []

    for username, user_data in raw.get("users", {}).items():
        resource          = user_data.get("user", {}).get("Arn", f"arn:aws:iam::{account_id}:user/{username}")
        attached_policies = user_data.get("attached_policies", [])
        inline_policies   = user_data.get("inline_policies", [])
        has_direct        = len(attached_policies) > 0 or len(inline_policies) > 0

        findings.append(_finding(
            cid, name,
            Status.FAIL if has_direct else Status.PASS,
            Severity.MEDIUM,
            resource, region, account_id,
            f"User '{username}' has {len(attached_policies)} attached and {len(inline_policies)} inline policies directly.",
            "N/A" if not has_direct else f"Move policies for '{username}' to an IAM group.",
            {
                "username":          username,
                "attached_policies": [p["PolicyName"] for p in attached_policies],
                "inline_policies":   inline_policies,
            },
        ))

    return findings


def _check_no_star_star_policies(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 1.16 — No crear políticas con permisos *:* (admin completo)."""
    cid      = "CIS-IAM-1.16"
    name     = "No IAM policies with full admin permissions (*:*)"
    findings = []

    for pname, policy_data in raw.get("customer_policies", {}).items():
        policy   = policy_data.get("policy", {})
        resource = policy.get("Arn", f"arn:aws:iam::{account_id}:policy/{pname}")
        has_star = policy_data.get("has_star_star", False)

        findings.append(_finding(
            cid, name,
            Status.FAIL if has_star else Status.PASS,
            Severity.CRITICAL,
            resource, region, account_id,
            f"Policy '{pname}' {'grants full admin (*:*) permissions' if has_star else 'does not grant full admin permissions'}.",
            "N/A" if not has_star else f"Remove the *:* statement from policy '{pname}' and apply least privilege.",
            {"policy_name": pname, "has_star_star": has_star},
        ))

    return findings


def _check_support_role(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 1.17 — Debe existir un rol con AWSSupportAccess policy."""
    cid      = "CIS-IAM-1.17"
    name     = "Support role created for incident management"
    resource = f"arn:aws:iam::{account_id}:policy/AWSSupportAccess"
    exists   = raw.get("support_role_exists", False)

    return [_finding(
        cid, name,
        Status.PASS if exists else Status.FAIL,
        Severity.LOW,
        resource, region, account_id,
        "AWSSupportAccess policy exists." if exists else "No role with AWSSupportAccess policy found.",
        "N/A" if exists else "Create an IAM role with AWSSupportAccess policy for incident management.",
        {"support_role_exists": exists},
    )]


def _check_access_analyzer(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 1.20 — IAM Access Analyzer debe estar habilitado."""
    cid      = "CIS-IAM-1.20"
    name     = "IAM Access Analyzer enabled"
    resource = f"arn:aws:accessanalyzer:{region}:{account_id}:analyzer"
    aa       = raw.get("access_analyzer", {})
    enabled  = aa.get("enabled", False)

    return [_finding(
        cid, name,
        Status.PASS if enabled else Status.FAIL,
        Severity.MEDIUM,
        resource, region, account_id,
        f"IAM Access Analyzer is {'active' if enabled else 'not enabled'} in region {region}.",
        "N/A" if enabled else f"Enable IAM Access Analyzer in region {region}.",
        {"analyzers": [a.get("name") for a in aa.get("analyzers", [])]},
    )]


def _check_groups_have_users(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Grupos IAM vacíos deben eliminarse."""
    cid      = "WAF-IAM-G01"
    name     = "IAM groups are not empty"
    findings = []

    for gname, group_data in raw.get("groups", {}).items():
        resource  = group_data.get("group", {}).get("Arn", f"arn:aws:iam::{account_id}:group/{gname}")
        has_users = len(group_data.get("users", [])) > 0

        findings.append(_finding(
            cid, name,
            Status.PASS if has_users else Status.FAIL,
            Severity.LOW,
            resource, region, account_id,
            f"Group '{gname}' {'has users' if has_users else 'is empty'}.",
            "N/A" if has_users else f"Remove empty IAM group '{gname}' or assign users to it.",
            {"group": gname, "user_count": len(group_data.get("users", []))},
        ))

    return findings