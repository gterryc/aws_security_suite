import json
from schemas.collector_output import CollectorOutput
from schemas.finding import Finding, Severity, Status, Framework
from utils.logger import get_logger

logger = get_logger(__name__)

SERVICE   = "s3"
FRAMEWORK = Framework.CIS_AWS_1_4


def analyze(output: CollectorOutput) -> list[Finding]:
    """
    [ANZ-02] Evalúa controles CIS/WAF sobre datos recopilados por s3_collector.
    """
    raw        = output.raw_data
    account_id = output.account_id
    region     = output.region
    findings: list[Finding] = []

    checks = [
        _check_account_public_access_block,
        _check_bucket_public_access_block,
        _check_bucket_public_acl,
        _check_bucket_public_policy,
        _check_bucket_encryption,
        _check_bucket_versioning,
        _check_bucket_logging,
        _check_bucket_replication,
        _check_bucket_lifecycle,
        _check_bucket_object_lock,
        _check_bucket_ssl_only,
        _check_bucket_website_exposure,
    ]

    for check in checks:
        try:
            findings.extend(check(raw, account_id, region))
        except Exception as e:
            logger.error(f"S3: error en {check.__name__} — {e}")

    passed = sum(1 for f in findings if f.status == Status.PASS)
    failed = sum(1 for f in findings if f.status == Status.FAIL)
    logger.info(f"S3 analyzer: {passed} PASS, {failed} FAIL, {len(findings)} total")

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


def _bucket_arn(name: str) -> str:
    return f"arn:aws:s3:::{name}"


def _all_blocked(pab: dict) -> bool:
    return all([
        pab.get("BlockPublicAcls", False),
        pab.get("IgnorePublicAcls", False),
        pab.get("BlockPublicPolicy", False),
        pab.get("RestrictPublicBuckets", False),
    ])


# ── Controles ─────────────────────────────────────────────────────────────────

def _check_account_public_access_block(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.1.2 — Block Public Access habilitado a nivel de cuenta."""
    cid      = "CIS-S3-2.1.2"
    name     = "S3 account-level Block Public Access enabled"
    resource = f"arn:aws:s3:::account-public-access-block:{account_id}"
    pab      = raw.get("account_public_access_block")

    if pab is None:
        return [_finding(
            cid, name, Status.FAIL, Severity.HIGH,
            resource, region, account_id,
            "Account-level S3 Block Public Access configuration could not be retrieved.",
            "Enable all four Block Public Access settings at the account level via S3 console or CLI.",
            {"error": "configuration not found"},
        )]

    blocked = _all_blocked(pab)
    return [_finding(
        cid, name,
        Status.PASS if blocked else Status.FAIL,
        Severity.HIGH,
        resource, region, account_id,
        "Account-level Block Public Access is fully enabled." if blocked
        else "Account-level Block Public Access is not fully enabled.",
        "N/A" if blocked else
        "Enable all four settings: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.",
        pab,
    )]


def _check_bucket_public_access_block(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.1.1 — Block Public Access habilitado en cada bucket."""
    cid      = "CIS-S3-2.1.1"
    name     = "S3 bucket Block Public Access enabled"
    findings = []

    for bname, bucket in raw.get("buckets", {}).items():
        pab     = bucket.get("public_access_block") or {}
        blocked = _all_blocked(pab)
        findings.append(_finding(
            cid, name,
            Status.PASS if blocked else Status.FAIL,
            Severity.HIGH,
            _bucket_arn(bname), region, account_id,
            f"Bucket '{bname}' Block Public Access is fully enabled." if blocked
            else f"Bucket '{bname}' Block Public Access is not fully enabled.",
            "N/A" if blocked else
            f"Enable all four Block Public Access settings on bucket '{bname}'.",
            {"bucket": bname, "public_access_block": pab},
        ))

    return findings


def _check_bucket_public_acl(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.1.3 — Ningún bucket debe tener ACL pública."""
    cid      = "CIS-S3-2.1.3"
    name     = "S3 bucket ACL not public"
    findings = []

    for bname, bucket in raw.get("buckets", {}).items():
        acl        = bucket.get("acl") or {}
        acl_public = False
        public_grants = []

        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri     = grantee.get("URI", "")
            if uri in (
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            ):
                acl_public = True
                public_grants.append({
                    "grantee": uri,
                    "permission": grant.get("Permission"),
                })

        findings.append(_finding(
            cid, name,
            Status.FAIL if acl_public else Status.PASS,
            Severity.CRITICAL,
            _bucket_arn(bname), region, account_id,
            f"Bucket '{bname}' has public ACL grants." if acl_public
            else f"Bucket '{bname}' has no public ACL grants.",
            "N/A" if not acl_public else
            f"Remove public ACL grants from bucket '{bname}' and enable Block Public ACLs.",
            {"bucket": bname, "public_grants": public_grants},
        ))

    return findings


def _check_bucket_public_policy(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.1.4 — Ningún bucket debe tener política pública."""
    cid      = "CIS-S3-2.1.4"
    name     = "S3 bucket policy not public"
    findings = []

    for bname, bucket in raw.get("buckets", {}).items():
        policy_status = bucket.get("policy_status") or {}
        is_public     = policy_status.get("IsPublic", False)

        findings.append(_finding(
            cid, name,
            Status.FAIL if is_public else Status.PASS,
            Severity.CRITICAL,
            _bucket_arn(bname), region, account_id,
            f"Bucket '{bname}' policy is marked as public." if is_public
            else f"Bucket '{bname}' policy is not public.",
            "N/A" if not is_public else
            f"Review and restrict the bucket policy for '{bname}'. Enable RestrictPublicBuckets.",
            {"bucket": bname, "is_public": is_public},
        ))

    return findings


def _check_bucket_encryption(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.1.1 / WAF — Todos los buckets deben tener SSE habilitado."""
    cid      = "CIS-S3-2.1.1-ENC"
    name     = "S3 bucket server-side encryption enabled"
    findings = []

    for bname, bucket in raw.get("buckets", {}).items():
        enc_type = bucket.get("encryption_type")
        encrypted = enc_type is not None

        findings.append(_finding(
            cid, name,
            Status.PASS if encrypted else Status.FAIL,
            Severity.HIGH,
            _bucket_arn(bname), region, account_id,
            f"Bucket '{bname}' is encrypted with {enc_type}." if encrypted
            else f"Bucket '{bname}' has no server-side encryption configured.",
            "N/A" if encrypted else
            f"Enable SSE on bucket '{bname}' using AES-256 or aws:kms.",
            {"bucket": bname, "encryption_type": enc_type},
        ))

    return findings


def _check_bucket_versioning(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.1.3 / WAF — Versioning habilitado para proteger contra borrado accidental."""
    cid      = "WAF-S3-VER-01"
    name     = "S3 bucket versioning enabled"
    findings = []

    for bname, bucket in raw.get("buckets", {}).items():
        enabled = bucket.get("versioning_enabled", False)

        findings.append(_finding(
            cid, name,
            Status.PASS if enabled else Status.FAIL,
            Severity.MEDIUM,
            _bucket_arn(bname), region, account_id,
            f"Bucket '{bname}' versioning is enabled." if enabled
            else f"Bucket '{bname}' versioning is disabled.",
            "N/A" if enabled else
            f"Enable versioning on bucket '{bname}' to protect against accidental deletion.",
            {"bucket": bname, "versioning_enabled": enabled},
        ))

    return findings


def _check_bucket_logging(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.6 — Access logging habilitado en todos los buckets."""
    cid      = "CIS-S3-2.6"
    name     = "S3 bucket access logging enabled"
    findings = []

    for bname, bucket in raw.get("buckets", {}).items():
        logging_enabled = bucket.get("logging_enabled", False)

        findings.append(_finding(
            cid, name,
            Status.PASS if logging_enabled else Status.FAIL,
            Severity.MEDIUM,
            _bucket_arn(bname), region, account_id,
            f"Bucket '{bname}' access logging is enabled." if logging_enabled
            else f"Bucket '{bname}' access logging is disabled.",
            "N/A" if logging_enabled else
            f"Enable access logging on bucket '{bname}' and configure a target logging bucket.",
            {"bucket": bname, "logging_enabled": logging_enabled},
        ))

    return findings


def _check_bucket_replication(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Buckets con datos críticos deben tener replicación configurada."""
    cid      = "WAF-S3-REP-01"
    name     = "S3 bucket replication configured"
    findings = []

    for bname, bucket in raw.get("buckets", {}).items():
        replication = bucket.get("replication")
        has_replication = replication is not None

        findings.append(_finding(
            cid, name,
            Status.PASS if has_replication else Status.FAIL,
            Severity.LOW,
            _bucket_arn(bname), region, account_id,
            f"Bucket '{bname}' has replication configured." if has_replication
            else f"Bucket '{bname}' has no replication configured.",
            "N/A" if has_replication else
            f"Consider enabling cross-region replication on bucket '{bname}' for disaster recovery.",
            {"bucket": bname, "replication": bool(replication)},
        ))

    return findings


def _check_bucket_lifecycle(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Buckets deben tener política de ciclo de vida para gestión de costos y datos."""
    cid      = "WAF-S3-LCY-01"
    name     = "S3 bucket lifecycle policy configured"
    findings = []

    for bname, bucket in raw.get("buckets", {}).items():
        has_lifecycle = bucket.get("has_lifecycle", False)

        findings.append(_finding(
            cid, name,
            Status.PASS if has_lifecycle else Status.FAIL,
            Severity.LOW,
            _bucket_arn(bname), region, account_id,
            f"Bucket '{bname}' has a lifecycle policy." if has_lifecycle
            else f"Bucket '{bname}' has no lifecycle policy.",
            "N/A" if has_lifecycle else
            f"Configure a lifecycle policy on bucket '{bname}' to manage object expiration and transitions.",
            {"bucket": bname, "has_lifecycle": has_lifecycle},
        ))

    return findings


def _check_bucket_object_lock(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Object Lock en buckets con datos de compliance o auditoría."""
    cid      = "WAF-S3-OBL-01"
    name     = "S3 bucket object lock configured"
    findings = []

    for bname, bucket in raw.get("buckets", {}).items():
        object_lock    = bucket.get("object_lock")
        lock_enabled   = object_lock is not None and object_lock.get("ObjectLockEnabled") == "Enabled"

        findings.append(_finding(
            cid, name,
            Status.PASS if lock_enabled else Status.FAIL,
            Severity.LOW,
            _bucket_arn(bname), region, account_id,
            f"Bucket '{bname}' has Object Lock enabled." if lock_enabled
            else f"Bucket '{bname}' does not have Object Lock enabled.",
            "N/A" if lock_enabled else
            f"Enable Object Lock on bucket '{bname}' if it stores compliance or audit data.",
            {"bucket": bname, "object_lock_enabled": lock_enabled},
        ))

    return findings


def _check_bucket_ssl_only(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.1.2 / WAF — Bucket policy debe denegar acceso HTTP (solo HTTPS)."""
    cid      = "WAF-S3-SSL-01"
    name     = "S3 bucket enforces SSL-only access"
    findings = []

    for bname, bucket in raw.get("buckets", {}).items():
        policy_str  = bucket.get("policy")
        ssl_enforced = False

        if policy_str:
            try:
                policy = json.loads(policy_str)
                for stmt in policy.get("Statement", []):
                    effect     = stmt.get("Effect", "")
                    conditions = stmt.get("Condition", {})
                    aws_secure = conditions.get("Bool", {}).get("aws:SecureTransport")
                    if effect == "Deny" and aws_secure in ("false", False):
                        ssl_enforced = True
                        break
            except Exception:
                pass

        findings.append(_finding(
            cid, name,
            Status.PASS if ssl_enforced else Status.FAIL,
            Severity.HIGH,
            _bucket_arn(bname), region, account_id,
            f"Bucket '{bname}' enforces SSL-only access via bucket policy." if ssl_enforced
            else f"Bucket '{bname}' does not enforce SSL-only access.",
            "N/A" if ssl_enforced else
            f"Add a bucket policy to bucket '{bname}' that denies requests where aws:SecureTransport is false.",
            {"bucket": bname, "ssl_enforced": ssl_enforced},
        ))

    return findings


def _check_bucket_website_exposure(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Buckets con sitio web estático habilitado deben revisarse."""
    cid      = "WAF-S3-WEB-01"
    name     = "S3 bucket static website hosting reviewed"
    findings = []

    for bname, bucket in raw.get("buckets", {}).items():
        website = bucket.get("website")
        if website is None:
            continue

        findings.append(_finding(
            cid, name,
            Status.FAIL,
            Severity.MEDIUM,
            _bucket_arn(bname), region, account_id,
            f"Bucket '{bname}' has static website hosting enabled. Verify this is intentional.",
            f"Review bucket '{bname}' — if website hosting is not required, disable it. "
            f"If intentional, ensure CloudFront is used instead of direct S3 access.",
            {"bucket": bname, "website_config": website},
        ))

    return findings