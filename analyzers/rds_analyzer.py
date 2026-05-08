from schemas.collector_output import CollectorOutput
from schemas.finding import Finding, Severity, Status, Framework
from utils.logger import get_logger

logger = get_logger(__name__)

SERVICE   = "rds"
FRAMEWORK = Framework.CIS_AWS_1_4


def analyze(output: CollectorOutput) -> list[Finding]:
    """
    [ANZ-04] Evalúa controles CIS/WAF sobre datos recopilados por rds_collector.
    """
    raw        = output.raw_data
    account_id = output.account_id
    region     = output.region
    findings: list[Finding] = []

    checks = [
        _check_instances_not_public,
        _check_instances_encrypted,
        _check_instances_multi_az,
        _check_instances_backup_retention,
        _check_instances_deletion_protection,
        _check_instances_iam_auth,
        _check_instances_missing_logs,
        _check_instances_auto_minor_upgrade,
        _check_instances_performance_insights,
        _check_snapshots_not_public,
        _check_cluster_snapshots_not_public,
        _check_clusters_encrypted,
        _check_clusters_backup_retention,
        _check_clusters_deletion_protection,
        _check_clusters_missing_logs,
        _check_parameter_groups_ssl,
        _check_event_subscriptions,
    ]

    for check in checks:
        try:
            findings.extend(check(raw, account_id, region))
        except Exception as e:
            logger.error(f"RDS: error en {check.__name__} — {e}")

    passed = sum(1 for f in findings if f.status == Status.PASS)
    failed = sum(1 for f in findings if f.status == Status.FAIL)
    logger.info(f"RDS analyzer: {passed} PASS, {failed} FAIL, {len(findings)} total")

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


def _db_arn(db_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:rds:{region}:{account_id}:db:{db_id}"


def _cluster_arn(cluster_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:rds:{region}:{account_id}:cluster:{cluster_id}"


def _snapshot_arn(snap_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:rds:{region}:{account_id}:snapshot:{snap_id}"


def _cluster_snapshot_arn(snap_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:rds:{region}:{account_id}:cluster-snapshot:{snap_id}"


# ── Controles — Instancias ────────────────────────────────────────────────────

def _check_instances_not_public(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.3.2 — Instancias RDS no deben ser públicamente accesibles."""
    cid      = "CIS-RDS-2.3.2"
    name     = "RDS instances not publicly accessible"
    findings = []

    for dbid, db in raw.get("instances", {}).items():
        is_public = db.get("publicly_accessible", False)
        findings.append(_finding(
            cid, name,
            Status.FAIL if is_public else Status.PASS,
            Severity.CRITICAL,
            _db_arn(dbid, region, account_id), region, account_id,
            f"DB instance '{dbid}' is publicly accessible." if is_public
            else f"DB instance '{dbid}' is not publicly accessible.",
            "N/A" if not is_public else
            f"Disable public accessibility on DB instance '{dbid}' and place it in a private subnet.",
            {"db_id": dbid, "engine": db.get("engine"), "publicly_accessible": is_public},
        ))

    return findings


def _check_instances_encrypted(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.3.1 — Instancias RDS deben estar encriptadas en reposo."""
    cid      = "CIS-RDS-2.3.1"
    name     = "RDS instances encrypted at rest"
    findings = []

    for dbid, db in raw.get("instances", {}).items():
        encrypted = db.get("encrypted", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if encrypted else Status.FAIL,
            Severity.HIGH,
            _db_arn(dbid, region, account_id), region, account_id,
            f"DB instance '{dbid}' is encrypted at rest." if encrypted
            else f"DB instance '{dbid}' is not encrypted at rest.",
            "N/A" if encrypted else
            f"Create an encrypted snapshot of '{dbid}' and restore to a new encrypted instance.",
            {"db_id": dbid, "encrypted": encrypted, "kms_key_id": db.get("kms_key_id")},
        ))

    return findings


def _check_instances_multi_az(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.3.2 / WAF — Instancias RDS deben tener Multi-AZ habilitado."""
    cid      = "WAF-RDS-MAZ-01"
    name     = "RDS instances have Multi-AZ enabled"
    findings = []

    for dbid, db in raw.get("instances", {}).items():
        multi_az = db.get("multi_az", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if multi_az else Status.FAIL,
            Severity.HIGH,
            _db_arn(dbid, region, account_id), region, account_id,
            f"DB instance '{dbid}' has Multi-AZ enabled." if multi_az
            else f"DB instance '{dbid}' does not have Multi-AZ enabled.",
            "N/A" if multi_az else
            f"Enable Multi-AZ on DB instance '{dbid}' for high availability.",
            {"db_id": dbid, "multi_az": multi_az},
        ))

    return findings


def _check_instances_backup_retention(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.3.1 — Backup retention debe ser al menos 7 días."""
    cid      = "CIS-RDS-2.3.1-BCK"
    name     = "RDS instances backup retention >= 7 days"
    findings = []
    min_days = 7

    for dbid, db in raw.get("instances", {}).items():
        retention = db.get("backup_retention_days", 0)
        compliant = retention >= min_days

        findings.append(_finding(
            cid, name,
            Status.PASS if compliant else Status.FAIL,
            Severity.MEDIUM,
            _db_arn(dbid, region, account_id), region, account_id,
            f"DB instance '{dbid}' backup retention is {retention} days." ,
            "N/A" if compliant else
            f"Set backup retention to at least {min_days} days on DB instance '{dbid}'.",
            {"db_id": dbid, "backup_retention_days": retention, "minimum_required": min_days},
        ))

    return findings


def _check_instances_deletion_protection(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Deletion protection debe estar habilitado en instancias productivas."""
    cid      = "WAF-RDS-DEL-01"
    name     = "RDS instances have deletion protection enabled"
    findings = []

    for dbid, db in raw.get("instances", {}).items():
        protected = db.get("deletion_protection", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if protected else Status.FAIL,
            Severity.MEDIUM,
            _db_arn(dbid, region, account_id), region, account_id,
            f"DB instance '{dbid}' has deletion protection enabled." if protected
            else f"DB instance '{dbid}' does not have deletion protection enabled.",
            "N/A" if protected else
            f"Enable deletion protection on DB instance '{dbid}'.",
            {"db_id": dbid, "deletion_protection": protected},
        ))

    return findings


def _check_instances_iam_auth(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — IAM database authentication debe estar habilitado."""
    cid      = "WAF-RDS-IAM-01"
    name     = "RDS instances have IAM database authentication enabled"
    findings = []

    IAM_AUTH_ENGINES = {"mysql", "postgres", "aurora-mysql", "aurora-postgresql"}

    for dbid, db in raw.get("instances", {}).items():
        engine = db.get("engine", "").lower()
        if engine not in IAM_AUTH_ENGINES:
            findings.append(_finding(
                cid, name, Status.SKIP, Severity.MEDIUM,
                _db_arn(dbid, region, account_id), region, account_id,
                f"DB instance '{dbid}' engine '{engine}' does not support IAM authentication.",
                "N/A",
                {"db_id": dbid, "engine": engine},
            ))
            continue

        iam_auth = db.get("iam_auth_enabled", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if iam_auth else Status.FAIL,
            Severity.MEDIUM,
            _db_arn(dbid, region, account_id), region, account_id,
            f"DB instance '{dbid}' has IAM authentication enabled." if iam_auth
            else f"DB instance '{dbid}' does not have IAM authentication enabled.",
            "N/A" if iam_auth else
            f"Enable IAM database authentication on DB instance '{dbid}'.",
            {"db_id": dbid, "engine": engine, "iam_auth_enabled": iam_auth},
        ))

    return findings


def _check_instances_missing_logs(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.3.1 — Logs de auditoría deben estar habilitados según el motor."""
    cid      = "CIS-RDS-2.3.1-LOG"
    name     = "RDS instances have required CloudWatch logs enabled"
    findings = []

    for dbid, db in raw.get("instances", {}).items():
        missing_logs = db.get("missing_logs", [])
        compliant    = len(missing_logs) == 0

        findings.append(_finding(
            cid, name,
            Status.PASS if compliant else Status.FAIL,
            Severity.MEDIUM,
            _db_arn(dbid, region, account_id), region, account_id,
            f"DB instance '{dbid}' has all required logs enabled." if compliant
            else f"DB instance '{dbid}' is missing logs: {missing_logs}.",
            "N/A" if compliant else
            f"Enable the following CloudWatch log exports on '{dbid}': {', '.join(missing_logs)}.",
            {
                "db_id":        dbid,
                "engine":       db.get("engine"),
                "missing_logs": missing_logs,
                "enabled_logs": db.get("enabled_cloudwatch_logs", []),
            },
        ))

    return findings


def _check_instances_auto_minor_upgrade(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Auto minor version upgrade debe estar habilitado para parches de seguridad."""
    cid      = "WAF-RDS-UPG-01"
    name     = "RDS instances have auto minor version upgrade enabled"
    findings = []

    for dbid, db in raw.get("instances", {}).items():
        auto_upgrade = db.get("auto_minor_version_upgrade", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if auto_upgrade else Status.FAIL,
            Severity.LOW,
            _db_arn(dbid, region, account_id), region, account_id,
            f"DB instance '{dbid}' has auto minor version upgrade enabled." if auto_upgrade
            else f"DB instance '{dbid}' does not have auto minor version upgrade enabled.",
            "N/A" if auto_upgrade else
            f"Enable auto minor version upgrade on DB instance '{dbid}' for automatic security patches.",
            {"db_id": dbid, "auto_minor_version_upgrade": auto_upgrade},
        ))

    return findings


def _check_instances_performance_insights(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Performance Insights ayuda a detectar anomalías de acceso a la DB."""
    cid      = "WAF-RDS-PI-01"
    name     = "RDS instances have Performance Insights enabled"
    findings = []

    for dbid, db in raw.get("instances", {}).items():
        pi_enabled = db.get("performance_insights", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if pi_enabled else Status.FAIL,
            Severity.LOW,
            _db_arn(dbid, region, account_id), region, account_id,
            f"DB instance '{dbid}' has Performance Insights enabled." if pi_enabled
            else f"DB instance '{dbid}' does not have Performance Insights enabled.",
            "N/A" if pi_enabled else
            f"Enable Performance Insights on DB instance '{dbid}' to monitor database load.",
            {"db_id": dbid, "performance_insights": pi_enabled},
        ))

    return findings


# ── Controles — Snapshots ─────────────────────────────────────────────────────

def _check_snapshots_not_public(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.3.3 — Snapshots RDS no deben ser públicos."""
    cid      = "CIS-RDS-2.3.3"
    name     = "RDS snapshots not publicly accessible"
    findings = []

    for sid, snap in raw.get("snapshots", {}).items():
        is_public = snap.get("is_public", False)
        findings.append(_finding(
            cid, name,
            Status.FAIL if is_public else Status.PASS,
            Severity.CRITICAL,
            _snapshot_arn(sid, region, account_id), region, account_id,
            f"RDS snapshot '{sid}' is publicly accessible." if is_public
            else f"RDS snapshot '{sid}' is not public.",
            "N/A" if not is_public else
            f"Remove public restore permission from RDS snapshot '{sid}'.",
            {"snapshot_id": sid, "db_id": snap.get("db_id"), "encrypted": snap.get("encrypted")},
        ))

    return findings


def _check_cluster_snapshots_not_public(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.3.3 — Snapshots de clusters Aurora no deben ser públicos."""
    cid      = "CIS-RDS-2.3.3-CLU"
    name     = "RDS cluster snapshots not publicly accessible"
    findings = []

    for sid, snap in raw.get("cluster_snapshots", {}).items():
        is_public = snap.get("is_public", False)
        findings.append(_finding(
            cid, name,
            Status.FAIL if is_public else Status.PASS,
            Severity.CRITICAL,
            _cluster_snapshot_arn(sid, region, account_id), region, account_id,
            f"Cluster snapshot '{sid}' is publicly accessible." if is_public
            else f"Cluster snapshot '{sid}' is not public.",
            "N/A" if not is_public else
            f"Remove public restore permission from cluster snapshot '{sid}'.",
            {"snapshot_id": sid, "cluster_id": snap.get("cluster_id"), "encrypted": snap.get("encrypted")},
        ))

    return findings


# ── Controles — Clusters Aurora ───────────────────────────────────────────────

def _check_clusters_encrypted(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.3.1 — Clusters Aurora deben estar encriptados en reposo."""
    cid      = "CIS-RDS-2.3.1-CLU"
    name     = "Aurora clusters encrypted at rest"
    findings = []

    for cid_r, cluster in raw.get("clusters", {}).items():
        encrypted = cluster.get("encrypted", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if encrypted else Status.FAIL,
            Severity.HIGH,
            _cluster_arn(cid_r, region, account_id), region, account_id,
            f"Cluster '{cid_r}' is encrypted at rest." if encrypted
            else f"Cluster '{cid_r}' is not encrypted at rest.",
            "N/A" if encrypted else
            f"Encryption must be enabled at cluster creation. "
            f"Create a new encrypted cluster and migrate data from '{cid_r}'.",
            {"cluster_id": cid_r, "encrypted": encrypted, "kms_key_id": cluster.get("kms_key_id")},
        ))

    return findings


def _check_clusters_backup_retention(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.3.1 — Clusters Aurora deben tener backup retention >= 7 días."""
    cid      = "CIS-RDS-2.3.1-CLU-BCK"
    name     = "Aurora clusters backup retention >= 7 days"
    findings = []
    min_days = 7

    for cid_r, cluster in raw.get("clusters", {}).items():
        retention = cluster.get("backup_retention_days", 0)
        compliant = retention >= min_days

        findings.append(_finding(
            cid, name,
            Status.PASS if compliant else Status.FAIL,
            Severity.MEDIUM,
            _cluster_arn(cid_r, region, account_id), region, account_id,
            f"Cluster '{cid_r}' backup retention is {retention} days.",
            "N/A" if compliant else
            f"Set backup retention to at least {min_days} days on cluster '{cid_r}'.",
            {"cluster_id": cid_r, "backup_retention_days": retention},
        ))

    return findings


def _check_clusters_deletion_protection(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Deletion protection debe estar habilitado en clusters Aurora."""
    cid      = "WAF-RDS-CLU-DEL-01"
    name     = "Aurora clusters have deletion protection enabled"
    findings = []

    for cid_r, cluster in raw.get("clusters", {}).items():
        protected = cluster.get("deletion_protection", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if protected else Status.FAIL,
            Severity.MEDIUM,
            _cluster_arn(cid_r, region, account_id), region, account_id,
            f"Cluster '{cid_r}' has deletion protection enabled." if protected
            else f"Cluster '{cid_r}' does not have deletion protection enabled.",
            "N/A" if protected else
            f"Enable deletion protection on Aurora cluster '{cid_r}'.",
            {"cluster_id": cid_r, "deletion_protection": protected},
        ))

    return findings


def _check_clusters_missing_logs(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.3.1 — Clusters Aurora deben exportar los logs requeridos a CloudWatch."""
    cid      = "CIS-RDS-2.3.1-CLU-LOG"
    name     = "Aurora clusters have required CloudWatch logs enabled"
    findings = []

    for cid_r, cluster in raw.get("clusters", {}).items():
        missing_logs = cluster.get("missing_logs", [])
        compliant    = len(missing_logs) == 0

        findings.append(_finding(
            cid, name,
            Status.PASS if compliant else Status.FAIL,
            Severity.MEDIUM,
            _cluster_arn(cid_r, region, account_id), region, account_id,
            f"Cluster '{cid_r}' has all required logs enabled." if compliant
            else f"Cluster '{cid_r}' is missing logs: {missing_logs}.",
            "N/A" if compliant else
            f"Enable the following CloudWatch log exports on cluster '{cid_r}': {', '.join(missing_logs)}.",
            {
                "cluster_id":   cid_r,
                "engine":       cluster.get("engine"),
                "missing_logs": missing_logs,
            },
        ))

    return findings


# ── Controles — Parameter Groups ──────────────────────────────────────────────

def _check_parameter_groups_ssl(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Parameter groups deben forzar conexiones SSL/TLS."""
    cid      = "WAF-RDS-SSL-01"
    name     = "RDS parameter groups enforce SSL connections"
    findings = []

    SSL_PARAMS = {
        "require_secure_transport": "1",
        "rds.force_ssl":            "1",
        "ssl":                      "1",
    }

    for pgname, pg_data in raw.get("parameter_groups", {}).items():
        params   = pg_data.get("parameters", {})
        resource = f"arn:aws:rds:{region}:{account_id}:pg:{pgname}"

        ssl_enforced = any(
            params.get(param) == value
            for param, value in SSL_PARAMS.items()
        )

        findings.append(_finding(
            cid, name,
            Status.PASS if ssl_enforced else Status.FAIL,
            Severity.HIGH,
            resource, region, account_id,
            f"Parameter group '{pgname}' enforces SSL connections." if ssl_enforced
            else f"Parameter group '{pgname}' does not enforce SSL connections.",
            "N/A" if ssl_enforced else
            f"Set require_secure_transport=1 or rds.force_ssl=1 in parameter group '{pgname}'.",
            {"parameter_group": pgname, "ssl_params": {k: params.get(k) for k in SSL_PARAMS}},
        ))

    return findings


# ── Controles — Event Subscriptions ──────────────────────────────────────────

def _check_event_subscriptions(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Deben existir event subscriptions para eventos críticos de RDS."""
    cid      = "WAF-RDS-EVT-01"
    name     = "RDS event subscriptions configured for critical events"
    resource = f"arn:aws:rds:{region}:{account_id}:es:rds-events"

    CRITICAL_EVENTS = {
        "db-instance":  {"failure", "failover", "maintenance", "deletion"},
        "db-cluster":   {"failure", "failover", "maintenance", "deletion"},
        "db-security-group": {"failure", "configuration change"},
    }

    subs = raw.get("event_subscriptions", {})

    if not subs:
        return [_finding(
            cid, name, Status.FAIL, Severity.MEDIUM,
            resource, region, account_id,
            "No RDS event subscriptions are configured.",
            "Create RDS event subscriptions for db-instance and db-cluster failure, failover, and deletion events.",
            {"subscriptions": []},
        )]

    covered_events: dict[str, set] = {}
    for sub in subs.values():
        if not sub.get("enabled"):
            continue
        source_type = sub.get("source_type", "")
        categories  = set(sub.get("event_categories", []))
        if source_type in covered_events:
            covered_events[source_type].update(categories)
        else:
            covered_events[source_type] = categories

    missing = {}
    for source_type, required in CRITICAL_EVENTS.items():
        covered  = covered_events.get(source_type, set())
        not_covered = required - covered
        if not_covered:
            missing[source_type] = sorted(not_covered)

    compliant = len(missing) == 0
    return [_finding(
        cid, name,
        Status.PASS if compliant else Status.FAIL,
        Severity.MEDIUM,
        resource, region, account_id,
        "All critical RDS event categories are covered by subscriptions." if compliant
        else f"Missing event subscriptions for: {missing}.",
        "N/A" if compliant else
        f"Create event subscriptions to cover missing categories: {missing}.",
        {"missing_events": missing, "active_subscriptions": len(subs)},
    )]