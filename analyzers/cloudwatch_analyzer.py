from schemas.collector_output import CollectorOutput
from schemas.finding import Finding, Severity, Status, Framework
from utils.logger import get_logger

logger = get_logger(__name__)

SERVICE   = "cloudwatch"
FRAMEWORK = Framework.CIS_AWS_1_4


def analyze(output: CollectorOutput) -> list[Finding]:
    """
    [ANZ-06] Evalúa controles CIS/WAF sobre datos recopilados por cloudwatch_collector.
    """
    raw        = output.raw_data
    account_id = output.account_id
    region     = output.region
    findings: list[Finding] = []

    checks = [
        _check_cloudtrail_enabled,
        _check_cloudtrail_cloudwatch_integration,
        _check_cloudtrail_multiregion,
        _check_cloudtrail_log_validation,
        _check_cloudtrail_encryption,
        _check_cis_4x_controls,
        _check_log_groups_retention,
        _check_log_groups_encryption,
        _check_alarms_have_actions,
        _check_alarms_in_alarm_state,
        _check_alarms_insufficient_data,
    ]

    for check in checks:
        try:
            findings.extend(check(raw, account_id, region))
        except Exception as e:
            logger.error(f"CloudWatch: error en {check.__name__} — {e}")

    passed = sum(1 for f in findings if f.status == Status.PASS)
    failed = sum(1 for f in findings if f.status == Status.FAIL)
    logger.info(f"CloudWatch analyzer: {passed} PASS, {failed} FAIL, {len(findings)} total")

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


def _trail_arn(trail_name: str, region: str, account_id: str) -> str:
    return f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}"


def _alarm_arn(alarm_name: str, region: str, account_id: str) -> str:
    return f"arn:aws:cloudwatch:{region}:{account_id}:alarm:{alarm_name}"


def _log_group_arn(log_group_name: str, region: str, account_id: str) -> str:
    return f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}"


# ── Controles — CloudTrail ────────────────────────────────────────────────────

def _check_cloudtrail_enabled(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 3.1 — CloudTrail debe estar habilitado y activo."""
    cid      = "CIS-CT-3.1"
    name     = "CloudTrail enabled and logging"
    findings = []

    trails = raw.get("cloudtrail_trails", {})
    if not trails:
        return [_finding(
            cid, name, Status.FAIL, Severity.CRITICAL,
            f"arn:aws:cloudtrail:{region}:{account_id}:trail",
            region, account_id,
            "No CloudTrail trails found in this region.",
            "Create a CloudTrail trail with multi-region logging enabled.",
            {"trails_found": 0},
        )]

    for tname, trail in trails.items():
        is_logging = trail.get("status", {}).get("is_logging", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if is_logging else Status.FAIL,
            Severity.CRITICAL,
            _trail_arn(tname, region, account_id), region, account_id,
            f"Trail '{tname}' is actively logging." if is_logging
            else f"Trail '{tname}' exists but is not logging.",
            "N/A" if is_logging else
            f"Start logging on trail '{tname}': aws cloudtrail start-logging --name {tname}",
            {"trail": tname, "is_logging": is_logging},
        ))

    return findings


def _check_cloudtrail_cloudwatch_integration(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 3.4 — CloudTrail debe estar integrado con CloudWatch Logs."""
    cid      = "CIS-CT-3.4"
    name     = "CloudTrail integrated with CloudWatch Logs"
    findings = []

    for tname, trail in raw.get("cloudtrail_trails", {}).items():
        has_cw = trail.get("has_cloudwatch_logs", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if has_cw else Status.FAIL,
            Severity.HIGH,
            _trail_arn(tname, region, account_id), region, account_id,
            f"Trail '{tname}' is integrated with CloudWatch Logs group '{trail.get('log_group_name')}'." if has_cw
            else f"Trail '{tname}' is not sending logs to CloudWatch Logs.",
            "N/A" if has_cw else
            f"Configure CloudWatch Logs integration for trail '{tname}' to enable metric filters and alarms.",
            {"trail": tname, "log_group": trail.get("log_group_name")},
        ))

    return findings


def _check_cloudtrail_multiregion(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 3.1 — Al menos un trail debe ser multi-región."""
    cid      = "CIS-CT-3.1-MR"
    name     = "CloudTrail multi-region trail enabled"
    trails   = raw.get("cloudtrail_trails", {})

    has_multiregion = any(
        t.get("is_multi_region", False)
        for t in trails.values()
    )

    resource = f"arn:aws:cloudtrail:{region}:{account_id}:trail"
    return [_finding(
        cid, name,
        Status.PASS if has_multiregion else Status.FAIL,
        Severity.HIGH,
        resource, region, account_id,
        "At least one multi-region CloudTrail trail is configured." if has_multiregion
        else "No multi-region CloudTrail trail found.",
        "N/A" if has_multiregion else
        "Create or update a trail with --is-multi-region-trail to capture events across all regions.",
        {"trails_checked": list(trails.keys()), "has_multiregion": has_multiregion},
    )]


def _check_cloudtrail_log_validation(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 3.2 — Log file validation debe estar habilitado."""
    cid      = "CIS-CT-3.2"
    name     = "CloudTrail log file validation enabled"
    findings = []

    for tname, trail in raw.get("cloudtrail_trails", {}).items():
        validated = trail.get("has_log_validation", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if validated else Status.FAIL,
            Severity.MEDIUM,
            _trail_arn(tname, region, account_id), region, account_id,
            f"Trail '{tname}' has log file validation enabled." if validated
            else f"Trail '{tname}' does not have log file validation enabled.",
            "N/A" if validated else
            f"Enable log file validation on trail '{tname}': "
            f"aws cloudtrail update-trail --name {tname} --enable-log-file-validation",
            {"trail": tname, "log_validation": validated},
        ))

    return findings


def _check_cloudtrail_encryption(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 3.7 — CloudTrail logs deben estar encriptados con KMS."""
    cid      = "CIS-CT-3.7"
    name     = "CloudTrail logs encrypted with KMS"
    findings = []

    for tname, trail in raw.get("cloudtrail_trails", {}).items():
        kms_key = trail.get("kms_key_id")
        encrypted = bool(kms_key)
        findings.append(_finding(
            cid, name,
            Status.PASS if encrypted else Status.FAIL,
            Severity.MEDIUM,
            _trail_arn(tname, region, account_id), region, account_id,
            f"Trail '{tname}' is encrypted with KMS key '{kms_key}'." if encrypted
            else f"Trail '{tname}' is not encrypted with KMS.",
            "N/A" if encrypted else
            f"Enable KMS encryption on trail '{tname}': "
            f"aws cloudtrail update-trail --name {tname} --kms-key-id <your-kms-key-arn>",
            {"trail": tname, "kms_key_id": kms_key},
        ))

    return findings


# ── Controles — CIS 4.x ───────────────────────────────────────────────────────

def _check_cis_4x_controls(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 4.x — Verificar los 15 controles de monitoreo con metric filters y alarmas."""
    findings = []

    CIS_SEVERITY = {
        "CIS-4.1":  Severity.CRITICAL,
        "CIS-4.2":  Severity.HIGH,
        "CIS-4.3":  Severity.HIGH,
        "CIS-4.4":  Severity.CRITICAL,
        "CIS-4.5":  Severity.MEDIUM,
        "CIS-4.6":  Severity.HIGH,
        "CIS-4.7":  Severity.MEDIUM,
        "CIS-4.8":  Severity.MEDIUM,
        "CIS-4.9":  Severity.MEDIUM,
        "CIS-4.10": Severity.MEDIUM,
        "CIS-4.11": Severity.MEDIUM,
        "CIS-4.12": Severity.MEDIUM,
        "CIS-4.13": Severity.MEDIUM,
        "CIS-4.14": Severity.HIGH,
        "CIS-4.15": Severity.MEDIUM,
    }

    for control_id, control in raw.get("cis_controls", {}).items():
        compliant      = control.get("compliant", False)
        failure_reason = control.get("failure_reason")
        cw_control_id  = f"CIS-CW-{control_id}"
        control_name   = control.get("name", control_id)
        severity       = CIS_SEVERITY.get(control_id, Severity.MEDIUM)

        log_group = control.get("log_group")
        resource  = (
            _log_group_arn(log_group, region, account_id)
            if log_group
            else f"arn:aws:cloudwatch:{region}:{account_id}:alarm"
        )

        findings.append(_finding(
            cw_control_id, control_name,
            Status.PASS if compliant else Status.FAIL,
            severity,
            resource, region, account_id,
            f"Control '{control_id}' ({control_name}) is compliant." if compliant
            else f"Control '{control_id}' ({control_name}) failed: {failure_reason}.",
            "N/A" if compliant else
            f"Create a metric filter matching the CIS pattern for '{control_name}', "
            f"then create a CloudWatch alarm with an SNS action on that metric.",
            {
                "control_id":       control_id,
                "log_group":        log_group,
                "metric_filter":    control.get("metric_filter"),
                "alarm":            control.get("alarm", {}).get("alarm", {}).get("AlarmName") if control.get("alarm") else None,
                "alarm_has_action": control.get("alarm_has_action"),
                "failure_reason":   failure_reason,
            },
        ))

    return findings


# ── Controles — Log Groups ────────────────────────────────────────────────────

def _check_log_groups_retention(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Log groups deben tener retention policy configurada."""
    cid      = "WAF-CW-LG-01"
    name     = "CloudWatch Log Groups have retention policy"
    findings = []

    for lgname, lg in raw.get("log_groups", {}).items():
        has_retention = lg.get("has_retention", False)
        retention     = lg.get("retention_days")

        findings.append(_finding(
            cid, name,
            Status.PASS if has_retention else Status.FAIL,
            Severity.LOW,
            _log_group_arn(lgname, region, account_id), region, account_id,
            f"Log group '{lgname}' has retention set to {retention} days." if has_retention
            else f"Log group '{lgname}' has no retention policy — logs are kept indefinitely.",
            "N/A" if has_retention else
            f"Set a retention policy on log group '{lgname}': "
            f"aws logs put-retention-policy --log-group-name '{lgname}' --retention-in-days 90",
            {"log_group": lgname, "retention_days": retention},
        ))

    return findings


def _check_log_groups_encryption(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 3.7 / WAF — Log groups deben estar encriptados con KMS."""
    cid      = "WAF-CW-LG-02"
    name     = "CloudWatch Log Groups encrypted with KMS"
    findings = []

    for lgname, lg in raw.get("log_groups", {}).items():
        has_kms = lg.get("has_kms", False)
        kms_key = lg.get("kms_key_id")

        findings.append(_finding(
            cid, name,
            Status.PASS if has_kms else Status.FAIL,
            Severity.MEDIUM,
            _log_group_arn(lgname, region, account_id), region, account_id,
            f"Log group '{lgname}' is encrypted with KMS key '{kms_key}'." if has_kms
            else f"Log group '{lgname}' is not encrypted with KMS.",
            "N/A" if has_kms else
            f"Associate a KMS key with log group '{lgname}': "
            f"aws logs associate-kms-key --log-group-name '{lgname}' --kms-key-id <key-arn>",
            {"log_group": lgname, "kms_key_id": kms_key},
        ))

    return findings


# ── Controles — Alarmas ───────────────────────────────────────────────────────

def _check_alarms_have_actions(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Todas las alarmas deben tener al menos una acción SNS configurada."""
    cid      = "WAF-CW-ALM-01"
    name     = "CloudWatch alarms have notification actions"
    findings = []

    for aname, alarm in raw.get("alarms", {}).items():
        has_actions = alarm.get("has_actions", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if has_actions else Status.FAIL,
            Severity.MEDIUM,
            _alarm_arn(aname, region, account_id), region, account_id,
            f"Alarm '{aname}' has notification actions configured." if has_actions
            else f"Alarm '{aname}' has no notification actions — it will trigger silently.",
            "N/A" if has_actions else
            f"Add an SNS topic action to alarm '{aname}' so alerts are delivered.",
            {"alarm": aname, "actions": alarm.get("actions", [])},
        ))

    return findings


def _check_alarms_in_alarm_state(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Alarmas en estado ALARM indican un problema activo que debe investigarse."""
    cid      = "WAF-CW-ALM-02"
    name     = "CloudWatch alarms not in ALARM state"
    findings = []

    alarms_in_alarm = raw.get("summary", {}).get("alarms_in_alarm_state", [])

    for aname in alarms_in_alarm:
        alarm = raw.get("alarms", {}).get(aname, {})
        findings.append(_finding(
            cid, name, Status.FAIL, Severity.HIGH,
            _alarm_arn(aname, region, account_id), region, account_id,
            f"Alarm '{aname}' is currently in ALARM state for metric '{alarm.get('metric_name')}'.",
            f"Investigate the condition triggering alarm '{aname}' and remediate or acknowledge.",
            {"alarm": aname, "metric": alarm.get("metric_name"), "namespace": alarm.get("namespace")},
        ))

    if not alarms_in_alarm:
        findings.append(_finding(
            cid, name, Status.PASS, Severity.HIGH,
            f"arn:aws:cloudwatch:{region}:{account_id}:alarm",
            region, account_id,
            "No CloudWatch alarms are currently in ALARM state.",
            "N/A",
            {"alarms_in_alarm": []},
        ))

    return findings


def _check_alarms_insufficient_data(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Alarmas en INSUFFICIENT_DATA pueden indicar métricas sin datos o mal configuradas."""
    cid      = "WAF-CW-ALM-03"
    name     = "CloudWatch alarms not in INSUFFICIENT_DATA state"
    findings = []

    alarms_insufficient = raw.get("summary", {}).get("alarms_insufficient_data", [])

    for aname in alarms_insufficient:
        alarm = raw.get("alarms", {}).get(aname, {})
        findings.append(_finding(
            cid, name, Status.FAIL, Severity.LOW,
            _alarm_arn(aname, region, account_id), region, account_id,
            f"Alarm '{aname}' is in INSUFFICIENT_DATA state — metric '{alarm.get('metric_name')}' has no data.",
            f"Verify alarm '{aname}' is correctly configured and the associated metric filter is receiving data.",
            {"alarm": aname, "metric": alarm.get("metric_name"), "namespace": alarm.get("namespace")},
        ))

    if not alarms_insufficient:
        findings.append(_finding(
            cid, name, Status.PASS, Severity.LOW,
            f"arn:aws:cloudwatch:{region}:{account_id}:alarm",
            region, account_id,
            "No CloudWatch alarms are in INSUFFICIENT_DATA state.",
            "N/A",
            {"alarms_insufficient": []},
        ))

    return findings