from schemas.collector_output import CollectorOutput
from schemas.finding import Finding, Severity, Status, Framework
from utils.logger import get_logger

logger = get_logger(__name__)

SERVICE   = "guardduty"
FRAMEWORK = Framework.CIS_AWS_1_4

PROTECTION_PLANS = {
    "S3_DATA_EVENTS":        ("S3 Protection",         Severity.HIGH),
    "EKS_AUDIT_LOGS":        ("EKS Protection",        Severity.MEDIUM),
    "EBS_MALWARE_PROTECTION":("Malware Protection",    Severity.HIGH),
    "RDS_LOGIN_EVENTS":      ("RDS Protection",        Severity.MEDIUM),
    "LAMBDA_NETWORK_LOGS":   ("Lambda Protection",     Severity.MEDIUM),
    "RUNTIME_MONITORING":    ("Runtime Monitoring",    Severity.HIGH),
}

FINDING_SEVERITY_MAP = {
    (9.0, 10.0): Severity.CRITICAL,
    (7.0,  8.9): Severity.HIGH,
    (4.0,  6.9): Severity.MEDIUM,
}


def analyze(output: CollectorOutput) -> list[Finding]:
    """
    [ANZ-05] Evalúa controles CIS/WAF sobre datos recopilados por guardduty_collector.
    """
    raw        = output.raw_data
    account_id = output.account_id
    region     = output.region
    findings: list[Finding] = []

    checks = [
        _check_guardduty_enabled,
        _check_finding_export_configured,
        _check_organization_centralized,
        _check_protection_plans,
        _check_active_findings_critical,
        _check_active_findings_high,
        _check_threat_intel_sets,
        _check_finding_frequency,
    ]

    for check in checks:
        try:
            findings.extend(check(raw, account_id, region))
        except Exception as e:
            logger.error(f"GuardDuty: error en {check.__name__} — {e}")

    passed = sum(1 for f in findings if f.status == Status.PASS)
    failed = sum(1 for f in findings if f.status == Status.FAIL)
    logger.info(f"GuardDuty analyzer: {passed} PASS, {failed} FAIL, {len(findings)} total")

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


def _detector_arn(detector_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:guardduty:{region}:{account_id}:detector/{detector_id}"


def _gd_severity(score: float) -> Severity:
    for (low, high), sev in FINDING_SEVERITY_MAP.items():
        if low <= score <= high:
            return sev
    return Severity.LOW


# ── Controles ─────────────────────────────────────────────────────────────────

def _check_guardduty_enabled(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 3.1 — GuardDuty debe estar habilitado en la región."""
    cid      = "CIS-GD-3.1"
    name     = "GuardDuty enabled in region"
    resource = f"arn:aws:guardduty:{region}:{account_id}:detector"
    enabled  = raw.get("enabled", False)

    if not enabled:
        return [_finding(
            cid, name, Status.FAIL, Severity.CRITICAL,
            resource, region, account_id,
            f"GuardDuty is not enabled in region '{region}'.",
            f"Enable GuardDuty in region '{region}' via the console or CLI: "
            f"aws guardduty create-detector --enable --region {region}",
            {"region": region, "enabled": False},
        )]

    findings = []
    for did, det in raw.get("detectors", {}).items():
        status_val = det.get("status", "DISABLED")
        is_active  = status_val == "ENABLED"
        findings.append(_finding(
            cid, name,
            Status.PASS if is_active else Status.FAIL,
            Severity.CRITICAL,
            _detector_arn(did, region, account_id), region, account_id,
            f"GuardDuty detector '{did}' is active." if is_active
            else f"GuardDuty detector '{did}' exists but is disabled.",
            "N/A" if is_active else
            f"Enable GuardDuty detector '{did}': aws guardduty update-detector --detector-id {did} --enable",
            {"detector_id": did, "status": status_val},
        ))

    return findings


def _check_finding_export_configured(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 3.1 / WAF — Findings deben exportarse a S3 o EventBridge."""
    cid      = "WAF-GD-EXP-01"
    name     = "GuardDuty findings export configured"
    findings = []

    for did, det in raw.get("detectors", {}).items():
        exp_config   = det.get("export_config", {})
        destinations = exp_config.get("Destinations", [])
        has_s3       = bool(exp_config.get("S3Destination")) or any(
            d.get("DestinationType") == "S3" and d.get("Status") == "PUBLISHING_ACTIVE"
            for d in destinations
        )
        configured   = len(destinations) > 0

        findings.append(_finding(
            cid, name,
            Status.PASS if configured else Status.FAIL,
            Severity.MEDIUM,
            _detector_arn(did, region, account_id), region, account_id,
            f"Detector '{did}' exports findings to {'S3' if has_s3 else 'a configured destination'}." if configured
            else f"Detector '{did}' has no findings export configured.",
            "N/A" if configured else
            f"Configure findings export for detector '{did}' to S3 or EventBridge for long-term retention.",
            {"detector_id": did, "has_s3_export": has_s3, "destinations": destinations},
        ))

    return findings


def _check_organization_centralized(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — GuardDuty debe estar centralizado en Organizations si aplica."""
    cid      = "WAF-GD-ORG-01"
    name     = "GuardDuty centralized via AWS Organizations"
    findings = []

    for did, det in raw.get("detectors", {}).items():
        master         = det.get("master")
        in_org         = master is not None
        master_account = master.get("AccountId") if master else None

        findings.append(_finding(
            cid, name,
            Status.PASS if in_org else Status.FAIL,
            Severity.MEDIUM,
            _detector_arn(did, region, account_id), region, account_id,
            f"Detector '{did}' is managed centrally by master account '{master_account}'." if in_org
            else f"Detector '{did}' is not part of an AWS Organizations centralized GuardDuty setup.",
            "N/A" if in_org else
            "Configure GuardDuty as a delegated administrator in AWS Organizations for centralized management.",
            {"detector_id": did, "master_account": master_account, "in_organization": in_org},
        ))

    return findings


def _check_protection_plans(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Todos los protection plans deben estar habilitados."""
    cid      = "WAF-GD-PPL-01"
    name     = "GuardDuty protection plan enabled"
    findings = []

    for did, det in raw.get("detectors", {}).items():
        features = det.get("features", {})

        for plan_key, (plan_name, severity) in PROTECTION_PLANS.items():
            status_val = features.get(plan_key, "DISABLED")
            enabled    = status_val == "ENABLED"
            resource   = f"{_detector_arn(did, region, account_id)}/feature/{plan_key}"

            findings.append(_finding(
                f"{cid}-{plan_key[:3]}",
                f"{name}: {plan_name}",
                Status.PASS if enabled else Status.FAIL,
                severity,
                resource, region, account_id,
                f"'{plan_name}' is enabled on detector '{did}'." if enabled
                else f"'{plan_name}' is disabled on detector '{did}'.",
                "N/A" if enabled else
                f"Enable {plan_name} on detector '{did}' to extend threat detection coverage.",
                {"detector_id": did, "plan": plan_key, "status": status_val},
            ))

    return findings


def _check_active_findings_critical(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Findings activos de severidad CRITICAL deben ser remediados."""
    cid      = "WAF-GD-FND-01"
    name     = "No active GuardDuty findings with CRITICAL severity"
    findings = []

    for did, det in raw.get("detectors", {}).items():
        critical_findings = [
            f for f in det.get("findings", [])
            if float(f.get("severity", 0)) >= 9.0
        ]

        if not critical_findings:
            findings.append(_finding(
                cid, name, Status.PASS, Severity.CRITICAL,
                _detector_arn(did, region, account_id), region, account_id,
                f"Detector '{did}' has no active CRITICAL findings.",
                "N/A",
                {"detector_id": did, "critical_count": 0},
            ))
            continue

        for gd_finding in critical_findings:
            resource = (
                gd_finding.get("resource", {}).get("InstanceDetails", {}).get("InstanceId") or
                gd_finding.get("resource", {}).get("S3BucketDetails", [{}])[0].get("Arn") or
                _detector_arn(did, region, account_id)
            )
            findings.append(_finding(
                cid, name, Status.FAIL, Severity.CRITICAL,
                resource, region, account_id,
                f"[CRITICAL] {gd_finding.get('title')} — "
                f"seen {gd_finding.get('count', 1)} time(s). "
                f"Type: {gd_finding.get('type')}.",
                f"Investigate and remediate GuardDuty finding '{gd_finding.get('id')}' immediately.",
                {
                    "finding_id":   gd_finding.get("id"),
                    "type":         gd_finding.get("type"),
                    "severity":     gd_finding.get("severity"),
                    "count":        gd_finding.get("count"),
                    "created_at":   gd_finding.get("created_at"),
                    "description":  gd_finding.get("description"),
                },
            ))

    return findings


def _check_active_findings_high(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Findings activos de severidad HIGH deben ser investigados."""
    cid      = "WAF-GD-FND-02"
    name     = "No active GuardDuty findings with HIGH severity"
    findings = []

    for did, det in raw.get("detectors", {}).items():
        high_findings = [
            f for f in det.get("findings", [])
            if 7.0 <= float(f.get("severity", 0)) <= 8.9
        ]

        if not high_findings:
            findings.append(_finding(
                cid, name, Status.PASS, Severity.HIGH,
                _detector_arn(did, region, account_id), region, account_id,
                f"Detector '{did}' has no active HIGH severity findings.",
                "N/A",
                {"detector_id": did, "high_count": 0},
            ))
            continue

        for gd_finding in high_findings:
            resource = (
                gd_finding.get("resource", {}).get("InstanceDetails", {}).get("InstanceId") or
                gd_finding.get("resource", {}).get("S3BucketDetails", [{}])[0].get("Arn") or
                _detector_arn(did, region, account_id)
            )
            findings.append(_finding(
                cid, name, Status.FAIL, Severity.HIGH,
                resource, region, account_id,
                f"[HIGH] {gd_finding.get('title')} — "
                f"seen {gd_finding.get('count', 1)} time(s). "
                f"Type: {gd_finding.get('type')}.",
                f"Investigate GuardDuty finding '{gd_finding.get('id')}' and apply remediation.",
                {
                    "finding_id":  gd_finding.get("id"),
                    "type":        gd_finding.get("type"),
                    "severity":    gd_finding.get("severity"),
                    "count":       gd_finding.get("count"),
                    "created_at":  gd_finding.get("created_at"),
                    "description": gd_finding.get("description"),
                },
            ))

    return findings


def _check_threat_intel_sets(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Al menos un threat intel set activo mejora la detección."""
    cid      = "WAF-GD-TIS-01"
    name     = "GuardDuty threat intel sets configured"
    findings = []

    for did, det in raw.get("detectors", {}).items():
        ti_sets = det.get("threat_intel_sets", [])
        active  = [t for t in ti_sets if t.get("status") == "ACTIVE"]
        has_active = len(active) > 0

        findings.append(_finding(
            cid, name,
            Status.PASS if has_active else Status.FAIL,
            Severity.LOW,
            _detector_arn(did, region, account_id), region, account_id,
            f"Detector '{did}' has {len(active)} active threat intelligence set(s)." if has_active
            else f"Detector '{did}' has no active threat intelligence sets.",
            "N/A" if has_active else
            "Configure at least one threat intelligence set in GuardDuty to enhance detection with known malicious IPs.",
            {"detector_id": did, "active_ti_sets": [t.get("name") for t in active]},
        ))

    return findings


def _check_finding_frequency(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — La frecuencia de publicación de findings debe ser FIFTEEN_MINUTES."""
    cid      = "WAF-GD-FRQ-01"
    name     = "GuardDuty finding publish frequency is optimal"
    findings = []
    OPTIMAL  = "FIFTEEN_MINUTES"

    for did, det in raw.get("detectors", {}).items():
        frequency = det.get("finding_frequency", "SIX_HOURS")
        optimal   = frequency == OPTIMAL

        findings.append(_finding(
            cid, name,
            Status.PASS if optimal else Status.FAIL,
            Severity.LOW,
            _detector_arn(did, region, account_id), region, account_id,
            f"Detector '{did}' publishes findings every {frequency}." if optimal
            else f"Detector '{did}' publishes findings every {frequency} — consider reducing to {OPTIMAL}.",
            "N/A" if optimal else
            f"Set finding publish frequency to {OPTIMAL} on detector '{did}' for faster alerting.",
            {"detector_id": did, "frequency": frequency, "recommended": OPTIMAL},
        ))

    return findings