from schemas.collector_output import CollectorOutput
from schemas.finding import Finding, Severity, Status, Framework
from utils.logger import get_logger

logger = get_logger(__name__)

SERVICE   = "vpc"
FRAMEWORK = Framework.CIS_AWS_1_4


def analyze(output: CollectorOutput) -> list[Finding]:
    """
    [ANZ-07] Evalúa controles CIS/WAF sobre datos recopilados por vpc_collector.
    """
    raw        = output.raw_data
    account_id = output.account_id
    region     = output.region
    findings: list[Finding] = []

    checks = [
        _check_flow_logs_enabled,
        _check_flow_logs_all_traffic,
        _check_default_vpc_no_resources,
        _check_vpc_cidr_overlaps,
        _check_peering_cross_account,
        _check_peering_cross_region,
        _check_endpoints_open_policy,
        _check_missing_critical_endpoints,
        _check_dhcp_custom_dns,
        _check_vpn_tunnels_up,
        _check_privatelink_acceptance,
        _check_resolver_rules,
        _check_flow_logs_destination,
    ]

    for check in checks:
        try:
            findings.extend(check(raw, account_id, region))
        except Exception as e:
            logger.error(f"VPC: error en {check.__name__} — {e}")

    passed = sum(1 for f in findings if f.status == Status.PASS)
    failed = sum(1 for f in findings if f.status == Status.FAIL)
    logger.info(f"VPC analyzer: {passed} PASS, {failed} FAIL, {len(findings)} total")

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


def _vpc_arn(vpc_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}"


def _endpoint_arn(endpoint_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:vpc-endpoint/{endpoint_id}"


def _vpn_arn(vpn_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:vpn-connection/{vpn_id}"


def _peering_arn(peer_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:vpc-peering-connection/{peer_id}"


# ── Controles ─────────────────────────────────────────────────────────────────

def _check_flow_logs_enabled(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 3.9 — Flow logs deben estar habilitados en todas las VPCs."""
    cid      = "CIS-VPC-3.9"
    name     = "VPC Flow Logs enabled"
    findings = []

    for vid, vpc in raw.get("vpcs", {}).items():
        has_logs = vpc.get("has_flow_logs", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if has_logs else Status.FAIL,
            Severity.MEDIUM,
            _vpc_arn(vid, region, account_id), region, account_id,
            f"VPC '{vid}' has flow logs enabled." if has_logs
            else f"VPC '{vid}' does not have flow logs enabled.",
            "N/A" if has_logs else
            f"Enable VPC Flow Logs on '{vid}': "
            f"aws ec2 create-flow-logs --resource-type VPC --resource-ids {vid} "
            f"--traffic-type ALL --log-destination-type cloud-watch-logs",
            {"vpc_id": vid, "is_default": vpc.get("is_default")},
        ))

    return findings


def _check_flow_logs_all_traffic(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Flow logs deben capturar TODO el tráfico (ACCEPT + REJECT)."""
    cid      = "WAF-VPC-FL-01"
    name     = "VPC Flow Logs capture ALL traffic"
    findings = []

    for vid, vpc in raw.get("vpcs", {}).items():
        if not vpc.get("has_flow_logs", False):
            continue

        all_traffic = vpc.get("flow_logs_all_traffic", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if all_traffic else Status.FAIL,
            Severity.MEDIUM,
            _vpc_arn(vid, region, account_id), region, account_id,
            f"VPC '{vid}' flow logs capture ALL traffic." if all_traffic
            else f"VPC '{vid}' flow logs do not capture ALL traffic — REJECT events may be missed.",
            "N/A" if all_traffic else
            f"Update flow logs for VPC '{vid}' to capture ALL traffic instead of ACCEPT or REJECT only.",
            {"vpc_id": vid, "all_traffic": all_traffic},
        ))

    return findings


def _check_default_vpc_no_resources(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 5.3 — La VPC default no debe usarse para workloads productivos."""
    cid      = "CIS-VPC-5.3"
    name     = "Default VPC not in use for workloads"
    findings = []

    for vid, vpc in raw.get("vpcs", {}).items():
        if not vpc.get("is_default", False):
            continue

        findings.append(_finding(
            cid, name,
            Status.FAIL,
            Severity.MEDIUM,
            _vpc_arn(vid, region, account_id), region, account_id,
            f"Default VPC '{vid}' exists in region '{region}'. "
            f"Verify no production workloads are running in it.",
            "Review workloads in the default VPC. Migrate them to a custom VPC and consider "
            "deleting the default VPC to reduce attack surface.",
            {"vpc_id": vid, "cidr": vpc.get("cidr")},
        ))

    if not any(v.get("is_default") for v in raw.get("vpcs", {}).values()):
        findings.append(_finding(
            cid, name, Status.PASS, Severity.MEDIUM,
            f"arn:aws:ec2:{region}:{account_id}:vpc/default",
            region, account_id,
            "No default VPC found in this region.",
            "N/A",
            {"default_vpc_exists": False},
        ))

    return findings


def _check_vpc_cidr_overlaps(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — CIDRs de VPCs no deben solaparse entre sí."""
    cid      = "WAF-VPC-CID-01"
    name     = "VPC CIDR blocks do not overlap"
    overlaps = raw.get("overlapping_cidrs", [])

    if not overlaps:
        return [_finding(
            cid, name, Status.PASS, Severity.MEDIUM,
            f"arn:aws:ec2:{region}:{account_id}:vpc",
            region, account_id,
            "No overlapping CIDR blocks found between VPCs.",
            "N/A",
            {"overlapping_pairs": []},
        )]

    findings = []
    for va, vb in overlaps:
        cidr_a = raw.get("vpcs", {}).get(va, {}).get("cidr", "unknown")
        cidr_b = raw.get("vpcs", {}).get(vb, {}).get("cidr", "unknown")
        findings.append(_finding(
            cid, name, Status.FAIL, Severity.MEDIUM,
            _vpc_arn(va, region, account_id), region, account_id,
            f"VPC '{va}' ({cidr_a}) has overlapping CIDR with VPC '{vb}' ({cidr_b}).",
            f"Resolve CIDR overlap between '{va}' and '{vb}' before establishing VPC peering.",
            {"vpc_a": va, "cidr_a": cidr_a, "vpc_b": vb, "cidr_b": cidr_b},
        ))

    return findings


def _check_peering_cross_account(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Peerings cross-account deben revisarse y justificarse."""
    cid      = "WAF-VPC-PER-01"
    name     = "VPC peering cross-account connections reviewed"
    findings = []

    for pid, peer in raw.get("peering_connections", {}).items():
        if peer.get("status") != "active":
            continue

        is_cross = peer.get("is_cross_account", False)
        if not is_cross:
            continue

        findings.append(_finding(
            cid, name, Status.FAIL, Severity.HIGH,
            _peering_arn(pid, region, account_id), region, account_id,
            f"Peering '{pid}' connects to account '{peer.get('accepter_account')}' "
            f"(CIDR: {peer.get('accepter_cidr')}) — cross-account access.",
            f"Review peering '{pid}'. Ensure it is authorized and follows least-privilege routing.",
            {
                "peering_id":       pid,
                "requester_account": peer.get("requester_account"),
                "accepter_account":  peer.get("accepter_account"),
                "accepter_cidr":     peer.get("accepter_cidr"),
            },
        ))

    if not any(
        p.get("is_cross_account") and p.get("status") == "active"
        for p in raw.get("peering_connections", {}).values()
    ):
        findings.append(_finding(
            cid, name, Status.PASS, Severity.HIGH,
            f"arn:aws:ec2:{region}:{account_id}:vpc-peering-connection",
            region, account_id,
            "No active cross-account VPC peering connections found.",
            "N/A",
            {"cross_account_peerings": 0},
        ))

    return findings


def _check_peering_cross_region(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Peerings cross-region deben revisarse."""
    cid      = "WAF-VPC-PER-02"
    name     = "VPC peering cross-region connections reviewed"
    findings = []

    for pid, peer in raw.get("peering_connections", {}).items():
        if peer.get("status") != "active":
            continue

        is_cross_region = peer.get("is_cross_region", False)
        if not is_cross_region:
            continue

        findings.append(_finding(
            cid, name, Status.FAIL, Severity.MEDIUM,
            _peering_arn(pid, region, account_id), region, account_id,
            f"Peering '{pid}' is a cross-region connection. Verify this is intentional.",
            f"Review cross-region peering '{pid}'. Ensure traffic routing is scoped to necessary CIDRs only.",
            {
                "peering_id":      pid,
                "requester_vpc":   peer.get("requester_vpc"),
                "accepter_vpc":    peer.get("accepter_vpc"),
                "is_cross_region": True,
            },
        ))

    if not any(
        p.get("is_cross_region") and p.get("status") == "active"
        for p in raw.get("peering_connections", {}).values()
    ):
        findings.append(_finding(
            cid, name, Status.PASS, Severity.MEDIUM,
            f"arn:aws:ec2:{region}:{account_id}:vpc-peering-connection",
            region, account_id,
            "No active cross-region VPC peering connections found.",
            "N/A",
            {"cross_region_peerings": 0},
        ))

    return findings


def _check_endpoints_open_policy(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Políticas de VPC Endpoints no deben ser completamente abiertas."""
    cid      = "WAF-VPC-EPO-01"
    name     = "VPC Endpoint policies are not open"
    findings = []

    for epid, ep in raw.get("vpc_endpoints", {}).items():
        is_open = ep.get("is_open_policy", False)
        svc     = ep.get("service_name", epid)

        findings.append(_finding(
            cid, name,
            Status.FAIL if is_open else Status.PASS,
            Severity.HIGH,
            _endpoint_arn(epid, region, account_id), region, account_id,
            f"Endpoint '{epid}' ({svc}) has an open policy (Principal: *)." if is_open
            else f"Endpoint '{epid}' ({svc}) has a restricted policy.",
            "N/A" if not is_open else
            f"Restrict the resource policy on endpoint '{epid}' to specific principals and actions.",
            {"endpoint_id": epid, "service": svc, "is_open_policy": is_open},
        ))

    return findings


def _check_missing_critical_endpoints(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Servicios críticos deben tener VPC Endpoints para evitar tráfico público."""
    cid      = "WAF-VPC-EPM-01"
    name     = "Critical services have VPC Endpoints"
    resource = f"arn:aws:ec2:{region}:{account_id}:vpc-endpoint"
    missing  = raw.get("summary", {}).get("missing_critical_endpoints", [])

    if not missing:
        return [_finding(
            cid, name, Status.PASS, Severity.MEDIUM,
            resource, region, account_id,
            "All critical AWS services have VPC Endpoints configured.",
            "N/A",
            {"missing_endpoints": []},
        )]

    return [_finding(
        cid, name, Status.FAIL, Severity.MEDIUM,
        resource, region, account_id,
        f"Missing VPC Endpoints for: {missing}. Traffic to these services routes through the internet.",
        f"Create Interface or Gateway endpoints for: {', '.join(missing)}.",
        {"missing_endpoints": missing},
    )]


def _check_dhcp_custom_dns(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — DHCP option sets con DNS custom deben revisarse para evitar DNS hijacking."""
    cid      = "WAF-VPC-DNS-01"
    name     = "DHCP option sets use trusted DNS servers"
    findings = []

    for did, dhcp in raw.get("dhcp_option_sets", {}).items():
        uses_custom = dhcp.get("uses_custom_dns", False)
        dns_servers = dhcp.get("dns_servers", [])
        resource    = f"arn:aws:ec2:{region}:{account_id}:dhcp-options/{did}"

        if not uses_custom:
            findings.append(_finding(
                cid, name, Status.PASS, Severity.LOW,
                resource, region, account_id,
                f"DHCP option set '{did}' uses AmazonProvidedDNS.",
                "N/A",
                {"dhcp_id": did, "dns_servers": dns_servers},
            ))
            continue

        findings.append(_finding(
            cid, name, Status.FAIL, Severity.MEDIUM,
            resource, region, account_id,
            f"DHCP option set '{did}' uses custom DNS servers: {dns_servers}. "
            f"Verify these are trusted and authorized.",
            f"Review custom DNS servers in DHCP option set '{did}'. "
            f"If not required, revert to AmazonProvidedDNS.",
            {"dhcp_id": did, "dns_servers": dns_servers},
        ))

    return findings


def _check_vpn_tunnels_up(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Todos los túneles VPN deben estar en estado UP."""
    cid      = "WAF-VPC-VPN-01"
    name     = "VPN connection tunnels are UP"
    findings = []

    for vpn_id, vpn in raw.get("vpn_connections", {}).items():
        if vpn.get("state") not in ("available", "pending"):
            continue

        tunnels_down = vpn.get("tunnels_down", 0)
        tunnels_up   = vpn.get("tunnels_up", 0)
        has_down     = tunnels_down > 0

        findings.append(_finding(
            cid, name,
            Status.FAIL if has_down else Status.PASS,
            Severity.HIGH,
            _vpn_arn(vpn_id, region, account_id), region, account_id,
            f"VPN '{vpn_id}' has {tunnels_down} tunnel(s) DOWN and {tunnels_up} UP." if has_down
            else f"VPN '{vpn_id}' has all tunnels UP.",
            "N/A" if not has_down else
            f"Investigate and restore VPN tunnels for connection '{vpn_id}'. "
            f"Check BGP configuration and customer gateway connectivity.",
            {
                "vpn_id":       vpn_id,
                "tunnels_up":   tunnels_up,
                "tunnels_down": tunnels_down,
                "tunnels":      vpn.get("tunnels", []),
            },
        ))

    return findings


def _check_privatelink_acceptance(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Servicios PrivateLink deben requerir aceptación manual de conexiones."""
    cid      = "WAF-VPC-PL-01"
    name     = "PrivateLink services require acceptance"
    findings = []

    for sname, svc in raw.get("privatelink_services", {}).items():
        acceptance_required = svc.get("acceptance_required", False)
        resource = f"arn:aws:ec2:{region}:{account_id}:vpc-endpoint-service/{sname}"

        findings.append(_finding(
            cid, name,
            Status.PASS if acceptance_required else Status.FAIL,
            Severity.MEDIUM,
            resource, region, account_id,
            f"PrivateLink service '{sname}' requires manual acceptance of connections." if acceptance_required
            else f"PrivateLink service '{sname}' auto-accepts connections — any allowed account can connect.",
            "N/A" if acceptance_required else
            f"Enable acceptance required on PrivateLink service '{sname}' to control who can connect.",
            {"service": sname, "acceptance_required": acceptance_required},
        ))

    return findings


def _check_resolver_rules(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Reglas de Route 53 Resolver compartidas deben revisarse."""
    cid      = "WAF-VPC-R53-01"
    name     = "Route 53 Resolver rules share status reviewed"
    findings = []

    resolver_rules = raw.get("resolver", {}).get("rules", {})

    for rid, rule in resolver_rules.items():
        share_status = rule.get("share_status", "NOT_SHARED")
        resource     = f"arn:aws:route53resolver:{region}:{account_id}:resolver-rule/{rid}"

        if share_status == "SHARED_WITH_ME":
            findings.append(_finding(
                cid, name, Status.FAIL, Severity.MEDIUM,
                resource, region, account_id,
                f"Resolver rule '{rid}' ({rule.get('domain_name')}) is shared from another account. "
                f"Verify this is authorized.",
                f"Review resolver rule '{rid}' shared from external account. "
                f"If unauthorized, disassociate it from your VPC.",
                {"rule_id": rid, "domain": rule.get("domain_name"), "share_status": share_status},
            ))
        elif share_status == "SHARED_BY_ME":
            findings.append(_finding(
                cid, name, Status.FAIL, Severity.LOW,
                resource, region, account_id,
                f"Resolver rule '{rid}' ({rule.get('domain_name')}) is shared with other accounts.",
                f"Review which accounts have access to resolver rule '{rid}' and revoke if unnecessary.",
                {"rule_id": rid, "domain": rule.get("domain_name"), "share_status": share_status},
            ))
        else:
            findings.append(_finding(
                cid, name, Status.PASS, Severity.LOW,
                resource, region, account_id,
                f"Resolver rule '{rid}' ({rule.get('domain_name')}) is not shared.",
                "N/A",
                {"rule_id": rid, "share_status": share_status},
            ))

    return findings


def _check_flow_logs_destination(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Flow logs deben enviarse a CloudWatch Logs o S3 con retención configurada."""
    cid      = "WAF-VPC-FL-02"
    name     = "VPC Flow Logs destination is configured correctly"
    findings = []

    for flid, fl in raw.get("flow_logs", {}).items():
        destination  = fl.get("destination", "")
        status       = fl.get("status", "")
        resource_id  = fl.get("resource_id", flid)
        resource     = f"arn:aws:ec2:{region}:{account_id}:vpc-flow-log/{flid}"

        if status != "ACTIVE":
            findings.append(_finding(
                cid, name, Status.FAIL, Severity.MEDIUM,
                resource, region, account_id,
                f"Flow log '{flid}' for resource '{resource_id}' is not ACTIVE (status: {status}).",
                f"Investigate and restore flow log '{flid}'. "
                f"Check IAM permissions and destination configuration.",
                {"flow_log_id": flid, "resource_id": resource_id, "status": status},
            ))
            continue

        valid_destination = destination in ("cloud-watch-logs", "s3", "kinesis-data-firehose")
        findings.append(_finding(
            cid, name,
            Status.PASS if valid_destination else Status.FAIL,
            Severity.LOW,
            resource, region, account_id,
            f"Flow log '{flid}' is active and sending to '{destination}'." if valid_destination
            else f"Flow log '{flid}' has an unrecognized destination type: '{destination}'.",
            "N/A" if valid_destination else
            f"Reconfigure flow log '{flid}' to send to CloudWatch Logs, S3, or Kinesis Data Firehose.",
            {"flow_log_id": flid, "destination": destination, "resource_id": resource_id},
        ))

    return findings