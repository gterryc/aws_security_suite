from schemas.collector_output import CollectorOutput
from schemas.finding import Finding, Severity, Status, Framework
from utils.logger import get_logger

logger = get_logger(__name__)

SERVICE   = "ec2"
FRAMEWORK = Framework.CIS_AWS_1_4


def analyze(output: CollectorOutput) -> list[Finding]:
    """
    [ANZ-03] Evalúa controles CIS/WAF sobre datos recopilados por ec2_collector.
    """
    raw        = output.raw_data
    account_id = output.account_id
    region     = output.region
    findings: list[Finding] = []

    checks = [
        _check_ebs_encryption_by_default,
        _check_ebs_volumes_encrypted,
        _check_snapshots_not_public,
        _check_amis_not_public,
        _check_imdsv2_enforced,
        _check_security_groups_no_open_ingress,
        _check_default_sg_no_rules,
        _check_vpc_flow_logs,
        _check_instances_monitoring,
        _check_instances_no_public_ip,
        _check_instances_ssm_managed,
        _check_vpc_endpoints_critical,
        _check_subnets_no_auto_assign_ip,
        _check_nacl_no_open_ingress,
        _check_unused_eips,
        _check_instances_exposure_type,
    ]

    for check in checks:
        try:
            findings.extend(check(raw, account_id, region))
        except Exception as e:
            logger.error(f"EC2: error en {check.__name__} — {e}")

    passed = sum(1 for f in findings if f.status == Status.PASS)
    failed = sum(1 for f in findings if f.status == Status.FAIL)
    logger.info(f"EC2 analyzer: {passed} PASS, {failed} FAIL, {len(findings)} total")

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


def _instance_arn(instance_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"


def _sg_arn(sg_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}"


def _volume_arn(vol_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:volume/{vol_id}"


def _snapshot_arn(snap_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:snapshot/{snap_id}"


def _subnet_arn(subnet_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:subnet/{subnet_id}"


def _vpc_arn(vpc_id: str, region: str, account_id: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}"


# ── Controles ─────────────────────────────────────────────────────────────────

def _check_ebs_encryption_by_default(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.2.1 — EBS encryption by default debe estar habilitado."""
    cid      = "CIS-EC2-2.2.1"
    name     = "EBS encryption by default enabled"
    resource = f"arn:aws:ec2:{region}:{account_id}:ebs-encryption-by-default"
    enabled  = raw.get("ebs_encryption_by_default", False)

    return [_finding(
        cid, name,
        Status.PASS if enabled else Status.FAIL,
        Severity.HIGH,
        resource, region, account_id,
        "EBS encryption by default is enabled." if enabled
        else "EBS encryption by default is not enabled.",
        "N/A" if enabled else
        "Enable EBS encryption by default in EC2 settings for this region.",
        {"ebs_encryption_by_default": enabled},
    )]


def _check_ebs_volumes_encrypted(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.2.1 — Todos los volúmenes EBS deben estar encriptados."""
    cid      = "CIS-EC2-2.2.1-VOL"
    name     = "EBS volumes encrypted at rest"
    findings = []

    for vid, vol in raw.get("ebs_volumes", {}).items():
        encrypted = vol.get("encrypted", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if encrypted else Status.FAIL,
            Severity.HIGH,
            _volume_arn(vid, region, account_id), region, account_id,
            f"Volume '{vid}' is encrypted." if encrypted
            else f"Volume '{vid}' is not encrypted.",
            "N/A" if encrypted else
            f"Encrypt volume '{vid}' by creating an encrypted snapshot and restoring from it.",
            {"volume_id": vid, "encrypted": encrypted, "kms_key_id": vol.get("kms_key_id")},
        ))

    return findings


def _check_snapshots_not_public(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 2.2.2 — Ningún snapshot EBS debe ser público."""
    cid      = "CIS-EC2-2.2.2"
    name     = "EBS snapshots not publicly restorable"
    findings = []

    for sid, snap in raw.get("ebs_snapshots", {}).items():
        is_public = snap.get("is_public", False)
        findings.append(_finding(
            cid, name,
            Status.FAIL if is_public else Status.PASS,
            Severity.CRITICAL,
            _snapshot_arn(sid, region, account_id), region, account_id,
            f"Snapshot '{sid}' is publicly restorable." if is_public
            else f"Snapshot '{sid}' is not public.",
            "N/A" if not is_public else
            f"Remove public restore permission from snapshot '{sid}'.",
            {"snapshot_id": sid, "is_public": is_public, "encrypted": snap.get("encrypted")},
        ))

    return findings


def _check_amis_not_public(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Ninguna AMI propia debe ser pública sin ser intencional."""
    cid      = "WAF-EC2-AMI-01"
    name     = "Custom AMIs not public"
    findings = []

    for iid, ami in raw.get("amis", {}).items():
        is_public = ami.get("is_public", False)
        findings.append(_finding(
            cid, name,
            Status.FAIL if is_public else Status.PASS,
            Severity.HIGH,
            f"arn:aws:ec2:{region}:{account_id}:image/{iid}", region, account_id,
            f"AMI '{iid}' ({ami.get('name')}) is public." if is_public
            else f"AMI '{iid}' is not public.",
            "N/A" if not is_public else
            f"Make AMI '{iid}' private unless public sharing is intentional.",
            {"ami_id": iid, "name": ami.get("name"), "is_public": is_public},
        ))

    return findings


def _check_imdsv2_enforced(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 5.6 — IMDSv2 debe ser requerido en todas las instancias."""
    cid      = "CIS-EC2-5.6"
    name     = "IMDSv2 enforced on EC2 instances"
    findings = []

    for iid, inst in raw.get("instances", {}).items():
        if inst.get("state") != "running":
            continue

        enforced = inst.get("imdsv2_enforced", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if enforced else Status.FAIL,
            Severity.HIGH,
            _instance_arn(iid, region, account_id), region, account_id,
            f"Instance '{iid}' requires IMDSv2." if enforced
            else f"Instance '{iid}' does not require IMDSv2 (HttpTokens=optional).",
            "N/A" if enforced else
            f"Set HttpTokens=required on instance '{iid}' to enforce IMDSv2.",
            {"instance_id": iid, "imdsv2_required": enforced},
        ))

    return findings


def _check_security_groups_no_open_ingress(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 5.2/5.3 — Security groups no deben permitir acceso 0.0.0.0/0 en puertos sensibles."""
    cid      = "CIS-EC2-5.2"
    name     = "Security groups restrict open ingress on sensitive ports"
    findings = []

    for sgid, sg in raw.get("security_groups", {}).items():
        open_to_world = sg.get("open_to_world", False)
        exposed       = sg.get("exposed_port_details", [])

        findings.append(_finding(
            cid, name,
            Status.FAIL if open_to_world else Status.PASS,
            Severity.CRITICAL if open_to_world else Severity.INFO,
            _sg_arn(sgid, region, account_id), region, account_id,
            f"Security group '{sgid}' ({sg.get('name')}) exposes sensitive ports to 0.0.0.0/0: "
            f"{[e['exposed_sensitive_ports'] for e in exposed]}." if open_to_world
            else f"Security group '{sgid}' does not expose sensitive ports to the world.",
            "N/A" if not open_to_world else
            f"Restrict inbound rules on security group '{sgid}' to known IP ranges.",
            {"sg_id": sgid, "name": sg.get("name"), "exposed_ports": exposed},
        ))

    return findings


def _check_default_sg_no_rules(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 5.4 — El security group default no debe tener reglas."""
    cid      = "CIS-EC2-5.4"
    name     = "Default security group has no inbound or outbound rules"
    findings = []

    for sgid, sg in raw.get("security_groups", {}).items():
        if not sg.get("is_default"):
            continue

        inbound  = sg.get("inbound_rules", [])
        outbound = sg.get("outbound_rules", [])
        has_rules = len(inbound) > 0 or len(outbound) > 0

        findings.append(_finding(
            cid, name,
            Status.FAIL if has_rules else Status.PASS,
            Severity.MEDIUM,
            _sg_arn(sgid, region, account_id), region, account_id,
            f"Default security group '{sgid}' has {len(inbound)} inbound and {len(outbound)} outbound rules." if has_rules
            else f"Default security group '{sgid}' has no rules.",
            "N/A" if not has_rules else
            f"Remove all inbound and outbound rules from default security group '{sgid}'.",
            {"sg_id": sgid, "inbound_count": len(inbound), "outbound_count": len(outbound)},
        ))

    return findings


def _check_vpc_flow_logs(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 3.9 — VPC Flow Logs deben estar habilitados en todas las VPCs."""
    cid      = "CIS-EC2-3.9"
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
            f"Enable VPC Flow Logs for VPC '{vid}' and send to CloudWatch Logs or S3.",
            {"vpc_id": vid, "is_default": vpc.get("is_default")},
        ))

    return findings


def _check_instances_monitoring(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Todas las instancias deben tener detailed monitoring habilitado."""
    cid      = "WAF-EC2-MON-01"
    name     = "EC2 instances have detailed monitoring enabled"
    findings = []

    for iid, inst in raw.get("instances", {}).items():
        if inst.get("state") != "running":
            continue

        monitoring = inst.get("monitoring_enabled", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if monitoring else Status.FAIL,
            Severity.LOW,
            _instance_arn(iid, region, account_id), region, account_id,
            f"Instance '{iid}' has detailed monitoring enabled." if monitoring
            else f"Instance '{iid}' has basic monitoring only.",
            "N/A" if monitoring else
            f"Enable detailed monitoring on instance '{iid}' for 1-minute metric granularity.",
            {"instance_id": iid, "monitoring": inst.get("monitoring")},
        ))

    return findings


def _check_instances_no_public_ip(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Instancias no deben tener IP pública directa salvo que sea necesario."""
    cid      = "WAF-EC2-PIP-01"
    name     = "EC2 instances without direct public IP"
    findings = []

    for iid, inst in raw.get("instances", {}).items():
        if inst.get("state") != "running":
            continue

        exposure = inst.get("exposure_type", "private")
        directly_exposed = exposure == "direct_public"

        findings.append(_finding(
            cid, name,
            Status.FAIL if directly_exposed else Status.PASS,
            Severity.HIGH,
            _instance_arn(iid, region, account_id), region, account_id,
            f"Instance '{iid}' is directly exposed to the internet ({inst.get('public_ip')})." if directly_exposed
            else f"Instance '{iid}' is not directly exposed ({exposure}).",
            "N/A" if not directly_exposed else
            f"Place instance '{iid}' behind a load balancer or remove its public IP.",
            {"instance_id": iid, "public_ip": inst.get("public_ip"), "exposure_type": exposure},
        ))

    return findings


def _check_instances_ssm_managed(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Instancias deben estar gestionadas por SSM en lugar de SSH."""
    cid      = "WAF-EC2-SSM-01"
    name     = "EC2 instances managed by SSM"
    findings = []

    for iid, inst in raw.get("instances", {}).items():
        if inst.get("state") != "running":
            continue

        ssm_managed = inst.get("ssm_managed", False)
        findings.append(_finding(
            cid, name,
            Status.PASS if ssm_managed else Status.FAIL,
            Severity.MEDIUM,
            _instance_arn(iid, region, account_id), region, account_id,
            f"Instance '{iid}' is managed by SSM." if ssm_managed
            else f"Instance '{iid}' is not registered in SSM.",
            "N/A" if ssm_managed else
            f"Install SSM Agent on instance '{iid}', attach an IAM role with AmazonSSMManagedInstanceCore, "
            f"and use Session Manager instead of SSH.",
            {"instance_id": iid, "ssm_managed": ssm_managed},
        ))

    return findings


def _check_vpc_endpoints_critical(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Servicios críticos deben tener VPC Endpoints para evitar tráfico por internet."""
    cid      = "WAF-EC2-VPE-01"
    name     = "Critical services have VPC Endpoints"
    findings = []

    missing = raw.get("missing_critical_endpoints", [])
    resource = f"arn:aws:ec2:{region}:{account_id}:vpc-endpoint"

    if not missing:
        return [_finding(
            cid, name, Status.PASS, Severity.MEDIUM,
            resource, region, account_id,
            "All critical services have VPC Endpoints configured.",
            "N/A",
            {"missing_endpoints": []},
        )]

    return [_finding(
        cid, name, Status.FAIL, Severity.MEDIUM,
        resource, region, account_id,
        f"Missing VPC Endpoints for critical services: {missing}.",
        f"Create VPC Endpoints for: {', '.join(missing)} to keep traffic within the AWS network.",
        {"missing_endpoints": missing},
    )]


def _check_subnets_no_auto_assign_ip(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 5.4 — Subnets no deben auto-asignar IP pública."""
    cid      = "WAF-EC2-SUB-01"
    name     = "Subnets do not auto-assign public IPs"
    findings = []

    for sid, subnet in raw.get("subnets", {}).items():
        auto_assign = subnet.get("auto_assign_public_ip", False)
        findings.append(_finding(
            cid, name,
            Status.FAIL if auto_assign else Status.PASS,
            Severity.MEDIUM,
            _subnet_arn(sid, region, account_id), region, account_id,
            f"Subnet '{sid}' auto-assigns public IPs to instances." if auto_assign
            else f"Subnet '{sid}' does not auto-assign public IPs.",
            "N/A" if not auto_assign else
            f"Disable auto-assign public IP on subnet '{sid}'.",
            {"subnet_id": sid, "auto_assign_public_ip": auto_assign},
        ))

    return findings


def _check_nacl_no_open_ingress(raw: dict, account_id: str, region: str) -> list[Finding]:
    """CIS 5.1 — NACLs no deben permitir ingreso irrestricto en puertos administrativos."""
    cid      = "CIS-EC2-5.1"
    name     = "Network ACLs restrict open ingress on admin ports"
    findings = []
    ADMIN_PORTS = {22, 3389}

    for aid, acl in raw.get("network_acls", {}).items():
        open_admin = []
        for entry in acl.get("entries", []):
            if entry.get("Egress", True):
                continue
            if entry.get("RuleAction") != "allow":
                continue

            cidr = entry.get("CidrBlock", "") or entry.get("Ipv6CidrBlock", "")
            if cidr not in ("0.0.0.0/0", "::/0"):
                continue

            port_range = entry.get("PortRange", {})
            from_p = port_range.get("From", 0)
            to_p   = port_range.get("To", 65535)

            for port in ADMIN_PORTS:
                if from_p <= port <= to_p:
                    open_admin.append({"port": port, "cidr": cidr})

        has_open = len(open_admin) > 0
        resource = f"arn:aws:ec2:{region}:{account_id}:network-acl/{aid}"

        findings.append(_finding(
            cid, name,
            Status.FAIL if has_open else Status.PASS,
            Severity.HIGH,
            resource, region, account_id,
            f"NACL '{aid}' allows unrestricted ingress on admin ports: {open_admin}." if has_open
            else f"NACL '{aid}' restricts ingress on admin ports.",
            "N/A" if not has_open else
            f"Add deny rules in NACL '{aid}' for ports 22 and 3389 from 0.0.0.0/0.",
            {"nacl_id": aid, "open_admin_ports": open_admin},
        ))

    return findings


def _check_unused_eips(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Elastic IPs sin asignar representan costo y superficie de ataque innecesaria."""
    cid      = "WAF-EC2-EIP-01"
    name     = "Elastic IPs are assigned"
    findings = []

    for eip in raw.get("elastic_ips", []):
        is_unassigned = eip.get("is_unassigned", False)
        public_ip     = eip.get("public_ip", "unknown")
        resource      = f"arn:aws:ec2:{region}:{account_id}:elastic-ip/{public_ip}"

        findings.append(_finding(
            cid, name,
            Status.FAIL if is_unassigned else Status.PASS,
            Severity.LOW,
            resource, region, account_id,
            f"Elastic IP '{public_ip}' is not associated with any resource." if is_unassigned
            else f"Elastic IP '{public_ip}' is in use.",
            "N/A" if not is_unassigned else
            f"Release unassigned Elastic IP '{public_ip}' to reduce attack surface and avoid charges.",
            {"public_ip": public_ip, "is_unassigned": is_unassigned},
        ))

    return findings


def _check_instances_exposure_type(raw: dict, account_id: str, region: str) -> list[Finding]:
    """WAF — Resumen de exposición de instancias (direct_public vs behind_elb vs private)."""
    cid      = "WAF-EC2-EXP-01"
    name     = "EC2 instances exposure classification"
    findings = []

    for iid, inst in raw.get("instances", {}).items():
        if inst.get("state") != "running":
            continue

        exposure = inst.get("exposure_type", "private")
        if exposure == "direct_public":
            findings.append(_finding(
                cid, name, Status.FAIL, Severity.HIGH,
                _instance_arn(iid, region, account_id), region, account_id,
                f"Instance '{iid}' is directly exposed to the internet without a load balancer.",
                f"Place instance '{iid}' behind an ALB or NLB and remove its public IP.",
                {"instance_id": iid, "exposure_type": exposure, "public_ip": inst.get("public_ip")},
            ))

    return findings