import boto3

from schemas.collector_output import CollectorOutput
from utils.aws_session import get_client, get_account_id, get_region
from utils.logger import get_logger

logger = get_logger(__name__)


def collect(session: boto3.Session) -> CollectorOutput:
    """
    [COL-03] Recopila configuración EC2 relevante para auditoría CIS/WAF:
      - Instancias: estado, metadata options, monitoring, EBS encryption
      - Security groups: reglas inbound/outbound permisivas
      - VPCs: default VPC, flow logs
      - Subnets: auto-assign public IP
      - Network ACLs
      - Internet Gateways
      - EBS volumes: encriptación en reposo
      - EBS snapshots: visibilidad pública
      - AMIs propias: visibilidad pública
      - Key pairs registrados
      - Elastic IPs sin asignar
    """
    ec2        = get_client("ec2", session)
    account_id = get_account_id(session)
    region     = get_region(session)
    errors: list[str] = []
    raw: dict  = {}

    # ── 1. Instancias ─────────────────────────────────────────────────────────
    logger.info("EC2: recopilando instancias")
    raw["instances"] = {}
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    iid = inst["InstanceId"]
                    raw["instances"][iid] = {
                        "instance":          inst,
                        "state":             inst.get("State", {}).get("Name"),
                        "public_ip":         inst.get("PublicIpAddress"),
                        "private_ip":        inst.get("PrivateIpAddress"),
                        "imdsv2_required":   inst.get("MetadataOptions", {}).get("HttpTokens") == "required",
                        "monitoring":        inst.get("Monitoring", {}).get("State"),
                        "ebs_optimized":     inst.get("EbsOptimized", False),
                        "iam_profile":       inst.get("IamInstanceProfile", {}).get("Arn"),
                        "security_groups":   [sg["GroupId"] for sg in inst.get("SecurityGroups", [])],
                        "subnet_id":         inst.get("SubnetId"),
                        "vpc_id":            inst.get("VpcId"),
                        "tags":              {t["Key"]: t["Value"] for t in inst.get("Tags", [])},
                    }
    except Exception as e:
        errors.append(f"describe_instances: {e}")
        logger.error(f"EC2: error listando instancias — {e}")

    # ── 2. Security groups ────────────────────────────────────────────────────
    logger.info("EC2: recopilando security groups")
    raw["security_groups"] = {}
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                sgid = sg["GroupId"]
                raw["security_groups"][sgid] = {
                    "sg":               sg,
                    "name":             sg.get("GroupName"),
                    "vpc_id":           sg.get("VpcId"),
                    "inbound_rules":    sg.get("IpPermissions", []),
                    "outbound_rules":   sg.get("IpPermissionsEgress", []),
                    "is_default":       sg.get("GroupName") == "default",
                }
    except Exception as e:
        errors.append(f"describe_security_groups: {e}")
        logger.error(f"EC2: error listando security groups — {e}")

    # ── 3. VPCs ───────────────────────────────────────────────────────────────
    logger.info("EC2: recopilando VPCs")
    raw["vpcs"] = {}
    try:
        for vpc in ec2.describe_vpcs()["Vpcs"]:
            vid = vpc["VpcId"]
            vpc_data = {
                "vpc":        vpc,
                "is_default": vpc.get("IsDefault", False),
                "cidr":       vpc.get("CidrBlock"),
                "flow_logs":  [],
            }

            try:
                fl_resp = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vid]}]
                )
                vpc_data["flow_logs"] = fl_resp.get("FlowLogs", [])
            except Exception as e:
                errors.append(f"flow_logs:{vid}: {e}")

            raw["vpcs"][vid] = vpc_data
    except Exception as e:
        errors.append(f"describe_vpcs: {e}")
        logger.error(f"EC2: error listando VPCs — {e}")

    # ── 4. Subnets ────────────────────────────────────────────────────────────
    logger.info("EC2: recopilando subnets")
    raw["subnets"] = {}
    try:
        paginator = ec2.get_paginator("describe_subnets")
        for page in paginator.paginate():
            for subnet in page["Subnets"]:
                sid = subnet["SubnetId"]
                raw["subnets"][sid] = {
                    "subnet":                 subnet,
                    "vpc_id":                 subnet.get("VpcId"),
                    "cidr":                   subnet.get("CidrBlock"),
                    "auto_assign_public_ip":  subnet.get("MapPublicIpOnLaunch", False),
                    "availability_zone":      subnet.get("AvailabilityZone"),
                }
    except Exception as e:
        errors.append(f"describe_subnets: {e}")
        logger.error(f"EC2: error listando subnets — {e}")

    # ── 5. Network ACLs ───────────────────────────────────────────────────────
    logger.info("EC2: recopilando Network ACLs")
    raw["network_acls"] = {}
    try:
        paginator = ec2.get_paginator("describe_network_acls")
        for page in paginator.paginate():
            for acl in page["NetworkAcls"]:
                aid = acl["NetworkAclId"]
                raw["network_acls"][aid] = {
                    "acl":        acl,
                    "vpc_id":     acl.get("VpcId"),
                    "is_default": acl.get("IsDefault", False),
                    "entries":    acl.get("Entries", []),
                    "associations": acl.get("Associations", []),
                }
    except Exception as e:
        errors.append(f"describe_network_acls: {e}")
        logger.error(f"EC2: error listando Network ACLs — {e}")

    # ── 6. Internet Gateways ──────────────────────────────────────────────────
    logger.info("EC2: recopilando Internet Gateways")
    raw["internet_gateways"] = {}
    try:
        paginator = ec2.get_paginator("describe_internet_gateways")
        for page in paginator.paginate():
            for igw in page["InternetGateways"]:
                igw_id = igw["InternetGatewayId"]
                raw["internet_gateways"][igw_id] = {
                    "igw":          igw,
                    "attachments":  igw.get("Attachments", []),
                    "vpc_ids":      [a["VpcId"] for a in igw.get("Attachments", [])],
                }
    except Exception as e:
        errors.append(f"describe_internet_gateways: {e}")
        logger.error(f"EC2: error listando Internet Gateways — {e}")

    # ── 7. EBS volumes ────────────────────────────────────────────────────────
    logger.info("EC2: recopilando EBS volumes")
    raw["ebs_volumes"] = {}
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                vid = vol["VolumeId"]
                raw["ebs_volumes"][vid] = {
                    "volume":      vol,
                    "encrypted":   vol.get("Encrypted", False),
                    "kms_key_id":  vol.get("KmsKeyId"),
                    "state":       vol.get("State"),
                    "size_gb":     vol.get("Size"),
                    "attachments": vol.get("Attachments", []),
                }
    except Exception as e:
        errors.append(f"describe_volumes: {e}")
        logger.error(f"EC2: error listando EBS volumes — {e}")

    # ── 8. EBS snapshots propios ──────────────────────────────────────────────
    logger.info("EC2: recopilando EBS snapshots")
    raw["ebs_snapshots"] = {}
    try:
        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=["self"]):
            for snap in page["Snapshots"]:
                sid = snap["SnapshotId"]
                snap_data = {
                    "snapshot":   snap,
                    "encrypted":  snap.get("Encrypted", False),
                    "is_public":  False,
                }
                try:
                    perms = ec2.describe_snapshot_attribute(
                        SnapshotId=sid,
                        Attribute="createVolumePermission",
                    )
                    for perm in perms.get("CreateVolumePermissions", []):
                        if perm.get("Group") == "all":
                            snap_data["is_public"] = True
                            break
                except Exception as e:
                    errors.append(f"snapshot_perms:{sid}: {e}")

                raw["ebs_snapshots"][sid] = snap_data
    except Exception as e:
        errors.append(f"describe_snapshots: {e}")
        logger.error(f"EC2: error listando EBS snapshots — {e}")

    # ── 9. AMIs propias ───────────────────────────────────────────────────────
    logger.info("EC2: recopilando AMIs propias")
    raw["amis"] = {}
    try:
        images = ec2.describe_images(Owners=["self"]).get("Images", [])
        for img in images:
            iid = img["ImageId"]
            raw["amis"][iid] = {
                "image":     img,
                "is_public": img.get("Public", False),
                "name":      img.get("Name"),
                "state":     img.get("State"),
            }
    except Exception as e:
        errors.append(f"describe_images: {e}")
        logger.error(f"EC2: error listando AMIs — {e}")

    # ── 10. Key pairs ─────────────────────────────────────────────────────────
    logger.info("EC2: recopilando key pairs")
    raw["key_pairs"] = []
    try:
        raw["key_pairs"] = ec2.describe_key_pairs().get("KeyPairs", [])
    except Exception as e:
        errors.append(f"describe_key_pairs: {e}")
        logger.error(f"EC2: error listando key pairs — {e}")

    # ── 11. Elastic IPs ───────────────────────────────────────────────────────
    logger.info("EC2: recopilando Elastic IPs")
    raw["elastic_ips"] = []
    try:
        addresses = ec2.describe_addresses().get("Addresses", [])
        for addr in addresses:
            raw["elastic_ips"].append({
                "address":       addr,
                "is_unassigned": "AssociationId" not in addr,
                "public_ip":     addr.get("PublicIp"),
            })
    except Exception as e:
        errors.append(f"describe_addresses: {e}")
        logger.error(f"EC2: error listando Elastic IPs — {e}")

    # ── 12. EBS encryption by default ─────────────────────────────────────────
    logger.info("EC2: verificando EBS encryption by default")
    raw["ebs_encryption_by_default"] = False
    try:
        resp = ec2.get_ebs_encryption_by_default()
        raw["ebs_encryption_by_default"] = resp.get("EbsEncryptionByDefault", False)
    except Exception as e:
        errors.append(f"ebs_encryption_by_default: {e}")
        logger.error(f"EC2: error verificando EBS encryption by default — {e}")

    # ── 13. SSM managed instances ─────────────────────────────────────────────
    try:
        _collect_ssm(session, raw, errors)
    except Exception as e:
        errors.append(f"ssm: {e}")
        logger.error(f"EC2: error en SSM — {e}")

    # ── 14. VPC Endpoints ─────────────────────────────────────────────────────
    try:
        _collect_vpc_endpoints(session, raw, errors)
    except Exception as e:
        errors.append(f"vpc_endpoints: {e}")
        logger.error(f"EC2: error en VPC Endpoints — {e}")

    # ── 15. Route Tables ──────────────────────────────────────────────────────
    try:
        _collect_route_tables(session, raw, errors)
    except Exception as e:
        errors.append(f"route_tables: {e}")
        logger.error(f"EC2: error en Route Tables — {e}")

    # ── 16. NAT Gateways ──────────────────────────────────────────────────────
    try:
        _collect_nat_gateways(session, raw, errors)
    except Exception as e:
        errors.append(f"nat_gateways: {e}")
        logger.error(f"EC2: error en NAT Gateways — {e}")

    # ── 17. ELB exposure ──────────────────────────────────────────────────────
    try:
        _collect_elb_exposure(session, raw, errors)
    except Exception as e:
        errors.append(f"elb_exposure: {e}")
        logger.error(f"EC2: error en ELB exposure — {e}")

    # ── 18. Enrichments ───────────────────────────────────────────────────────
    logger.info("EC2: calculando enrichments")
    try:
        _enrich(raw, errors)
    except Exception as e:
        errors.append(f"enrichments: {e}")
        logger.error(f"EC2: error en enrichments — {e}")

    exp = raw.get("exposure_summary", {})
    logger.info(
        f"EC2: recolección completa — "
        f"{len(raw.get('instances', {}))} instancias "
        f"(directas: {exp.get('direct_public', 0)}, "
        f"ELB: {exp.get('behind_elb', 0)}, "
        f"privadas: {exp.get('private', 0)}), "
        f"{len(raw.get('security_groups', {}))} SGs, "
        f"{len(raw.get('vpcs', {}))} VPCs, "
        f"{len(raw.get('vpc_endpoints', {}))} endpoints, "
        f"{len(raw.get('route_tables', {}))} route tables, "
        f"{len(raw.get('nat_gateways', {}))} NAT GWs, "
        f"{len(raw.get('load_balancers', {}))} LBs, "
        f"{len(raw.get('ebs_volumes', {}))} volúmenes, "
        f"{len(errors)} errores"
    )

    return CollectorOutput(
        service="ec2",
        account_id=account_id,
        region=region,
        raw_data=raw,
        errors=errors,
    )


def _enrich(raw: dict, errors: list[str]) -> None:
    """
    Calcula métricas derivadas:
      - Security groups con reglas 0.0.0.0/0 en puertos sensibles
      - VPCs default sin flow logs
      - Instancias sin IMDSv2
      - Subnets con auto-assign public IP
      - Snapshots y AMIs públicas
      - Volúmenes sin encriptar adjuntos a instancias activas
    """
    SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 8080, 8443}

    # Security groups permisivos
    for sgid, sg_data in raw.get("security_groups", {}).items():
        try:
            open_ports: list[dict] = []
            for rule in sg_data.get("inbound_rules", []):
                from_port = rule.get("FromPort", 0)
                to_port   = rule.get("ToPort", 65535)
                ranges    = rule.get("IpRanges", []) + rule.get("Ipv6Ranges", [])

                is_open = any(
                    r.get("CidrIp") == "0.0.0.0/0" or r.get("CidrIpv6") == "::/0"
                    for r in ranges
                )
                if is_open:
                    exposed = [
                        p for p in SENSITIVE_PORTS
                        if from_port <= p <= to_port
                    ] or (["all"] if from_port == 0 and to_port == 65535 else [])

                    if exposed:
                        open_ports.append({
                            "protocol":   rule.get("IpProtocol"),
                            "from_port":  from_port,
                            "to_port":    to_port,
                            "exposed_sensitive_ports": exposed,
                        })

            sg_data["open_to_world"]        = len(open_ports) > 0
            sg_data["exposed_port_details"] = open_ports
        except Exception as e:
            errors.append(f"enrich_sg:{sgid}: {e}")

    # VPCs default y flow logs
    for vid, vpc_data in raw.get("vpcs", {}).items():
        try:
            vpc_data["has_flow_logs"]     = len(vpc_data.get("flow_logs", [])) > 0
            vpc_data["default_no_logs"]   = vpc_data["is_default"] and not vpc_data["has_flow_logs"]
        except Exception as e:
            errors.append(f"enrich_vpc:{vid}: {e}")

    # Instancias sin IMDSv2 o sin monitoring
    for iid, inst_data in raw.get("instances", {}).items():
        try:
            inst_data["imdsv2_enforced"]    = inst_data.get("imdsv2_required", False)
            inst_data["monitoring_enabled"] = inst_data.get("monitoring") == "enabled"
        except Exception as e:
            errors.append(f"enrich_instance:{iid}: {e}")

    # Resumen global
    raw["summary"] = {
        "total_instances":          len(raw.get("instances", {})),
        "running_instances":        sum(1 for i in raw.get("instances", {}).values() if i.get("state") == "running"),
        "instances_without_imdsv2": sum(1 for i in raw.get("instances", {}).values() if not i.get("imdsv2_enforced")),
        "public_snapshots":         sum(1 for s in raw.get("ebs_snapshots", {}).values() if s.get("is_public")),
        "public_amis":              sum(1 for a in raw.get("amis", {}).values() if a.get("is_public")),
        "unencrypted_volumes":      sum(1 for v in raw.get("ebs_volumes", {}).values() if not v.get("encrypted")),
        "sgs_open_to_world":        sum(1 for sg in raw.get("security_groups", {}).values() if sg.get("open_to_world")),
        "vpcs_without_flow_logs":   sum(1 for v in raw.get("vpcs", {}).values() if not v.get("has_flow_logs")),
        "unassigned_eips":          sum(1 for e in raw.get("elastic_ips", []) if e.get("is_unassigned")),
        "ebs_encryption_by_default": raw.get("ebs_encryption_by_default", False),
    }


# ══════════════════════════════════════════════════════════════════════════════
# BLOQUES ADICIONALES — se integran llamando a collect_extended(session, raw, errors)
# ══════════════════════════════════════════════════════════════════════════════

def _collect_ssm(session: boto3.Session, raw: dict, errors: list[str]) -> None:
    """[COL-03-EXT-01] Instancias registradas en SSM vs acceso por SSH."""
    logger.info("EC2: verificando instancias gestionadas por SSM")
    raw["ssm_managed_instances"] = {}
    try:
        ssm = get_client("ssm", session)
        paginator = ssm.get_paginator("describe_instance_information")
        for page in paginator.paginate():
            for inst in page["InstanceInformationList"]:
                iid = inst.get("InstanceId")
                if iid:
                    raw["ssm_managed_instances"][iid] = {
                        "ping_status":      inst.get("PingStatus"),
                        "agent_version":    inst.get("AgentVersion"),
                        "platform_type":    inst.get("PlatformType"),
                        "last_ping":        inst.get("LastPingDateTime"),
                        "association_status": inst.get("AssociationStatus"),
                    }
    except Exception as e:
        errors.append(f"ssm_instances: {e}")
        logger.error(f"EC2: error verificando SSM — {e}")

    # Marcar instancias EC2 con/sin SSM
    managed_ids = set(raw["ssm_managed_instances"].keys())
    for iid, inst_data in raw.get("instances", {}).items():
        inst_data["ssm_managed"] = iid in managed_ids


def _collect_vpc_endpoints(session: boto3.Session, raw: dict, errors: list[str]) -> None:
    """[COL-03-EXT-02] VPC Endpoints — tráfico interno vs salida a internet."""
    logger.info("EC2: recopilando VPC Endpoints")
    raw["vpc_endpoints"] = {}
    try:
        ec2 = get_client("ec2", session)
        paginator = ec2.get_paginator("describe_vpc_endpoints")
        for page in paginator.paginate():
            for ep in page["VpcEndpoints"]:
                epid = ep["VpcEndpointId"]
                raw["vpc_endpoints"][epid] = {
                    "endpoint":     ep,
                    "vpc_id":       ep.get("VpcId"),
                    "service_name": ep.get("ServiceName"),
                    "type":         ep.get("VpcEndpointType"),
                    "state":        ep.get("State"),
                }
    except Exception as e:
        errors.append(f"vpc_endpoints: {e}")
        logger.error(f"EC2: error listando VPC Endpoints — {e}")

    # Marcar qué servicios críticos tienen endpoint
    critical_services = {"s3", "dynamodb", "ssm", "ec2messages", "ssmmessages", "kms", "logs"}
    covered = set()
    for ep in raw["vpc_endpoints"].values():
        svc = ep.get("service_name", "").split(".")[-1].lower()
        covered.add(svc)

    raw["missing_critical_endpoints"] = sorted(critical_services - covered)


def _collect_route_tables(session: boto3.Session, raw: dict, errors: list[str]) -> None:
    """[COL-03-EXT-03] Route tables — valida aislamiento real de subnets privadas."""
    logger.info("EC2: recopilando route tables")
    raw["route_tables"] = {}
    try:
        ec2 = get_client("ec2", session)
        paginator = ec2.get_paginator("describe_route_tables")
        for page in paginator.paginate():
            for rt in page["RouteTables"]:
                rtid = rt["RouteTableId"]
                routes = rt.get("Routes", [])

                # Detectar rutas a internet (IGW o cualquier gateway de salida)
                has_igw_route = any(
                    r.get("GatewayId", "").startswith("igw-") and
                    r.get("DestinationCidrBlock") in ("0.0.0.0/0", "::/0")
                    for r in routes
                )
                has_nat_route = any(
                    r.get("NatGatewayId", "") and
                    r.get("DestinationCidrBlock") in ("0.0.0.0/0", "::/0")
                    for r in routes
                )

                associated_subnets = [
                    a["SubnetId"]
                    for a in rt.get("Associations", [])
                    if a.get("SubnetId")
                ]

                raw["route_tables"][rtid] = {
                    "route_table":       rt,
                    "vpc_id":            rt.get("VpcId"),
                    "routes":            routes,
                    "associated_subnets": associated_subnets,
                    "has_igw_route":     has_igw_route,
                    "has_nat_route":     has_nat_route,
                    "is_public":         has_igw_route,
                }

        # Marcar subnets como públicas o privadas según su route table
        for rtid, rt_data in raw["route_tables"].items():
            for sid in rt_data["associated_subnets"]:
                if sid in raw.get("subnets", {}):
                    raw["subnets"][sid]["is_effectively_public"] = rt_data["is_public"]

    except Exception as e:
        errors.append(f"route_tables: {e}")
        logger.error(f"EC2: error listando route tables — {e}")


def _collect_nat_gateways(session: boto3.Session, raw: dict, errors: list[str]) -> None:
    """[COL-03-EXT-04] NAT Gateways — inventario y subnets que sirven."""
    logger.info("EC2: recopilando NAT Gateways")
    raw["nat_gateways"] = {}
    try:
        ec2 = get_client("ec2", session)
        paginator = ec2.get_paginator("describe_nat_gateways")
        for page in paginator.paginate():
            for nat in page["NatGateways"]:
                nid = nat["NatGatewayId"]
                raw["nat_gateways"][nid] = {
                    "nat":       nat,
                    "vpc_id":    nat.get("VpcId"),
                    "subnet_id": nat.get("SubnetId"),
                    "state":     nat.get("State"),
                    "type":      nat.get("ConnectivityType", "public"),
                }
    except Exception as e:
        errors.append(f"nat_gateways: {e}")
        logger.error(f"EC2: error listando NAT Gateways — {e}")


def _collect_elb_exposure(session: boto3.Session, raw: dict, errors: list[str]) -> None:
    """
    [COL-03-EXT-05] Instancias con IP pública directa vs detrás de ELB.
    Consulta ELBv2 (ALB/NLB) y ELB clásico para mapear qué instancias
    están detrás de un load balancer y cuáles están expuestas directamente.
    """
    logger.info("EC2: verificando exposición directa vs ELB")
    raw["load_balancers"] = {}
    instances_behind_elb: set[str] = set()

    # ELBv2 (ALB / NLB)
    try:
        elbv2 = get_client("elbv2", session)
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page["LoadBalancers"]:
                lbarn  = lb["LoadBalancerArn"]
                lb_data = {
                    "lb":       lb,
                    "name":     lb.get("LoadBalancerName"),
                    "type":     lb.get("Type"),
                    "scheme":   lb.get("Scheme"),
                    "dns_name": lb.get("DNSName"),
                    "targets":  [],
                }

                # Target groups → instancias
                try:
                    tg_resp = elbv2.describe_target_groups(LoadBalancerArn=lbarn)
                    for tg in tg_resp.get("TargetGroups", []):
                        tgarn = tg["TargetGroupArn"]
                        try:
                            th_resp = elbv2.describe_target_health(TargetGroupArn=tgarn)
                            for th in th_resp.get("TargetHealthDescriptions", []):
                                iid = th.get("Target", {}).get("Id")
                                if iid and iid.startswith("i-"):
                                    instances_behind_elb.add(iid)
                                    lb_data["targets"].append(iid)
                        except Exception as e:
                            errors.append(f"target_health:{tgarn}: {e}")
                except Exception as e:
                    errors.append(f"target_groups:{lbarn}: {e}")

                raw["load_balancers"][lbarn] = lb_data

    except Exception as e:
        errors.append(f"elbv2: {e}")
        logger.error(f"EC2: error listando ELBv2 — {e}")

    # ELB clásico
    try:
        elb = get_client("elb", session)
        paginator = elb.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page["LoadBalancerDescriptions"]:
                lbname  = lb["LoadBalancerName"]
                lb_data = {
                    "lb":       lb,
                    "name":     lbname,
                    "type":     "classic",
                    "scheme":   lb.get("Scheme"),
                    "dns_name": lb.get("DNSName"),
                    "targets":  [i["InstanceId"] for i in lb.get("Instances", [])],
                }
                for iid in lb_data["targets"]:
                    instances_behind_elb.add(iid)

                raw["load_balancers"][f"classic:{lbname}"] = lb_data

    except Exception as e:
        errors.append(f"elb_classic: {e}")
        logger.error(f"EC2: error listando ELB clásico — {e}")

    # Marcar cada instancia con su tipo de exposición
    for iid, inst_data in raw.get("instances", {}).items():
        has_public_ip  = bool(inst_data.get("public_ip"))
        behind_elb     = iid in instances_behind_elb
        inst_data["behind_elb"]          = behind_elb
        inst_data["directly_exposed"]    = has_public_ip and not behind_elb
        inst_data["exposure_type"] = (
            "behind_elb"    if behind_elb and has_public_ip else
            "private"       if not has_public_ip else
            "direct_public"
        )

    raw["exposure_summary"] = {
        "direct_public":  sum(1 for i in raw.get("instances", {}).values() if i.get("exposure_type") == "direct_public"),
        "behind_elb":     sum(1 for i in raw.get("instances", {}).values() if i.get("exposure_type") == "behind_elb"),
        "private":        sum(1 for i in raw.get("instances", {}).values() if i.get("exposure_type") == "private"),
    }