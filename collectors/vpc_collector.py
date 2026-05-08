import boto3

from schemas.collector_output import CollectorOutput
from utils.aws_session import get_client, get_account_id, get_region
from utils.logger import get_logger

logger = get_logger(__name__)


def collect(session: boto3.Session) -> CollectorOutput:
    """
    [COL-07] Recopila configuración VPC relevante para auditoría CIS/WAF:
      - VPCs: configuración base, DNS, tenancy
      - Flow logs: cobertura, destino, tipo de tráfico
      - Peering connections: estado, cross-account, CIDRs
      - VPN Gateways y Customer Gateways
      - Site-to-Site VPN connections: estado de túneles
      - Direct Connect: conexiones y virtual interfaces
      - Subnets: segmentación público/privado
      - VPC Endpoints: inventario y políticas
      - PrivateLink services expuestos
      - DHCP option sets
      - Route 53 Resolver rules
    """
    ec2        = get_client("ec2", session)
    account_id = get_account_id(session)
    region     = get_region(session)
    errors: list[str] = []
    raw: dict  = {}

    # ── 1. VPCs ───────────────────────────────────────────────────────────────
    logger.info("VPC: recopilando VPCs")
    raw["vpcs"] = {}
    try:
        paginator = ec2.get_paginator("describe_vpcs")
        for page in paginator.paginate():
            for vpc in page["Vpcs"]:
                vid = vpc["VpcId"]
                raw["vpcs"][vid] = {
                    "vpc":               vpc,
                    "cidr":              vpc.get("CidrBlock"),
                    "cidr_associations": [
                        a.get("CidrBlock")
                        for a in vpc.get("CidrBlockAssociationSet", [])
                    ],
                    "is_default":        vpc.get("IsDefault", False),
                    "tenancy":           vpc.get("InstanceTenancy", "default"),
                    "state":             vpc.get("State"),
                    "dns_resolution":    False,
                    "dns_hostnames":     False,
                    "tags":              {t["Key"]: t["Value"] for t in vpc.get("Tags", [])},
                }

                # DNS resolution y hostnames
                try:
                    dns_res = ec2.describe_vpc_attribute(VpcId=vid, Attribute="enableDnsSupport")
                    raw["vpcs"][vid]["dns_resolution"] = dns_res.get("EnableDnsSupport", {}).get("Value", False)
                except Exception as e:
                    errors.append(f"dns_resolution:{vid}: {e}")

                try:
                    dns_host = ec2.describe_vpc_attribute(VpcId=vid, Attribute="enableDnsHostnames")
                    raw["vpcs"][vid]["dns_hostnames"] = dns_host.get("EnableDnsHostnames", {}).get("Value", False)
                except Exception as e:
                    errors.append(f"dns_hostnames:{vid}: {e}")

    except Exception as e:
        errors.append(f"describe_vpcs: {e}")
        logger.error(f"VPC: error listando VPCs — {e}")

    # ── 2. Flow logs ──────────────────────────────────────────────────────────
    logger.info("VPC: recopilando flow logs")
    raw["flow_logs"] = {}
    try:
        paginator = ec2.get_paginator("describe_flow_logs")
        for page in paginator.paginate():
            for fl in page["FlowLogs"]:
                flid = fl["FlowLogId"]
                raw["flow_logs"][flid] = {
                    "flow_log":        fl,
                    "resource_id":     fl.get("ResourceId"),
                    "resource_type":   fl.get("ResourceType"),
                    "traffic_type":    fl.get("TrafficType"),
                    "destination":     fl.get("LogDestinationType"),
                    "destination_arn": fl.get("LogDestination") or fl.get("CloudWatchLogsLogGroupArn"),
                    "log_format":      fl.get("LogFormat"),
                    "status":          fl.get("FlowLogStatus"),
                    "deliver_role":    fl.get("DeliverLogsPermissionArn"),
                }

        # Indexar flow logs por VPC
        for vid in raw["vpcs"]:
            vpc_flow_logs = [
                fl for fl in raw["flow_logs"].values()
                if fl.get("resource_id") == vid
                and fl.get("resource_type") == "VPC"
                and fl.get("status") == "ACTIVE"
            ]
            raw["vpcs"][vid]["flow_logs"]        = [fl["flow_log"]["FlowLogId"] for fl in vpc_flow_logs]
            raw["vpcs"][vid]["has_flow_logs"]    = len(vpc_flow_logs) > 0
            raw["vpcs"][vid]["flow_logs_all_traffic"] = any(
                fl.get("traffic_type") == "ALL" for fl in vpc_flow_logs
            )

    except Exception as e:
        errors.append(f"describe_flow_logs: {e}")
        logger.error(f"VPC: error listando flow logs — {e}")

    # ── 3. Peering connections ────────────────────────────────────────────────
    logger.info("VPC: recopilando peering connections")
    raw["peering_connections"] = {}
    try:
        paginator = ec2.get_paginator("describe_vpc_peering_connections")
        for page in paginator.paginate():
            for peer in page["VpcPeeringConnections"]:
                pid = peer["VpcPeeringConnectionId"]
                requester = peer.get("RequesterVpcInfo", {})
                accepter  = peer.get("AccepterVpcInfo", {})
                raw["peering_connections"][pid] = {
                    "peering":             peer,
                    "status":              peer.get("Status", {}).get("Code"),
                    "requester_vpc":       requester.get("VpcId"),
                    "requester_account":   requester.get("OwnerId"),
                    "requester_cidr":      requester.get("CidrBlock"),
                    "accepter_vpc":        accepter.get("VpcId"),
                    "accepter_account":    accepter.get("OwnerId"),
                    "accepter_cidr":       accepter.get("CidrBlock"),
                    "is_cross_account":    requester.get("OwnerId") != accepter.get("OwnerId"),
                    "is_cross_region":     requester.get("Region") != accepter.get("Region"),
                    "tags":                {t["Key"]: t["Value"] for t in peer.get("Tags", [])},
                }
    except Exception as e:
        errors.append(f"describe_vpc_peering_connections: {e}")
        logger.error(f"VPC: error listando peering connections — {e}")

    # ── 4. VPN Gateways ───────────────────────────────────────────────────────
    logger.info("VPC: recopilando VPN Gateways")
    raw["vpn_gateways"] = {}
    try:
        for vgw in ec2.describe_vpn_gateways().get("VpnGateways", []):
            gid = vgw["VpnGatewayId"]
            raw["vpn_gateways"][gid] = {
                "gateway":      vgw,
                "state":        vgw.get("State"),
                "type":         vgw.get("Type"),
                "attachments":  vgw.get("VpcAttachments", []),
                "tags":         {t["Key"]: t["Value"] for t in vgw.get("Tags", [])},
            }
    except Exception as e:
        errors.append(f"describe_vpn_gateways: {e}")
        logger.error(f"VPC: error listando VPN Gateways — {e}")

    # ── 5. Customer Gateways ──────────────────────────────────────────────────
    logger.info("VPC: recopilando Customer Gateways")
    raw["customer_gateways"] = {}
    try:
        for cgw in ec2.describe_customer_gateways().get("CustomerGateways", []):
            cid = cgw["CustomerGatewayId"]
            raw["customer_gateways"][cid] = {
                "gateway":    cgw,
                "state":      cgw.get("State"),
                "type":       cgw.get("Type"),
                "ip_address": cgw.get("IpAddress"),
                "bgp_asn":    cgw.get("BgpAsn"),
                "tags":       {t["Key"]: t["Value"] for t in cgw.get("Tags", [])},
            }
    except Exception as e:
        errors.append(f"describe_customer_gateways: {e}")
        logger.error(f"VPC: error listando Customer Gateways — {e}")

    # ── 6. Site-to-Site VPN connections ───────────────────────────────────────
    logger.info("VPC: recopilando VPN connections")
    raw["vpn_connections"] = {}
    try:
        for vpn in ec2.describe_vpn_connections().get("VpnConnections", []):
            vid = vpn["VpnConnectionId"]
            tunnels = vpn.get("VgwTelemetry", [])
            raw["vpn_connections"][vid] = {
                "connection":       vpn,
                "state":            vpn.get("State"),
                "type":             vpn.get("Type"),
                "vpn_gateway_id":   vpn.get("VpnGatewayId"),
                "customer_gateway_id": vpn.get("CustomerGatewayId"),
                "tunnels":          [
                    {
                        "outside_ip":    t.get("OutsideIpAddress"),
                        "status":        t.get("Status"),
                        "status_message": t.get("StatusMessage"),
                        "accepted_routes": t.get("AcceptedRouteCount", 0),
                    }
                    for t in tunnels
                ],
                "tunnels_up":       sum(1 for t in tunnels if t.get("Status") == "UP"),
                "tunnels_down":     sum(1 for t in tunnels if t.get("Status") == "DOWN"),
                "tags":             {t["Key"]: t["Value"] for t in vpn.get("Tags", [])},
            }
    except Exception as e:
        errors.append(f"describe_vpn_connections: {e}")
        logger.error(f"VPC: error listando VPN connections — {e}")

    # ── 7. Direct Connect ─────────────────────────────────────────────────────
    logger.info("VPC: recopilando Direct Connect")
    raw["direct_connect"] = {"connections": {}, "virtual_interfaces": {}}
    try:
        dx = get_client("directconnect", session)

        for conn in dx.describe_connections().get("connections", []):
            cid = conn["connectionId"]
            raw["direct_connect"]["connections"][cid] = {
                "connection":  conn,
                "name":        conn.get("connectionName"),
                "state":       conn.get("connectionState"),
                "bandwidth":   conn.get("bandwidth"),
                "location":    conn.get("location"),
            }

        for vif in dx.describe_virtual_interfaces().get("virtualInterfaces", []):
            vid = vif["virtualInterfaceId"]
            raw["direct_connect"]["virtual_interfaces"][vid] = {
                "vif":          vif,
                "name":         vif.get("virtualInterfaceName"),
                "type":         vif.get("virtualInterfaceType"),
                "state":        vif.get("virtualInterfaceState"),
                "vlan":         vif.get("vlan"),
                "amazon_side_asn": vif.get("amazonSideAsn"),
                "customer_asn":    vif.get("asn"),
            }
    except Exception as e:
        errors.append(f"direct_connect: {e}")
        logger.error(f"VPC: error obteniendo Direct Connect — {e}")

    # ── 8. VPC Endpoints con políticas ────────────────────────────────────────
    logger.info("VPC: recopilando VPC Endpoints con políticas")
    raw["vpc_endpoints"] = {}
    try:
        paginator = ec2.get_paginator("describe_vpc_endpoints")
        for page in paginator.paginate():
            for ep in page["VpcEndpoints"]:
                epid = ep["VpcEndpointId"]
                policy_doc = ep.get("PolicyDocument", "{}")

                # Detectar política permisiva (Principal: * sin condiciones)
                is_open_policy = False
                try:
                    import json
                    policy = json.loads(policy_doc)
                    for stmt in policy.get("Statement", []):
                        principal = stmt.get("Principal", "")
                        if principal == "*" or principal == {"AWS": "*"}:
                            if not stmt.get("Condition"):
                                is_open_policy = True
                                break
                except Exception:
                    pass

                raw["vpc_endpoints"][epid] = {
                    "endpoint":        ep,
                    "vpc_id":          ep.get("VpcId"),
                    "service_name":    ep.get("ServiceName"),
                    "type":            ep.get("VpcEndpointType"),
                    "state":           ep.get("State"),
                    "policy_document": policy_doc,
                    "is_open_policy":  is_open_policy,
                    "route_table_ids": ep.get("RouteTableIds", []),
                    "subnet_ids":      ep.get("SubnetIds", []),
                }
    except Exception as e:
        errors.append(f"describe_vpc_endpoints: {e}")
        logger.error(f"VPC: error listando VPC Endpoints — {e}")

    # ── 9. PrivateLink services expuestos ─────────────────────────────────────
    logger.info("VPC: recopilando PrivateLink services")
    raw["privatelink_services"] = {}
    try:
        paginator = ec2.get_paginator("describe_vpc_endpoint_services")
        for page in paginator.paginate(Filters=[{"Name": "owner", "Values": [account_id]}]):
            for svc in page["ServiceDetails"]:
                sname = svc.get("ServiceName", "")
                raw["privatelink_services"][sname] = {
                    "service":              svc,
                    "type":                 svc.get("ServiceType", [{}])[0].get("ServiceType"),
                    "availability_zones":   svc.get("AvailabilityZones", []),
                    "acceptance_required":  svc.get("AcceptanceRequired", False),
                    "manages_vpc_endpoints": svc.get("ManagesVpcEndpoints", False),
                }
    except Exception as e:
        errors.append(f"describe_vpc_endpoint_services: {e}")
        logger.error(f"VPC: error listando PrivateLink services — {e}")

    # ── 10. DHCP option sets ──────────────────────────────────────────────────
    logger.info("VPC: recopilando DHCP option sets")
    raw["dhcp_option_sets"] = {}
    try:
        paginator = ec2.get_paginator("describe_dhcp_options")
        for page in paginator.paginate():
            for dhcp in page["DhcpOptions"]:
                did = dhcp["DhcpOptionsId"]
                configs = {}
                for config in dhcp.get("DhcpConfigurations", []):
                    key    = config.get("Key")
                    values = [v.get("Value") for v in config.get("Values", [])]
                    configs[key] = values

                raw["dhcp_option_sets"][did] = {
                    "options":          dhcp,
                    "configurations":   configs,
                    "domain_name":      configs.get("domain-name", []),
                    "dns_servers":      configs.get("domain-name-servers", []),
                    "uses_custom_dns":  configs.get("domain-name-servers", []) != ["AmazonProvidedDNS"],
                    "tags":             {t["Key"]: t["Value"] for t in dhcp.get("Tags", [])},
                }
    except Exception as e:
        errors.append(f"describe_dhcp_options: {e}")
        logger.error(f"VPC: error listando DHCP option sets — {e}")

    # ── 11. Route 53 Resolver ─────────────────────────────────────────────────
    logger.info("VPC: recopilando Route 53 Resolver rules")
    raw["resolver"] = {"rules": {}, "endpoints": {}}
    try:
        r53r = get_client("route53resolver", session)

        # Resolver rules
        paginator = r53r.get_paginator("list_resolver_rules")
        for page in paginator.paginate():
            for rule in page["ResolverRules"]:
                rid = rule["Id"]
                raw["resolver"]["rules"][rid] = {
                    "rule":          rule,
                    "name":          rule.get("Name"),
                    "domain_name":   rule.get("DomainName"),
                    "rule_type":     rule.get("RuleType"),
                    "status":        rule.get("Status"),
                    "target_ips":    [t.get("Ip") for t in rule.get("TargetIps", [])],
                    "share_status":  rule.get("ShareStatus"),
                }

        # Resolver endpoints
        paginator = r53r.get_paginator("list_resolver_endpoints")
        for page in paginator.paginate():
            for ep in page["ResolverEndpoints"]:
                eid = ep["Id"]
                raw["resolver"]["endpoints"][eid] = {
                    "endpoint":      ep,
                    "name":          ep.get("Name"),
                    "direction":     ep.get("Direction"),
                    "status":        ep.get("Status"),
                    "ip_count":      ep.get("IpAddressCount", 0),
                    "vpc_id":        ep.get("HostVPCId"),
                }

    except Exception as e:
        errors.append(f"route53resolver: {e}")
        logger.error(f"VPC: error obteniendo Route 53 Resolver — {e}")

    # ── 12. Enrichments ───────────────────────────────────────────────────────
    logger.info("VPC: calculando enrichments")
    try:
        _enrich(raw, errors)
    except Exception as e:
        errors.append(f"enrichments: {e}")
        logger.error(f"VPC: error en enrichments — {e}")

    logger.info(
        f"VPC: recolección completa — "
        f"{len(raw['vpcs'])} VPCs, "
        f"{len(raw['flow_logs'])} flow logs, "
        f"{len(raw['peering_connections'])} peerings, "
        f"{len(raw['vpn_connections'])} VPN connections, "
        f"{len(raw['vpc_endpoints'])} endpoints, "
        f"{len(errors)} errores"
    )

    return CollectorOutput(
        service="vpc",
        account_id=account_id,
        region=region,
        raw_data=raw,
        errors=errors,
    )


def _enrich(raw: dict, errors: list[str]) -> None:
    """
    Calcula métricas derivadas:
      - VPCs sin flow logs o sin cobertura ALL
      - VPCs default en uso
      - Peerings cross-account o cross-region
      - VPN tunnels caídos
      - Endpoints con política abierta
      - DHCP con DNS custom
      - Resumen global de postura de red
    """
    # CIDR overlap entre VPCs
    import ipaddress

    vpc_cidrs = {}
    for vid, vpc_data in raw.get("vpcs", {}).items():
        try:
            cidr = vpc_data.get("cidr")
            if cidr:
                vpc_cidrs[vid] = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            pass

    overlapping_pairs = []
    vpc_ids = list(vpc_cidrs.keys())
    for i in range(len(vpc_ids)):
        for j in range(i + 1, len(vpc_ids)):
            va, vb = vpc_ids[i], vpc_ids[j]
            try:
                if vpc_cidrs[va].overlaps(vpc_cidrs[vb]):
                    overlapping_pairs.append((va, vb))
            except Exception:
                pass

    raw["overlapping_cidrs"] = overlapping_pairs

    # Flags por VPC
    for vid, vpc_data in raw.get("vpcs", {}).items():
        try:
            vpc_data["flow_logs_compliant"] = (
                vpc_data.get("has_flow_logs", False) and
                vpc_data.get("flow_logs_all_traffic", False)
            )
            vpc_data["is_default_in_use"] = vpc_data.get("is_default", False)
        except Exception as e:
            errors.append(f"enrich_vpc:{vid}: {e}")

    # VPN tunnels caídos
    for vpn_id, vpn_data in raw.get("vpn_connections", {}).items():
        try:
            vpn_data["has_tunnel_down"] = vpn_data.get("tunnels_down", 0) > 0
            vpn_data["fully_operational"] = (
                vpn_data.get("tunnels_up", 0) > 0 and
                vpn_data.get("tunnels_down", 0) == 0
            )
        except Exception as e:
            errors.append(f"enrich_vpn:{vpn_id}: {e}")

    # Resumen global
    raw["summary"] = {
        "total_vpcs":                   len(raw.get("vpcs", {})),
        "default_vpcs":                 sum(1 for v in raw.get("vpcs", {}).values() if v.get("is_default")),
        "vpcs_without_flow_logs":       sum(1 for v in raw.get("vpcs", {}).values() if not v.get("has_flow_logs")),
        "vpcs_without_all_traffic_logs": sum(1 for v in raw.get("vpcs", {}).values() if not v.get("flow_logs_all_traffic")),
        "overlapping_cidr_pairs":       len(overlapping_pairs),
        "total_peerings":               len(raw.get("peering_connections", {})),
        "cross_account_peerings":       sum(1 for p in raw.get("peering_connections", {}).values() if p.get("is_cross_account")),
        "cross_region_peerings":        sum(1 for p in raw.get("peering_connections", {}).values() if p.get("is_cross_region")),
        "total_vpn_connections":        len(raw.get("vpn_connections", {})),
        "vpn_tunnels_down":             sum(1 for v in raw.get("vpn_connections", {}).values() if v.get("has_tunnel_down")),
        "total_dx_connections":         len(raw.get("direct_connect", {}).get("connections", {})),
        "total_endpoints":              len(raw.get("vpc_endpoints", {})),
        "endpoints_open_policy":        sum(1 for e in raw.get("vpc_endpoints", {}).values() if e.get("is_open_policy")),
        "privatelink_services":         len(raw.get("privatelink_services", {})),
        "dhcp_with_custom_dns":         sum(1 for d in raw.get("dhcp_option_sets", {}).values() if d.get("uses_custom_dns")),
        "resolver_rules":               len(raw.get("resolver", {}).get("rules", {})),
        "resolver_endpoints":           len(raw.get("resolver", {}).get("endpoints", {})),
    }