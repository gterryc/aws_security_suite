import boto3
import json

from schemas.collector_output import CollectorOutput
from utils.aws_session import get_client, get_account_id, get_region
from utils.logger import get_logger

logger = get_logger(__name__)

# ── Patrones CIS 4.x ──────────────────────────────────────────────────────────
# Cada control define el patrón exacto que debe existir como metric filter
# en un log group conectado a CloudTrail.
CIS_METRIC_FILTERS = {
    "CIS-4.1": {
        "name":        "Root account usage",
        "pattern":     '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }',
    },
    "CIS-4.2": {
        "name":        "Console login without MFA",
        "pattern":     '{ $.eventName = "ConsoleLogin" && $.additionalEventData.MFAUsed != "Yes" }',
    },
    "CIS-4.3": {
        "name":        "IAM policy changes",
        "pattern":     '{ $.eventSource = "iam.amazonaws.com" && ($.eventName = "DeleteGroupPolicy" || $.eventName = "DeleteRolePolicy" || $.eventName = "DeleteUserPolicy" || $.eventName = "PutGroupPolicy" || $.eventName = "PutRolePolicy" || $.eventName = "PutUserPolicy" || $.eventName = "CreatePolicy" || $.eventName = "DeletePolicy" || $.eventName = "CreatePolicyVersion" || $.eventName = "DeletePolicyVersion" || $.eventName = "SetDefaultPolicyVersion" || $.eventName = "AttachRolePolicy" || $.eventName = "DetachRolePolicy" || $.eventName = "AttachUserPolicy" || $.eventName = "DetachUserPolicy" || $.eventName = "AttachGroupPolicy" || $.eventName = "DetachGroupPolicy") }',
    },
    "CIS-4.4": {
        "name":        "CloudTrail configuration changes",
        "pattern":     '{ $.eventName = "CreateTrail" || $.eventName = "UpdateTrail" || $.eventName = "DeleteTrail" || $.eventName = "StartLogging" || $.eventName = "StopLogging" }',
    },
    "CIS-4.5": {
        "name":        "Console login failures",
        "pattern":     '{ $.eventName = "ConsoleLogin" && $.errorMessage = "Failed authentication" }',
    },
    "CIS-4.6": {
        "name":        "Disabled or deleted CMK usage",
        "pattern":     '{ $.eventSource = "kms.amazonaws.com" && ($.eventName = "DisableKey" || $.eventName = "ScheduleKeyDeletion") }',
    },
    "CIS-4.7": {
        "name":        "S3 bucket policy changes",
        "pattern":     '{ $.eventSource = "s3.amazonaws.com" && ($.eventName = "PutBucketAcl" || $.eventName = "PutBucketPolicy" || $.eventName = "PutBucketCors" || $.eventName = "PutBucketLifecycle" || $.eventName = "PutBucketReplication" || $.eventName = "DeleteBucketPolicy" || $.eventName = "DeleteBucketCors" || $.eventName = "DeleteBucketLifecycle" || $.eventName = "DeleteBucketReplication") }',
    },
    "CIS-4.8": {
        "name":        "AWS Config changes",
        "pattern":     '{ $.eventSource = "config.amazonaws.com" && ($.eventName = "StopConfigurationRecorder" || $.eventName = "DeleteDeliveryChannel" || $.eventName = "PutDeliveryChannel" || $.eventName = "PutConfigurationRecorder") }',
    },
    "CIS-4.9": {
        "name":        "Security group changes",
        "pattern":     '{ $.eventName = "AuthorizeSecurityGroupIngress" || $.eventName = "AuthorizeSecurityGroupEgress" || $.eventName = "RevokeSecurityGroupIngress" || $.eventName = "RevokeSecurityGroupEgress" || $.eventName = "CreateSecurityGroup" || $.eventName = "DeleteSecurityGroup" }',
    },
    "CIS-4.10": {
        "name":        "NACL changes",
        "pattern":     '{ $.eventName = "CreateNetworkAcl" || $.eventName = "CreateNetworkAclEntry" || $.eventName = "DeleteNetworkAcl" || $.eventName = "DeleteNetworkAclEntry" || $.eventName = "ReplaceNetworkAclEntry" || $.eventName = "ReplaceNetworkAclAssociation" }',
    },
    "CIS-4.11": {
        "name":        "Network gateway changes",
        "pattern":     '{ $.eventName = "CreateCustomerGateway" || $.eventName = "DeleteCustomerGateway" || $.eventName = "AttachInternetGateway" || $.eventName = "CreateInternetGateway" || $.eventName = "DeleteInternetGateway" || $.eventName = "DetachInternetGateway" }',
    },
    "CIS-4.12": {
        "name":        "Route table changes",
        "pattern":     '{ $.eventName = "CreateRoute" || $.eventName = "CreateRouteTable" || $.eventName = "ReplaceRoute" || $.eventName = "ReplaceRouteTableAssociation" || $.eventName = "DeleteRouteTable" || $.eventName = "DeleteRoute" || $.eventName = "DisassociateRouteTable" }',
    },
    "CIS-4.13": {
        "name":        "VPC changes",
        "pattern":     '{ $.eventName = "CreateVpc" || $.eventName = "DeleteVpc" || $.eventName = "ModifyVpcAttribute" || $.eventName = "AcceptVpcPeeringConnection" || $.eventName = "CreateVpcPeeringConnection" || $.eventName = "DeleteVpcPeeringConnection" || $.eventName = "RejectVpcPeeringConnection" || $.eventName = "AttachClassicLinkVpc" || $.eventName = "DetachClassicLinkVpc" || $.eventName = "DisableVpcClassicLink" || $.eventName = "EnableVpcClassicLink" }',
    },
    "CIS-4.14": {
        "name":        "AWS Organizations changes",
        "pattern":     '{ $.eventSource = "organizations.amazonaws.com" && ($.eventName = "AcceptHandshake" || $.eventName = "AttachPolicy" || $.eventName = "CreateAccount" || $.eventName = "CreateOrganizationalUnit" || $.eventName = "CreatePolicy" || $.eventName = "DeclineHandshake" || $.eventName = "DeleteOrganization" || $.eventName = "DeleteOrganizationalUnit" || $.eventName = "DeletePolicy" || $.eventName = "DetachPolicy" || $.eventName = "DisablePolicyType" || $.eventName = "EnablePolicyType" || $.eventName = "InviteAccountToOrganization" || $.eventName = "LeaveOrganization" || $.eventName = "MoveAccount" || $.eventName = "RemoveAccountFromOrganization" || $.eventName = "UpdatePolicy" || $.eventName = "UpdateOrganizationalUnit") }',
    },
    "CIS-4.15": {
        "name":        "AWS Config configuration changes",
        "pattern":     '{ $.eventSource = "config.amazonaws.com" && ($.eventName = "PutConfigRule" || $.eventName = "DeleteConfigRule" || $.eventName = "DeleteConfigurationRecorder" || $.eventName = "DeleteDeliveryChannel" || $.eventName = "DeleteEvaluationResults") }',
    },
}


def collect(session: boto3.Session) -> CollectorOutput:
    """
    [COL-06] Recopila configuración CloudWatch relevante para auditoría CIS/WAF.
    """
    cw         = get_client("cloudwatch", session)
    logs       = get_client("logs", session)
    ct         = get_client("cloudtrail", session)
    account_id = get_account_id(session)
    region     = get_region(session)
    errors: list[str] = []
    raw: dict  = {}

    # ── 1. CloudTrail trails ──────────────────────────────────────────────────
    logger.info("CloudWatch: recopilando trails de CloudTrail")
    raw["cloudtrail_trails"] = {}
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        for trail in trails:
            tname = trail["Name"]
            trail_data = {
                "trail":                trail,
                "name":                 tname,
                "is_multi_region":      trail.get("IsMultiRegionTrail", False),
                "log_group_arn":        trail.get("CloudWatchLogsLogGroupArn"),
                "log_group_name":       None,
                "log_role_arn":         trail.get("CloudWatchLogsRoleArn"),
                "kms_key_id":           trail.get("KMSKeyId"),
                "has_log_validation":   trail.get("LogFileValidationEnabled", False),
                "s3_bucket":            trail.get("S3BucketName"),
                "status":               {},
            }

            # Extraer nombre del log group del ARN
            log_group_arn = trail.get("CloudWatchLogsLogGroupArn", "")
            if log_group_arn:
                trail_data["log_group_name"] = log_group_arn.split(":log-group:")[-1].split(":")[0]

            # Estado del trail
            try:
                status = ct.get_trail_status(Name=tname)
                trail_data["status"] = {
                    "is_logging":               status.get("IsLogging", False),
                    "latest_delivery_time":     str(status.get("LatestDeliveryTime", "")),
                    "latest_cloudwatch_time":   str(status.get("LatestCloudWatchLogsDeliveryTime", "")),
                }
            except Exception as e:
                errors.append(f"trail_status:{tname}: {e}")

            raw["cloudtrail_trails"][tname] = trail_data

    except Exception as e:
        errors.append(f"describe_trails: {e}")
        logger.error(f"CloudWatch: error obteniendo trails — {e}")

    # ── 2. Log groups ─────────────────────────────────────────────────────────
    logger.info("CloudWatch: recopilando log groups")
    raw["log_groups"] = {}
    try:
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for lg in page["logGroups"]:
                lgname = lg["logGroupName"]
                raw["log_groups"][lgname] = {
                    "log_group":         lg,
                    "retention_days":    lg.get("retentionInDays"),
                    "kms_key_id":        lg.get("kmsKeyId"),
                    "stored_bytes":      lg.get("storedBytes", 0),
                    "metric_filters":    [],
                }
    except Exception as e:
        errors.append(f"describe_log_groups: {e}")
        logger.error(f"CloudWatch: error listando log groups — {e}")

    # ── 3. Metric filters por log group ───────────────────────────────────────
    logger.info("CloudWatch: recopilando metric filters")
    try:
        paginator = logs.get_paginator("describe_metric_filters")
        for page in paginator.paginate():
            for mf in page["metricFilters"]:
                lgname = mf.get("logGroupName", "")
                if lgname in raw["log_groups"]:
                    raw["log_groups"][lgname]["metric_filters"].append({
                        "name":            mf.get("filterName"),
                        "pattern":         mf.get("filterPattern"),
                        "metric_name":     mf.get("metricTransformations", [{}])[0].get("metricName"),
                        "metric_namespace": mf.get("metricTransformations", [{}])[0].get("metricNamespace"),
                    })
    except Exception as e:
        errors.append(f"describe_metric_filters: {e}")
        logger.error(f"CloudWatch: error listando metric filters — {e}")

    # ── 4. Alarmas ────────────────────────────────────────────────────────────
    logger.info("CloudWatch: recopilando alarmas")
    raw["alarms"] = {}
    try:
        paginator = cw.get_paginator("describe_alarms")
        for page in paginator.paginate():
            for alarm in page["MetricAlarms"]:
                aname = alarm["AlarmName"]
                raw["alarms"][aname] = {
                    "alarm":           alarm,
                    "state":           alarm.get("StateValue"),
                    "metric_name":     alarm.get("MetricName"),
                    "namespace":       alarm.get("Namespace"),
                    "actions":         alarm.get("AlarmActions", []),
                    "ok_actions":      alarm.get("OKActions", []),
                    "has_actions":     len(alarm.get("AlarmActions", [])) > 0,
                    "metric_filters":  [],
                }
    except Exception as e:
        errors.append(f"describe_alarms: {e}")
        logger.error(f"CloudWatch: error listando alarmas — {e}")

    # ── 5. Verificación de controles CIS 4.x ──────────────────────────────────
    logger.info("CloudWatch: verificando controles CIS 4.x")
    raw["cis_controls"] = {}
    try:
        _check_cis_controls(raw, errors)
    except Exception as e:
        errors.append(f"cis_controls: {e}")
        logger.error(f"CloudWatch: error verificando controles CIS — {e}")

    # ── 6. Enrichments ────────────────────────────────────────────────────────
    logger.info("CloudWatch: calculando enrichments")
    try:
        _enrich(raw, errors)
    except Exception as e:
        errors.append(f"enrichments: {e}")
        logger.error(f"CloudWatch: error en enrichments — {e}")

    passing = sum(1 for c in raw.get("cis_controls", {}).values() if c.get("compliant"))
    logger.info(
        f"CloudWatch: recolección completa — "
        f"{len(raw.get('cloudtrail_trails', {}))} trails, "
        f"{len(raw.get('log_groups', {}))} log groups, "
        f"{len(raw.get('alarms', {}))} alarmas, "
        f"CIS 4.x: {passing}/{len(CIS_METRIC_FILTERS)} controles passing, "
        f"{len(errors)} errores"
    )

    return CollectorOutput(
        service="cloudwatch",
        account_id=account_id,
        region=region,
        raw_data=raw,
        errors=errors,
    )


def _check_cis_controls(raw: dict, errors: list[str]) -> None:
    """
    Verifica cada control CIS 4.x buscando:
    1. Un log group conectado a un trail de CloudTrail activo
    2. Un metric filter con patrón equivalente en ese log group
    3. Una alarma conectada a ese metric filter con al menos una acción SNS
    """
    # Construir índice: metric_name → alarm
    metric_to_alarm: dict[str, dict] = {}
    for alarm in raw.get("alarms", {}).values():
        mname = alarm.get("metric_name")
        if mname:
            metric_to_alarm[mname] = alarm

    # Log groups conectados a trails activos
    active_trail_log_groups: set[str] = set()
    for trail in raw.get("cloudtrail_trails", {}).values():
        if trail.get("status", {}).get("is_logging") and trail.get("log_group_name"):
            active_trail_log_groups.add(trail["log_group_name"])

    for control_id, control_def in CIS_METRIC_FILTERS.items():
        result = {
            "control_id":      control_id,
            "name":            control_def["name"],
            "expected_pattern": control_def["pattern"],
            "compliant":       False,
            "log_group":       None,
            "metric_filter":   None,
            "alarm":           None,
            "alarm_has_action": False,
            "failure_reason":  None,
        }

        # Buscar metric filter que coincida con el patrón en log groups activos
        found_filter = None
        found_lg     = None

        for lgname, lg_data in raw.get("log_groups", {}).items():
            if lgname not in active_trail_log_groups:
                continue
            for mf in lg_data.get("metric_filters", []):
                if _patterns_match(mf.get("pattern", ""), control_def["pattern"]):
                    found_filter = mf
                    found_lg     = lgname
                    break
            if found_filter:
                break

        if not found_filter:
            result["failure_reason"] = "No metric filter found matching CIS pattern in active CloudTrail log group"
            raw["cis_controls"][control_id] = result
            continue

        result["log_group"]     = found_lg
        result["metric_filter"] = found_filter

        # Buscar alarma conectada a ese metric filter
        metric_name  = found_filter.get("metric_name")
        linked_alarm = metric_to_alarm.get(metric_name)

        if not linked_alarm:
            result["failure_reason"] = f"Metric filter exists but no alarm linked to metric '{metric_name}'"
            raw["cis_controls"][control_id] = result
            continue

        result["alarm"] = linked_alarm

        # Verificar que la alarma tiene al menos una acción SNS
        has_action = linked_alarm.get("has_actions", False)
        result["alarm_has_action"] = has_action

        if not has_action:
            result["failure_reason"] = "Alarm exists but has no notification actions configured"
            raw["cis_controls"][control_id] = result
            continue

        result["compliant"] = True
        raw["cis_controls"][control_id] = result


def _patterns_match(actual: str, expected: str) -> bool:
    """
    Comparación flexible de patrones de metric filters.
    Normaliza espacios y compara los event names clave en lugar
    de hacer match exacto de strings, ya que AWS puede formatear
    el patrón de forma ligeramente distinta al guardarlo.
    """
    def normalize(p: str) -> set[str]:
        import re
        tokens = re.findall(r'"([^"]+)"', p)
        return set(tokens)

    return bool(normalize(actual) & normalize(expected))


def _enrich(raw: dict, errors: list[str]) -> None:
    """
    Calcula métricas derivadas:
      - Trails sin CloudWatch Logs conectado
      - Log groups sin retention
      - Log groups sin KMS
      - Alarmas en estado ALARM o INSUFFICIENT_DATA
      - Alarmas sin acciones
      - Resumen global CIS 4.x
    """
    # Trails
    for tname, trail in raw.get("cloudtrail_trails", {}).items():
        try:
            trail["has_cloudwatch_logs"] = bool(trail.get("log_group_name"))
            trail["is_logging"]          = trail.get("status", {}).get("is_logging", False)
            trail["compliant"]           = (
                trail["has_cloudwatch_logs"] and
                trail["is_logging"] and
                trail.get("is_multi_region", False) and
                trail.get("has_log_validation", False)
            )
        except Exception as e:
            errors.append(f"enrich_trail:{tname}: {e}")

    # Log groups
    for lgname, lg in raw.get("log_groups", {}).items():
        try:
            lg["has_retention"]   = lg.get("retention_days") is not None
            lg["has_kms"]         = bool(lg.get("kms_key_id"))
            lg["has_metric_filters"] = len(lg.get("metric_filters", [])) > 0
        except Exception as e:
            errors.append(f"enrich_lg:{lgname}: {e}")

    # Alarmas
    alarms_in_alarm       = []
    alarms_insufficient   = []
    alarms_without_action = []

    for aname, alarm in raw.get("alarms", {}).items():
        try:
            if alarm.get("state") == "ALARM":
                alarms_in_alarm.append(aname)
            elif alarm.get("state") == "INSUFFICIENT_DATA":
                alarms_insufficient.append(aname)
            if not alarm.get("has_actions"):
                alarms_without_action.append(aname)
        except Exception as e:
            errors.append(f"enrich_alarm:{aname}: {e}")

    # Resumen CIS
    cis_passing = [cid for cid, c in raw.get("cis_controls", {}).items() if c.get("compliant")]
    cis_failing = [cid for cid, c in raw.get("cis_controls", {}).items() if not c.get("compliant")]

    raw["summary"] = {
        "total_trails":               len(raw.get("cloudtrail_trails", {})),
        "trails_with_cloudwatch":     sum(1 for t in raw.get("cloudtrail_trails", {}).values() if t.get("has_cloudwatch_logs")),
        "trails_logging":             sum(1 for t in raw.get("cloudtrail_trails", {}).values() if t.get("is_logging")),
        "total_log_groups":           len(raw.get("log_groups", {})),
        "log_groups_without_retention": sum(1 for lg in raw.get("log_groups", {}).values() if not lg.get("has_retention")),
        "log_groups_without_kms":     sum(1 for lg in raw.get("log_groups", {}).values() if not lg.get("has_kms")),
        "total_alarms":               len(raw.get("alarms", {})),
        "alarms_in_alarm_state":      alarms_in_alarm,
        "alarms_insufficient_data":   alarms_insufficient,
        "alarms_without_action":      alarms_without_action,
        "cis_4x_passing":             cis_passing,
        "cis_4x_failing":             cis_failing,
        "cis_4x_score":               round(len(cis_passing) / len(CIS_METRIC_FILTERS) * 100, 1),
    }