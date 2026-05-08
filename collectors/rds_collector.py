import boto3

from schemas.collector_output import CollectorOutput
from utils.aws_session import get_client, get_account_id, get_region
from utils.logger import get_logger

logger = get_logger(__name__)


def collect(session: boto3.Session) -> CollectorOutput:
    """
    [COL-04] Recopila configuración RDS relevante para auditoría CIS/WAF:
      - Instancias DB: encriptación, acceso público, multi-AZ, backups
      - Clusters Aurora: encriptación, multi-AZ, backups
      - Snapshots: visibilidad pública, encriptación
      - Security groups asociados
      - Parameter groups: configuraciones de seguridad
      - Option groups
      - Subnet groups: subnets asociadas
      - Event subscriptions
      - Logs habilitados por instancia
      - IAM authentication
      - Performance Insights
      - Auto minor version upgrade
      - Deletion protection
    """
    rds        = get_client("rds", session)
    account_id = get_account_id(session)
    region     = get_region(session)
    errors: list[str] = []
    raw: dict  = {}

    # ── 1. Instancias DB ──────────────────────────────────────────────────────
    logger.info("RDS: recopilando instancias DB")
    raw["instances"] = {}
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                dbid = db["DBInstanceIdentifier"]
                raw["instances"][dbid] = {
                    "instance":                    db,
                    "engine":                      db.get("Engine"),
                    "engine_version":              db.get("EngineVersion"),
                    "instance_class":              db.get("DBInstanceClass"),
                    "status":                      db.get("DBInstanceStatus"),
                    "publicly_accessible":         db.get("PubliclyAccessible", False),
                    "encrypted":                   db.get("StorageEncrypted", False),
                    "kms_key_id":                  db.get("KmsKeyId"),
                    "multi_az":                    db.get("MultiAZ", False),
                    "backup_retention_days":       db.get("BackupRetentionPeriod", 0),
                    "deletion_protection":         db.get("DeletionProtection", False),
                    "iam_auth_enabled":            db.get("IAMDatabaseAuthenticationEnabled", False),
                    "performance_insights":        db.get("PerformanceInsightsEnabled", False),
                    "auto_minor_version_upgrade":  db.get("AutoMinorVersionUpgrade", False),
                    "ca_certificate":              db.get("CACertificateIdentifier"),
                    "subnet_group":                db.get("DBSubnetGroup", {}).get("DBSubnetGroupName"),
                    "security_groups":             [sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])],
                    "parameter_groups":            [pg["DBParameterGroupName"] for pg in db.get("DBParameterGroups", [])],
                    "option_groups":               [og["OptionGroupName"] for og in db.get("OptionGroupMemberships", [])],
                    "enabled_cloudwatch_logs":     db.get("EnabledCloudwatchLogsExports", []),
                    "cluster_id":                  db.get("DBClusterIdentifier"),
                    "tags":                        {t["Key"]: t["Value"] for t in db.get("TagList", [])},
                }
    except Exception as e:
        errors.append(f"describe_db_instances: {e}")
        logger.error(f"RDS: error listando instancias — {e}")

    # ── 2. Clusters Aurora ────────────────────────────────────────────────────
    logger.info("RDS: recopilando clusters Aurora")
    raw["clusters"] = {}
    try:
        paginator = rds.get_paginator("describe_db_clusters")
        for page in paginator.paginate():
            for cluster in page["DBClusters"]:
                cid = cluster["DBClusterIdentifier"]
                raw["clusters"][cid] = {
                    "cluster":                    cluster,
                    "engine":                     cluster.get("Engine"),
                    "engine_version":             cluster.get("EngineVersion"),
                    "status":                     cluster.get("Status"),
                    "encrypted":                  cluster.get("StorageEncrypted", False),
                    "kms_key_id":                 cluster.get("KmsKeyId"),
                    "multi_az":                   cluster.get("MultiAZ", False),
                    "backup_retention_days":      cluster.get("BackupRetentionPeriod", 0),
                    "deletion_protection":        cluster.get("DeletionProtection", False),
                    "iam_auth_enabled":           cluster.get("IAMDatabaseAuthenticationEnabled", False),
                    "publicly_accessible":        cluster.get("PubliclyAccessible", False),
                    "enabled_cloudwatch_logs":    cluster.get("EnabledCloudwatchLogsExports", []),
                    "members":                    [m["DBInstanceIdentifier"] for m in cluster.get("DBClusterMembers", [])],
                    "security_groups":            [sg["VpcSecurityGroupId"] for sg in cluster.get("VpcSecurityGroups", [])],
                    "tags":                       {t["Key"]: t["Value"] for t in cluster.get("TagList", [])},
                }
    except Exception as e:
        errors.append(f"describe_db_clusters: {e}")
        logger.error(f"RDS: error listando clusters — {e}")

    # ── 3. Snapshots — instancias ─────────────────────────────────────────────
    logger.info("RDS: recopilando snapshots de instancias")
    raw["snapshots"] = {}
    try:
        paginator = rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate(SnapshotType="manual"):
            for snap in page["DBSnapshots"]:
                sid = snap["DBSnapshotIdentifier"]
                snap_data = {
                    "snapshot":   snap,
                    "db_id":      snap.get("DBInstanceIdentifier"),
                    "engine":     snap.get("Engine"),
                    "encrypted":  snap.get("Encrypted", False),
                    "status":     snap.get("Status"),
                    "is_public":  False,
                }
                try:
                    attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=sid)
                    for attr in attrs.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", []):
                        if attr["AttributeName"] == "restore":
                            snap_data["is_public"] = "all" in attr.get("AttributeValues", [])
                except Exception as e:
                    errors.append(f"snapshot_attrs:{sid}: {e}")

                raw["snapshots"][sid] = snap_data
    except Exception as e:
        errors.append(f"describe_db_snapshots: {e}")
        logger.error(f"RDS: error listando snapshots — {e}")

    # ── 4. Snapshots — clusters ───────────────────────────────────────────────
    logger.info("RDS: recopilando snapshots de clusters")
    raw["cluster_snapshots"] = {}
    try:
        paginator = rds.get_paginator("describe_db_cluster_snapshots")
        for page in paginator.paginate(SnapshotType="manual"):
            for snap in page["DBClusterSnapshots"]:
                sid = snap["DBClusterSnapshotIdentifier"]
                snap_data = {
                    "snapshot":  snap,
                    "cluster_id": snap.get("DBClusterIdentifier"),
                    "engine":    snap.get("Engine"),
                    "encrypted": snap.get("StorageEncrypted", False),
                    "status":    snap.get("Status"),
                    "is_public": False,
                }
                try:
                    attrs = rds.describe_db_cluster_snapshot_attributes(DBClusterSnapshotIdentifier=sid)
                    for attr in attrs.get("DBClusterSnapshotAttributesResult", {}).get("DBClusterSnapshotAttributes", []):
                        if attr["AttributeName"] == "restore":
                            snap_data["is_public"] = "all" in attr.get("AttributeValues", [])
                except Exception as e:
                    errors.append(f"cluster_snapshot_attrs:{sid}: {e}")

                raw["cluster_snapshots"][sid] = snap_data
    except Exception as e:
        errors.append(f"describe_db_cluster_snapshots: {e}")
        logger.error(f"RDS: error listando cluster snapshots — {e}")

    # ── 5. Parameter groups ───────────────────────────────────────────────────
    logger.info("RDS: recopilando parameter groups")
    raw["parameter_groups"] = {}
    try:
        paginator = rds.get_paginator("describe_db_parameter_groups")
        for page in paginator.paginate():
            for pg in page["DBParameterGroups"]:
                pgname = pg["DBParameterGroupName"]
                if pgname.startswith("default."):
                    continue  # solo custom parameter groups

                pg_data = {"group": pg, "parameters": {}}
                SECURITY_PARAMS = {
                    "log_connections", "log_disconnections", "log_checkpoints",
                    "log_lock_waits", "log_min_duration_statement",
                    "require_secure_transport", "ssl", "rds.force_ssl",
                    "general_log", "slow_query_log", "audit_log",
                }
                try:
                    param_paginator = rds.get_paginator("describe_db_parameters")
                    for param_page in param_paginator.paginate(DBParameterGroupName=pgname):
                        for param in param_page["Parameters"]:
                            if param["ParameterName"] in SECURITY_PARAMS:
                                pg_data["parameters"][param["ParameterName"]] = param.get("ParameterValue")
                except Exception as e:
                    errors.append(f"db_parameters:{pgname}: {e}")

                raw["parameter_groups"][pgname] = pg_data
    except Exception as e:
        errors.append(f"describe_db_parameter_groups: {e}")
        logger.error(f"RDS: error listando parameter groups — {e}")

    # ── 6. Subnet groups ──────────────────────────────────────────────────────
    logger.info("RDS: recopilando subnet groups")
    raw["subnet_groups"] = {}
    try:
        paginator = rds.get_paginator("describe_db_subnet_groups")
        for page in paginator.paginate():
            for sg in page["DBSubnetGroups"]:
                sgname = sg["DBSubnetGroupName"]
                raw["subnet_groups"][sgname] = {
                    "group":   sg,
                    "vpc_id":  sg.get("VpcId"),
                    "subnets": [s["SubnetIdentifier"] for s in sg.get("Subnets", [])],
                    "status":  sg.get("SubnetGroupStatus"),
                }
    except Exception as e:
        errors.append(f"describe_db_subnet_groups: {e}")
        logger.error(f"RDS: error listando subnet groups — {e}")

    # ── 7. Event subscriptions ────────────────────────────────────────────────
    logger.info("RDS: recopilando event subscriptions")
    raw["event_subscriptions"] = {}
    try:
        paginator = rds.get_paginator("describe_event_subscriptions")
        for page in paginator.paginate():
            for sub in page["EventSubscriptionsList"]:
                subname = sub["CustSubscriptionId"]
                raw["event_subscriptions"][subname] = {
                    "subscription": sub,
                    "enabled":      sub.get("Enabled", False),
                    "source_type":  sub.get("SourceType"),
                    "event_categories": sub.get("EventCategoriesList", []),
                    "sns_topic":    sub.get("SnsTopicArn"),
                }
    except Exception as e:
        errors.append(f"describe_event_subscriptions: {e}")
        logger.error(f"RDS: error listando event subscriptions — {e}")

    # ── 8. Enrichments ────────────────────────────────────────────────────────
    logger.info("RDS: calculando enrichments")
    try:
        _enrich(raw, errors)
    except Exception as e:
        errors.append(f"enrichments: {e}")
        logger.error(f"RDS: error en enrichments — {e}")

    logger.info(
        f"RDS: recolección completa — "
        f"{len(raw['instances'])} instancias, "
        f"{len(raw['clusters'])} clusters, "
        f"{len(raw['snapshots'])} snapshots, "
        f"{len(raw['cluster_snapshots'])} cluster snapshots, "
        f"{len(raw['parameter_groups'])} parameter groups custom, "
        f"{len(errors)} errores"
    )

    return CollectorOutput(
        service="rds",
        account_id=account_id,
        region=region,
        raw_data=raw,
        errors=errors,
    )


def _enrich(raw: dict, errors: list[str]) -> None:
    """
    Calcula métricas derivadas:
      - Instancias sin encriptación, sin backups, sin multi-AZ
      - Instancias con acceso público
      - Logs de auditoría faltantes por motor
      - Snapshots públicos
      - Resumen global
    """
    REQUIRED_LOGS = {
        "mysql":       {"audit", "error", "general", "slowquery"},
        "postgres":    {"postgresql", "upgrade"},
        "mariadb":     {"audit", "error", "general", "slowquery"},
        "oracle-ee":   {"alert", "audit", "listener", "trace"},
        "sqlserver-ee":{"agent", "error"},
        "aurora-mysql":     {"audit", "error", "general", "slowquery"},
        "aurora-postgresql": {"postgresql"},
    }

    for dbid, db_data in raw.get("instances", {}).items():
        try:
            engine        = db_data.get("engine", "").lower()
            enabled_logs  = set(db_data.get("enabled_cloudwatch_logs", []))
            required_logs = REQUIRED_LOGS.get(engine, set())

            db_data["missing_logs"]          = sorted(required_logs - enabled_logs)
            db_data["backup_compliant"]      = db_data.get("backup_retention_days", 0) >= 7
            db_data["encryption_compliant"]  = db_data.get("encrypted", False)
            db_data["network_compliant"]     = not db_data.get("publicly_accessible", False)
            db_data["ha_compliant"]          = db_data.get("multi_az", False)
        except Exception as e:
            errors.append(f"enrich_instance:{dbid}: {e}")

    for cid, cluster_data in raw.get("clusters", {}).items():
        try:
            engine        = cluster_data.get("engine", "").lower()
            enabled_logs  = set(cluster_data.get("enabled_cloudwatch_logs", []))
            required_logs = REQUIRED_LOGS.get(engine, set())

            cluster_data["missing_logs"]         = sorted(required_logs - enabled_logs)
            cluster_data["backup_compliant"]     = cluster_data.get("backup_retention_days", 0) >= 7
            cluster_data["encryption_compliant"] = cluster_data.get("encrypted", False)
            cluster_data["ha_compliant"]         = cluster_data.get("multi_az", False)
        except Exception as e:
            errors.append(f"enrich_cluster:{cid}: {e}")

    raw["summary"] = {
        "total_instances":            len(raw.get("instances", {})),
        "total_clusters":             len(raw.get("clusters", {})),
        "publicly_accessible":        sum(1 for d in raw.get("instances", {}).values() if d.get("publicly_accessible")),
        "unencrypted_instances":      sum(1 for d in raw.get("instances", {}).values() if not d.get("encrypted")),
        "no_multi_az":                sum(1 for d in raw.get("instances", {}).values() if not d.get("multi_az")),
        "no_backup":                  sum(1 for d in raw.get("instances", {}).values() if not d.get("backup_compliant")),
        "no_deletion_protection":     sum(1 for d in raw.get("instances", {}).values() if not d.get("deletion_protection")),
        "no_iam_auth":                sum(1 for d in raw.get("instances", {}).values() if not d.get("iam_auth_enabled")),
        "missing_logs":               sum(1 for d in raw.get("instances", {}).values() if d.get("missing_logs")),
        "public_snapshots":           sum(1 for s in raw.get("snapshots", {}).values() if s.get("is_public")),
        "public_cluster_snapshots":   sum(1 for s in raw.get("cluster_snapshots", {}).values() if s.get("is_public")),
    }