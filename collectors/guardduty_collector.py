import boto3

from schemas.collector_output import CollectorOutput
from utils.aws_session import get_client, get_account_id, get_region
from utils.logger import get_logger

logger = get_logger(__name__)


def collect(session: boto3.Session) -> CollectorOutput:
    """
    [COL-05] Recopila configuración GuardDuty relevante para auditoría CIS/WAF:
      - Estado del detector (habilitado / deshabilitado)
      - Configuración del detector y frecuencia de exportación
      - Protection plans habilitados
      - Configuración de exportación a S3 / EventBridge
      - Master / member account (Organizations)
      - Findings activos por severidad
      - Estadísticas de findings por tipo
      - IP sets y threat intel sets configurados
    """
    gd         = get_client("guardduty", session)
    account_id = get_account_id(session)
    region     = get_region(session)
    errors: list[str] = []
    raw: dict  = {}

    # ── 1. Detectores ─────────────────────────────────────────────────────────
    logger.info("GuardDuty: verificando detectores")
    raw["detectors"] = {}
    raw["enabled"]   = False
    detector_ids: list[str] = []

    try:
        resp         = gd.list_detectors()
        detector_ids = resp.get("DetectorIds", [])
        raw["enabled"] = len(detector_ids) > 0

        if not raw["enabled"]:
            logger.warning("GuardDuty: no hay detectores habilitados en esta región")

    except Exception as e:
        errors.append(f"list_detectors: {e}")
        logger.error(f"GuardDuty: error listando detectores — {e}")

    for did in detector_ids:
        detector_data = {
            "detector_id":          did,
            "status":               None,
            "created_at":           None,
            "updated_at":           None,
            "finding_frequency":    None,
            "data_sources":         {},
            "features":             {},
            "export_config":        {},
            "master":               None,
            "members":              [],
            "ip_sets":              [],
            "threat_intel_sets":    [],
        }

        # ── 2. Detalle del detector ───────────────────────────────────────────
        try:
            det = gd.get_detector(DetectorId=did)
            detector_data["status"]            = det.get("Status")
            detector_data["created_at"]        = str(det.get("CreatedAt", ""))
            detector_data["updated_at"]        = str(det.get("UpdatedAt", ""))
            detector_data["finding_frequency"] = det.get("FindingPublishingFrequency")
            detector_data["data_sources"]      = det.get("DataSources", {})
            detector_data["features"]          = {
                f["Name"]: f["Status"]
                for f in det.get("Features", [])
            }
        except Exception as e:
            errors.append(f"get_detector:{did}: {e}")
            logger.error(f"GuardDuty: error obteniendo detector {did} — {e}")

        # ── 3. Configuración de exportación (S3 / EventBridge) ────────────────
        try:
            destinations = gd.list_publishing_destinations(DetectorId=did)
            dest_list    = destinations.get("Destinations", [])
            detector_data["export_config"] = {
                "Destinations": dest_list,
                "S3Destination": next(
                    (d for d in dest_list if d.get("DestinationType") == "S3"), None
                ),
            }
        except Exception as e:
            errors.append(f"export_config:{did}: {e}")
            logger.error(f"GuardDuty: error obteniendo export config — {e}")

        # ── 4. Master account (si es member en Organizations) ─────────────────
        try:
            master = gd.get_master_account(DetectorId=did)
            detector_data["master"] = master.get("Master")
        except gd.exceptions.BadRequestException:
            detector_data["master"] = None  # no está en una Organization
        except Exception as e:
            errors.append(f"master_account:{did}: {e}")

        # ── 5. Member accounts (si es master en Organizations) ────────────────
        try:
            paginator = gd.get_paginator("list_members")
            for page in paginator.paginate(DetectorId=did):
                detector_data["members"].extend(page.get("Members", []))
        except Exception as e:
            errors.append(f"list_members:{did}: {e}")

        # ── 6. IP sets ────────────────────────────────────────────────────────
        try:
            ip_resp = gd.list_ip_sets(DetectorId=did)
            for ipset_id in ip_resp.get("IpSetIds", []):
                try:
                    ipset = gd.get_ip_set(DetectorId=did, IpSetId=ipset_id)
                    detector_data["ip_sets"].append({
                        "id":     ipset_id,
                        "name":   ipset.get("Name"),
                        "format": ipset.get("Format"),
                        "status": ipset.get("Status"),
                    })
                except Exception as e:
                    errors.append(f"get_ip_set:{ipset_id}: {e}")
        except Exception as e:
            errors.append(f"list_ip_sets:{did}: {e}")

        # ── 7. Threat intel sets ──────────────────────────────────────────────
        try:
            ti_resp = gd.list_threat_intel_sets(DetectorId=did)
            for tiset_id in ti_resp.get("ThreatIntelSetIds", []):
                try:
                    tiset = gd.get_threat_intel_set(DetectorId=did, ThreatIntelSetId=tiset_id)
                    detector_data["threat_intel_sets"].append({
                        "id":     tiset_id,
                        "name":   tiset.get("Name"),
                        "format": tiset.get("Format"),
                        "status": tiset.get("Status"),
                    })
                except Exception as e:
                    errors.append(f"get_threat_intel_set:{tiset_id}: {e}")
        except Exception as e:
            errors.append(f"list_threat_intel_sets:{did}: {e}")

        # ── 8. Findings activos (MEDIUM, HIGH, CRITICAL) ──────────────────────
        logger.info(f"GuardDuty: recopilando findings activos del detector {did}")
        detector_data["findings"] = []
        try:
            # Filtrar findings no archivados con severidad >= 4 (MEDIUM+)
            finding_ids = []
            paginator = gd.get_paginator("list_findings")
            for page in paginator.paginate(
                DetectorId=did,
                FindingCriteria={
                    "Criterion": {
                        "severity": {"Gte": 4},
                        "service.archived": {"Eq": ["false"]},
                    }
                },
                SortCriteria={"AttributeName": "severity", "OrderBy": "DESC"},
            ):
                finding_ids.extend(page.get("FindingIds", []))

            # Obtener detalle en lotes de 50 (límite de la API)
            for i in range(0, len(finding_ids), 50):
                batch = finding_ids[i:i + 50]
                try:
                    findings_resp = gd.get_findings(DetectorId=did, FindingIds=batch)
                    for finding in findings_resp.get("Findings", []):
                        detector_data["findings"].append({
                            "id":          finding.get("Id"),
                            "type":        finding.get("Type"),
                            "severity":    finding.get("Severity"),
                            "title":       finding.get("Title"),
                            "description": finding.get("Description"),
                            "region":      finding.get("Region"),
                            "created_at":  str(finding.get("CreatedAt", "")),
                            "updated_at":  str(finding.get("UpdatedAt", "")),
                            "count":       finding.get("Service", {}).get("Count", 1),
                            "resource":    finding.get("Resource", {}),
                            "service":     finding.get("Service", {}),
                        })
                except Exception as e:
                    errors.append(f"get_findings_batch:{did}: {e}")

        except Exception as e:
            errors.append(f"list_findings:{did}: {e}")
            logger.error(f"GuardDuty: error listando findings — {e}")

        # ── 9. Estadísticas de findings por tipo y severidad ──────────────────
        try:
            stats = gd.get_findings_statistics(
                DetectorId=did,
                FindingStatisticTypes=["COUNT_BY_SEVERITY"],
                FindingCriteria={
                    "Criterion": {
                        "service.archived": {"Eq": ["false"]}
                    }
                },
            )
            detector_data["findings_statistics"] = stats.get("FindingStatistics", {})
        except Exception as e:
            errors.append(f"findings_statistics:{did}: {e}")
            detector_data["findings_statistics"] = {}

        raw["detectors"][did] = detector_data

    # ── 10. Enrichments ───────────────────────────────────────────────────────
    logger.info("GuardDuty: calculando enrichments")
    try:
        _enrich(raw, errors)
    except Exception as e:
        errors.append(f"enrichments: {e}")
        logger.error(f"GuardDuty: error en enrichments — {e}")

    total_findings = sum(
        len(d.get("findings", []))
        for d in raw["detectors"].values()
    )
    logger.info(
        f"GuardDuty: recolección completa — "
        f"habilitado: {raw['enabled']}, "
        f"{len(raw['detectors'])} detector(es), "
        f"{total_findings} findings activos, "
        f"{len(errors)} errores"
    )

    return CollectorOutput(
        service="guardduty",
        account_id=account_id,
        region=region,
        raw_data=raw,
        errors=errors,
    )


def _enrich(raw: dict, errors: list[str]) -> None:
    """
    Calcula métricas derivadas:
      - Protection plans habilitados / deshabilitados
      - Exportación configurada o no
      - Findings clasificados por banda de severidad
      - Resumen global de postura
    """
    PROTECTION_PLANS = {
        "S3_DATA_EVENTS",
        "EKS_AUDIT_LOGS",
        "EBS_MALWARE_PROTECTION",
        "RDS_LOGIN_EVENTS",
        "LAMBDA_NETWORK_LOGS",
        "RUNTIME_MONITORING",
    }

    SEVERITY_BANDS = {
        "critical": (9.0, 10.0),
        "high":     (7.0,  8.9),
        "medium":   (4.0,  6.9),
    }

    raw["summary"] = {
        "enabled":                   raw.get("enabled", False),
        "total_detectors":           len(raw.get("detectors", {})),
        "total_active_findings":     0,
        "findings_by_severity":      {"critical": 0, "high": 0, "medium": 0},
        "findings_by_type":          {},
        "protection_plans":          {},
        "export_configured":         False,
        "in_organization":           False,
        "missing_protection_plans":  [],
    }

    for did, det in raw.get("detectors", {}).items():
        try:
            # Protection plans
            features = det.get("features", {})
            enabled_plans  = {k for k, v in features.items() if v == "ENABLED"}
            disabled_plans = PROTECTION_PLANS - enabled_plans
            raw["summary"]["protection_plans"][did] = {
                "enabled":  sorted(enabled_plans & PROTECTION_PLANS),
                "disabled": sorted(disabled_plans),
            }
            raw["summary"]["missing_protection_plans"] = sorted(disabled_plans)

            # Exportación configurada
            exp = det.get("export_config", {})
            raw["summary"]["export_configured"] = bool(
                exp.get("S3Destination") or exp.get("ExternalDestination")
            )

            # Organizations
            raw["summary"]["in_organization"] = det.get("master") is not None

            # Findings por severidad y tipo
            for finding in det.get("findings", []):
                severity = float(finding.get("severity", 0))
                ftype    = finding.get("type", "Unknown")

                for band, (low, high) in SEVERITY_BANDS.items():
                    if low <= severity <= high:
                        raw["summary"]["findings_by_severity"][band] += 1
                        break

                raw["summary"]["findings_by_type"][ftype] = \
                    raw["summary"]["findings_by_type"].get(ftype, 0) + 1

            raw["summary"]["total_active_findings"] += len(det.get("findings", []))

        except Exception as e:
            errors.append(f"enrich_detector:{did}: {e}")