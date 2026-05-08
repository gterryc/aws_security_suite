"""
[ORC-01] AWS Security Audit Suite — Entry point principal.

Orquesta la ejecución de collectors y analyzers, construye el Report
y lo pasa al Reporter para generar los entregables finales.

Uso:
    python main.py --profile audit-role --region us-east-1
    python main.py --profile audit-role --region us-east-1 --services iam,s3,ec2
    python main.py --profile audit-role --region us-east-1 --output-dir ./outputs
"""

import sys
import click
from datetime import datetime, timezone
from pathlib import Path

from utils.aws_session import get_session, get_account_id, get_region
from utils.logger import get_logger
from utils.helpers import save_json

from schemas.report import Report

from collectors import COLLECTORS
from analyzers import ANALYZERS

logger = get_logger(__name__, log_file="outputs/audit.log")

ALL_SERVICES = list(COLLECTORS.keys())


@click.command()
@click.option("--profile",    default=None,        help="AWS profile name (default: env credentials)")
@click.option("--region",     default="us-east-1", help="AWS region to audit", show_default=True)
@click.option("--services",   default=None,        help="Comma-separated services to audit (default: all)")
@click.option("--output-dir", default="outputs",   help="Output directory for reports", show_default=True)
@click.option("--auditor",    default=None,        help="Auditor name for the report")
@click.option("--formats",    default="pdf,html,markdown", help="Report formats to generate", show_default=True)
@click.option("--skip-report", is_flag=True,       help="Skip report generation (collect + analyze only)")
@click.option("--verbose",    is_flag=True,        help="Enable verbose logging")
def main(profile, region, services, output_dir, auditor, formats, skip_report, verbose):
    """AWS Security Audit Suite — CIS AWS Foundations Benchmark + AWS WAF Security Pillar."""

    start_time = datetime.now(timezone.utc)
    logger.info("=" * 60)
    logger.info("AWS Security Audit Suite — Starting")
    logger.info(f"Profile : {profile or 'environment credentials'}")
    logger.info(f"Region  : {region}")
    logger.info(f"Started : {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    logger.info("=" * 60)

    # ── Servicios a auditar ───────────────────────────────────────────────────
    if services:
        requested = [s.strip().lower() for s in services.split(",")]
        invalid   = [s for s in requested if s not in ALL_SERVICES]
        if invalid:
            logger.error(f"Unknown services: {invalid}. Valid options: {ALL_SERVICES}")
            sys.exit(1)
        target_services = requested
    else:
        target_services = ALL_SERVICES

    logger.info(f"Services: {target_services}")

    # ── Sesión AWS ────────────────────────────────────────────────────────────
    try:
        session    = get_session(profile=profile, region=region)
        account_id = get_account_id(session)
        region     = get_region(session)
        logger.info(f"Account : {account_id}")
        logger.info(f"Region  : {region}")
    except Exception as e:
        logger.error(f"Failed to initialize AWS session: {e}")
        sys.exit(1)

    # ── Directorios de salida ─────────────────────────────────────────────────
    output_path = Path(output_dir)
    json_dir    = output_path / "json"
    reports_dir = output_path / "reports"
    dash_dir    = output_path / "dashboard"

    for d in [json_dir, reports_dir, dash_dir]:
        d.mkdir(parents=True, exist_ok=True)

    timestamp = start_time.strftime("%Y%m%d_%H%M%S")

    # ── Phase 1: Collectors ───────────────────────────────────────────────────
    logger.info("")
    logger.info("Phase 1 — Data Collection")
    logger.info("-" * 40)

    collector_outputs = {}
    collection_errors = {}

    for service in target_services:
        collector = COLLECTORS.get(service)
        if not collector:
            logger.warning(f"No collector found for service '{service}' — skipping")
            continue

        logger.info(f"Collecting: {service}")
        try:
            output = collector(session)
            collector_outputs[service] = output

            # Persistir raw data
            json_path = json_dir / f"{service}_{timestamp}.json"
            save_json(output.model_dump(), str(json_path))
            logger.info(f"  ✓ {service} — saved to {json_path.name}")

            if output.errors:
                logger.warning(f"  ! {service} — {len(output.errors)} non-fatal errors")
                for err in output.errors[:3]:
                    logger.warning(f"    - {err}")
                if len(output.errors) > 3:
                    logger.warning(f"    ... and {len(output.errors) - 3} more")

        except Exception as e:
            logger.error(f"  ✗ {service} — collection failed: {e}")
            collection_errors[service] = str(e)

    logger.info(f"Collection complete: {len(collector_outputs)}/{len(target_services)} services")

    # ── Phase 2: Analyzers ────────────────────────────────────────────────────
    logger.info("")
    logger.info("Phase 2 — Analysis")
    logger.info("-" * 40)

    all_findings = []
    analysis_errors = {}

    for service, collector_output in collector_outputs.items():
        analyzer = ANALYZERS.get(service)
        if not analyzer:
            logger.warning(f"No analyzer found for service '{service}' — skipping")
            continue

        logger.info(f"Analyzing : {service}")
        try:
            findings = analyzer(collector_output)
            all_findings.extend(findings)

            passed = sum(1 for f in findings if f.status.value == "PASS")
            failed = sum(1 for f in findings if f.status.value == "FAIL")
            skipped = sum(1 for f in findings if f.status.value == "SKIP")
            logger.info(f"  ✓ {service} — {passed} PASS / {failed} FAIL / {skipped} SKIP")

        except Exception as e:
            logger.error(f"  ✗ {service} — analysis failed: {e}")
            analysis_errors[service] = str(e)

    logger.info(f"Analysis complete: {len(all_findings)} total findings")

    # ── Phase 3: Build Report ─────────────────────────────────────────────────
    logger.info("")
    logger.info("Phase 3 — Building Report")
    logger.info("-" * 40)

    report = Report(
        account_id=account_id,
        region=region,
        findings=all_findings,
        auditor=auditor,
    )
    report.compute_summary()

    logger.info(f"Global score : {report.global_score}%")
    logger.info(f"Total        : {report.total_controls} controls")
    logger.info(f"Passed       : {report.passed_controls}")
    logger.info(f"Failed       : {report.failed_controls}")
    logger.info(f"Skipped      : {report.skipped_controls}")
    logger.info(f"By severity  : {report.by_severity}")

    # Persistir report completo en JSON
    report_json_path = json_dir / f"report_{timestamp}.json"
    save_json(report.model_dump(), str(report_json_path))
    logger.info(f"Report JSON  : {report_json_path}")

    # ── Phase 4: Reporter ─────────────────────────────────────────────────────
    if skip_report:
        logger.info("Skipping report generation (--skip-report flag)")
    else:
        logger.info("")
        logger.info("Phase 4 — Generating Reports")
        logger.info("-" * 40)

        requested_formats = [f.strip().lower() for f in formats.split(",")]

        try:
            from reporter import build_reports
            build_reports(
                report=report,
                formats=requested_formats,
                output_dir=str(reports_dir),
                dashboard_dir=str(dash_dir),
                timestamp=timestamp,
            )
        except Exception as e:
            logger.error(f"Report generation failed: {e}")

    # ── Summary ───────────────────────────────────────────────────────────────
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    logger.info("")
    logger.info("=" * 60)
    logger.info("Audit Complete")
    logger.info(f"Duration     : {elapsed:.1f}s")
    logger.info(f"Score        : {report.global_score}%")
    logger.info(f"Output dir   : {output_path.resolve()}")
    logger.info("=" * 60)

    # Exit con código no-zero si hay FAILs críticos
    critical_fails = sum(
        1 for f in all_findings
        if f.status.value == "FAIL" and f.severity.value == "CRITICAL"
    )
    if critical_fails:
        logger.warning(f"⚠  {critical_fails} CRITICAL findings require immediate attention")
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()