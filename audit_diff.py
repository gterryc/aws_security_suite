#!/usr/bin/env python3
"""
[TOOL-01] audit_diff.py — Compara dos reportes de auditoría y genera un diff.

Uso:
    python3 audit_diff.py <report_anterior.json> <report_nuevo.json> [--output diff.md]

Genera un Markdown con:
  - Delta de score global y por servicio
  - Controles remediados (FAIL → PASS)
  - Regresiones y nuevos fallos (PASS → FAIL, nuevos FAIL)
  - Controles que siguen fallando (FAIL → FAIL)
"""
import json
import sys
import argparse
from pathlib import Path
from datetime import datetime


# ── Helpers ──────────────────────────────────────────────────────────────────

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def load_report(path: str) -> dict:
    """Carga un report JSON y valida campos mínimos."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    required = ["account_id", "global_score", "findings"]
    for field in required:
        if field not in data:
            print(f"ERROR: '{path}' missing required field: '{field}'")
            sys.exit(1)
    return data


def finding_key(f: dict) -> str:
    """
    Genera una key única para un finding.
    Para controles evaluados por recurso, incluye el mensaje truncado
    para distinguir entre recursos diferentes con el mismo control_id.
    """
    cid = f.get("control_id", "")
    svc = f.get("service", "")
    msg = f.get("message", "")

    # Extraer identificador de recurso del mensaje (bucket name, instance id, sg id, etc.)
    # Esto permite distinguir "SG sg-abc allows..." de "SG sg-xyz allows..."
    resource_hint = ""
    for token in msg.split():
        if any(token.startswith(p) for p in [
            "sg-", "i-", "vol-", "snap-", "vpc-", "subnet-", "rtb-", "igw-",
            "nat-", "eni-", "acl-", "ami-", "arn:", "db-", "rds-",
        ]):
            resource_hint = token.rstrip(".,;:)")
            break
        # Bucket names (no prefix, pero suelen ser el primer token relevante)
        if svc == "s3" and "bucket" in msg.lower() and len(token) > 3 and not token.startswith(("S3", "s3", "Block", "ACL")):
            resource_hint = token.rstrip(".,;:)")
            break

    if resource_hint:
        return f"{cid}|{svc}|{resource_hint}"
    return f"{cid}|{svc}"


def build_index(findings: list[dict]) -> dict[str, dict]:
    """
    Construye un índice de findings por key.
    Si hay duplicados (mismo control, mismo recurso), prioriza FAIL sobre PASS.
    """
    index = {}
    for f in findings:
        key = finding_key(f)
        existing = index.get(key)
        if existing is None:
            index[key] = f
        elif f.get("status") == "FAIL" and existing.get("status") != "FAIL":
            index[key] = f  # FAIL tiene prioridad
    return index


def sev_sort(f: dict) -> int:
    return SEV_ORDER.get(f.get("severity", "INFO"), 99)


def score_delta_symbol(old: float, new: float) -> str:
    diff = new - old
    if diff > 0:
        return f"+{diff:.1f}% ▲"
    elif diff < 0:
        return f"{diff:.1f}% ▼"
    return "0% ─"


def score_emoji(old: float, new: float) -> str:
    diff = new - old
    if diff > 10:
        return "🟢"
    elif diff > 0:
        return "🔵"
    elif diff == 0:
        return "⚪"
    elif diff > -10:
        return "🟡"
    return "🔴"


# ── Diff Engine ──────────────────────────────────────────────────────────────

def compute_diff(old_report: dict, new_report: dict) -> dict:
    """Calcula el diff completo entre dos reportes."""

    old_idx = build_index(old_report["findings"])
    new_idx = build_index(new_report["findings"])

    all_keys = set(old_idx.keys()) | set(new_idx.keys())

    remediated = []     # FAIL → PASS
    regressions = []    # PASS → FAIL
    new_fails = []      # no existía → FAIL
    new_passes = []     # no existía → PASS
    removed = []        # existía → no existe
    still_failing = []  # FAIL → FAIL

    for key in all_keys:
        old_f = old_idx.get(key)
        new_f = new_idx.get(key)

        if old_f and new_f:
            old_status = old_f.get("status")
            new_status = new_f.get("status")

            if old_status == "FAIL" and new_status == "PASS":
                remediated.append({"old": old_f, "new": new_f, "key": key})
            elif old_status == "PASS" and new_status == "FAIL":
                regressions.append({"old": old_f, "new": new_f, "key": key})
            elif old_status == "FAIL" and new_status == "FAIL":
                still_failing.append({"old": old_f, "new": new_f, "key": key})

        elif old_f and not new_f:
            removed.append(old_f)

        elif new_f and not old_f:
            if new_f.get("status") == "FAIL":
                new_fails.append(new_f)
            else:
                new_passes.append(new_f)

    # Ordenar todo por severidad
    remediated.sort(key=lambda x: sev_sort(x["old"]))
    regressions.sort(key=lambda x: sev_sort(x["new"]))
    new_fails.sort(key=lambda x: sev_sort(x))
    still_failing.sort(key=lambda x: sev_sort(x["new"]))

    # Score deltas por servicio
    old_svc = {s["service"]: s for s in old_report.get("by_service", [])}
    new_svc = {s["service"]: s for s in new_report.get("by_service", [])}
    all_svcs = sorted(set(old_svc.keys()) | set(new_svc.keys()))

    svc_deltas = []
    for svc in all_svcs:
        old_s = old_svc.get(svc, {})
        new_s = new_svc.get(svc, {})
        svc_deltas.append({
            "service":    svc.upper(),
            "old_score":  old_s.get("score", 0),
            "new_score":  new_s.get("score", 0),
            "old_failed": old_s.get("failed", 0),
            "new_failed": new_s.get("failed", 0),
        })

    return {
        "old_score":      old_report.get("global_score", 0),
        "new_score":      new_report.get("global_score", 0),
        "old_total":      old_report.get("total_controls", 0),
        "new_total":      new_report.get("total_controls", 0),
        "old_failed":     old_report.get("failed_controls", 0),
        "new_failed":     new_report.get("failed_controls", 0),
        "old_passed":     old_report.get("passed_controls", 0),
        "new_passed":     new_report.get("passed_controls", 0),
        "remediated":     remediated,
        "regressions":    regressions,
        "new_fails":      new_fails,
        "new_passes":     new_passes,
        "removed":        removed,
        "still_failing":  still_failing,
        "svc_deltas":     svc_deltas,
        "old_account":    old_report.get("account_id", "N/A"),
        "new_account":    new_report.get("account_id", "N/A"),
        "old_date":       old_report.get("generated_at", "N/A"),
        "new_date":       new_report.get("generated_at", "N/A"),
    }


# ── Markdown Renderer ────────────────────────────────────────────────────────

def render_markdown(diff: dict) -> str:
    lines = []

    # ── Header ───────────────────────────────────────────────────────────
    lines.append("# AWS Security Audit — Comparison Report")
    lines.append("")
    lines.append(f"| | Previous Audit | Current Audit |")
    lines.append(f"|---|---|---|")
    lines.append(f"| **Account** | `{diff['old_account']}` | `{diff['new_account']}` |")
    lines.append(f"| **Date** | {diff['old_date'][:19] if len(diff['old_date']) > 10 else diff['old_date']} | {diff['new_date'][:19] if len(diff['new_date']) > 10 else diff['new_date']} |")
    lines.append(f"| **Score** | {diff['old_score']}% | {diff['new_score']}% |")
    lines.append(f"| **Total Controls** | {diff['old_total']} | {diff['new_total']} |")
    lines.append(f"| **Passed** | {diff['old_passed']} | {diff['new_passed']} |")
    lines.append(f"| **Failed** | {diff['old_failed']} | {diff['new_failed']} |")
    lines.append("")

    # ── Score Delta ──────────────────────────────────────────────────────
    delta = diff["new_score"] - diff["old_score"]
    emoji = score_emoji(diff["old_score"], diff["new_score"])
    lines.append(f"## Score Delta: {emoji} {score_delta_symbol(diff['old_score'], diff['new_score'])}")
    lines.append("")

    n_remediated = len(diff["remediated"])
    n_regressions = len(diff["regressions"])
    n_new_fails = len(diff["new_fails"])
    n_still_failing = len(diff["still_failing"])

    lines.append(f"- **{n_remediated}** controls remediated (FAIL → PASS)")
    lines.append(f"- **{n_regressions}** regressions (PASS → FAIL)")
    lines.append(f"- **{n_new_fails}** new failures")
    lines.append(f"- **{n_still_failing}** controls still failing")
    lines.append("")

    # ── Score by Service ─────────────────────────────────────────────────
    lines.append("## Score by Service")
    lines.append("")
    lines.append("| Service | Previous | Current | Delta | Fails Before | Fails After |")
    lines.append("|---------|----------|---------|-------|-------------|-------------|")
    for s in diff["svc_deltas"]:
        delta_str = score_delta_symbol(s["old_score"], s["new_score"])
        emoji = score_emoji(s["old_score"], s["new_score"])
        lines.append(
            f"| {s['service']} | {s['old_score']}% | {s['new_score']}% | {emoji} {delta_str} | {s['old_failed']} | {s['new_failed']} |"
        )
    lines.append("")

    # ── Remediated ───────────────────────────────────────────────────────
    if diff["remediated"]:
        lines.append(f"## ✅ Remediated Controls ({n_remediated})")
        lines.append("")
        lines.append("Controls that were fixed since the previous audit.")
        lines.append("")
        lines.append("| Severity | Service | Control ID | Control Name |")
        lines.append("|----------|---------|------------|--------------|")
        for item in diff["remediated"]:
            f = item["old"]
            lines.append(
                f"| {f['severity']} | {f['service'].upper()} | {f['control_id']} | {f.get('control_name', '')} |"
            )
        lines.append("")

    # ── Regressions ──────────────────────────────────────────────────────
    if diff["regressions"]:
        lines.append(f"## ⚠️ Regressions ({n_regressions})")
        lines.append("")
        lines.append("Controls that were passing before but are now failing.")
        lines.append("")
        lines.append("| Severity | Service | Control ID | Finding | Remediation |")
        lines.append("|----------|---------|------------|---------|-------------|")
        for item in diff["regressions"]:
            f = item["new"]
            lines.append(
                f"| {f['severity']} | {f['service'].upper()} | {f['control_id']} | {f.get('message', '')[:100]} | {f.get('remediation', '')[:100]} |"
            )
        lines.append("")

    # ── New Failures ─────────────────────────────────────────────────────
    if diff["new_fails"]:
        lines.append(f"## 🆕 New Failures ({n_new_fails})")
        lines.append("")
        lines.append("Controls not present in the previous audit that are now failing.")
        lines.append("")
        lines.append("| Severity | Service | Control ID | Finding | Remediation |")
        lines.append("|----------|---------|------------|---------|-------------|")
        for f in diff["new_fails"]:
            lines.append(
                f"| {f['severity']} | {f['service'].upper()} | {f['control_id']} | {f.get('message', '')[:100]} | {f.get('remediation', '')[:100]} |"
            )
        lines.append("")

    # ── Still Failing ────────────────────────────────────────────────────
    if diff["still_failing"]:
        lines.append(f"## 🔴 Still Failing ({n_still_failing})")
        lines.append("")
        lines.append("Controls that remain in FAIL status. Prioritize CRITICAL and HIGH.")
        lines.append("")
        lines.append("| Severity | Service | Control ID | Control Name |")
        lines.append("|----------|---------|------------|--------------|")
        for item in diff["still_failing"]:
            f = item["new"]
            lines.append(
                f"| {f['severity']} | {f['service'].upper()} | {f['control_id']} | {f.get('control_name', '')} |"
            )
        lines.append("")

    # ── Footer ───────────────────────────────────────────────────────────
    lines.append("---")
    lines.append(f"*Generated by audit_diff.py on {datetime.now(tz=None).strftime('%Y-%m-%d %H:%M UTC')}*")
    lines.append("")

    return "\n".join(lines)


# ── Console Summary ──────────────────────────────────────────────────────────

def print_summary(diff: dict):
    """Imprime resumen rápido en consola."""
    delta = diff["new_score"] - diff["old_score"]
    arrow = "▲" if delta > 0 else ("▼" if delta < 0 else "─")

    print()
    print("=" * 60)
    print("  AWS AUDIT DIFF — SUMMARY")
    print("=" * 60)
    print(f"  Score:  {diff['old_score']}%  →  {diff['new_score']}%  ({delta:+.1f}% {arrow})")
    print(f"  Failed: {diff['old_failed']}  →  {diff['new_failed']}")
    print(f"  Passed: {diff['old_passed']}  →  {diff['new_passed']}")
    print("-" * 60)
    print(f"  ✅ Remediated:     {len(diff['remediated'])}")
    print(f"  ⚠️  Regressions:   {len(diff['regressions'])}")
    print(f"  🆕 New failures:   {len(diff['new_fails'])}")
    print(f"  🔴 Still failing:  {len(diff['still_failing'])}")
    print("=" * 60)
    print()


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Compare two AWS audit reports and generate a diff.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 audit_diff.py outputs/run-01/json/report_*.json outputs/run-02/json/report_*.json
  python3 audit_diff.py old_report.json new_report.json --output comparison.md
        """,
    )
    parser.add_argument("old_report", help="Path to the previous (baseline) report JSON")
    parser.add_argument("new_report", help="Path to the new (current) report JSON")
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output path for the Markdown diff (default: audit_diff_<timestamp>.md)",
    )
    args = parser.parse_args()

    # Load reports
    print(f"Loading previous report: {args.old_report}")
    old_report = load_report(args.old_report)

    print(f"Loading current report:  {args.new_report}")
    new_report = load_report(args.new_report)

    # Validate same account
    if old_report.get("account_id") != new_report.get("account_id"):
        print(f"WARNING: Account IDs differ ({old_report.get('account_id')} vs {new_report.get('account_id')})")

    # Compute diff
    diff = compute_diff(old_report, new_report)

    # Console summary
    print_summary(diff)

    # Generate markdown
    md_content = render_markdown(diff)

    # Write output
    if args.output:
        output_path = Path(args.output)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"audit_diff_{ts}.md")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(md_content, encoding="utf-8")
    print(f"Diff report saved: {output_path}")


if __name__ == "__main__":
    main()