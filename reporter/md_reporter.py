"""
[REP-01] Markdown reporter — genera reporte en formato .md
"""
from reporter.base_reporter import BaseReporter
from utils.logger import get_logger

logger = get_logger(__name__)


class MarkdownReporter(BaseReporter):

    def generate(self) -> str:
        logger.info("Generating Markdown report...")
        path = self._output_path("md")
        content = self._build()
        path.write_text(content, encoding="utf-8")
        logger.info(f"Markdown report saved: {path}")
        return str(path)

    def _build(self) -> str:
        r   = self.report
        lines = []

        # ── Portada ───────────────────────────────────────────────────────────
        lines += [
            f"# AWS Security Audit Report",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Account ID** | `{r.account_id}` |",
            f"| **Region** | `{r.region}` |",
            f"| **Generated** | {r.generated_at.strftime('%Y-%m-%d %H:%M UTC')} |",
            f"| **Auditor** | {r.auditor or 'N/A'} |",
            f"| **Framework** | CIS AWS Foundations Benchmark 1.4 + AWS WAF Security Pillar |",
            f"",
        ]

        # ── Executive Summary ─────────────────────────────────────────────────
        score_label = self._score_label(r.global_score)
        lines += [
            f"## Executive Summary",
            f"",
            f"### Global Security Score: {r.global_score}% — {score_label}",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Controls | {r.total_controls} |",
            f"| ✅ Passed | {r.passed_controls} |",
            f"| ❌ Failed | {r.failed_controls} |",
            f"| ⏭️ Skipped | {r.skipped_controls} |",
            f"",
            f"### Findings by Severity",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = r.by_severity.get(sev, 0)
            emoji = self._severity_emoji(sev)
            lines.append(f"| {emoji} {sev} | {count} |")

        lines.append("")

        # ── Score por servicio ────────────────────────────────────────────────
        lines += [
            f"### Score by Service",
            f"",
            f"| Service | Score | Passed | Failed | Skipped |",
            f"|---------|-------|--------|--------|---------|",
        ]
        for svc in r.by_service:
            bar   = self._score_bar(svc.score)
            lines.append(
                f"| **{svc.service.upper()}** | {svc.score}% {bar} | {svc.passed} | {svc.failed} | {svc.skipped} |"
            )

        lines.append("")

        # ── Findings CRITICAL ─────────────────────────────────────────────────
        critical = self._critical_findings()
        if critical:
            lines += [
                f"## 🔴 Critical Findings ({len(critical)})",
                f"",
                f"> These findings require **immediate attention**.",
                f"",
            ]
            for f in critical:
                lines += [
                    f"### {f.control_id} — {f.control_name}",
                    f"",
                    f"- **Resource:** `{f.resource_id}`",
                    f"- **Service:** {f.service.upper()}",
                    f"- **Message:** {f.message}",
                    f"- **Remediation:** {f.remediation}",
                    f"",
                ]

        # ── Findings por servicio ─────────────────────────────────────────────
        lines += [
            f"## Findings by Service",
            f"",
        ]

        by_service = self._findings_by_service()
        for service, findings in sorted(by_service.items()):
            failed  = [f for f in findings if f.status.value == "FAIL"]
            passed  = [f for f in findings if f.status.value == "PASS"]
            skipped = [f for f in findings if f.status.value == "SKIP"]

            svc_score = next(
                (s.score for s in r.by_service if s.service == service), 0.0
            )

            lines += [
                f"### {service.upper()} — {svc_score}%",
                f"",
                f"**{len(failed)} FAIL / {len(passed)} PASS / {len(skipped)} SKIP**",
                f"",
            ]

            if failed:
                lines += [
                    f"| Control | Severity | Resource | Message |",
                    f"|---------|----------|----------|---------|",
                ]
                for f in sorted(failed, key=lambda x: x.severity.value):
                    emoji    = self._severity_emoji(f.severity.value)
                    resource = f.resource_id.split(":")[-1][:50]
                    message  = f.message[:80].replace("|", "—")
                    lines.append(f"| `{f.control_id}` | {emoji} {f.severity.value} | `{resource}` | {message} |")
                lines.append("")

            # Remediation plan para esta sección
            if failed:
                lines += [f"#### Remediation Actions", f""]
                for i, f in enumerate(
                    sorted(failed, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity.value)),
                    start=1
                ):
                    lines.append(f"{i}. **[{f.severity.value}]** `{f.control_id}` — {f.remediation}")
                lines.append("")

        # ── Prioritized Remediation Plan ──────────────────────────────────────
        lines += [
            f"## Prioritized Remediation Plan",
            f"",
            f"Ordered by severity — address CRITICAL and HIGH items first.",
            f"",
            f"| Priority | Control | Service | Severity | Remediation |",
            f"|----------|---------|---------|----------|-------------|",
        ]

        all_failed = sorted(
            self._failed_findings(),
            key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity.value)
        )
        for i, f in enumerate(all_failed, start=1):
            remediation = f.remediation[:100].replace("|", "—")
            lines.append(
                f"| {i} | `{f.control_id}` | {f.service.upper()} | "
                f"{self._severity_emoji(f.severity.value)} {f.severity.value} | {remediation} |"
            )

        lines += [
            f"",
            f"---",
            f"*Generated by AWS Security Audit Suite — "
            f"CIS AWS Foundations Benchmark 1.4 + AWS Well-Architected Framework Security Pillar*",
        ]

        return "\n".join(lines)

    def _score_bar(self, score: float) -> str:
        filled = int(score / 10)
        empty  = 10 - filled
        return "█" * filled + "░" * empty