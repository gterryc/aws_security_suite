"""
[REP-01] Base reporter — interfaz común para todos los formatos de reporte.
"""
from abc import ABC, abstractmethod
from pathlib import Path
from schemas.report import Report


class BaseReporter(ABC):
    """
    Clase base para todos los reporters.
    Define la interfaz común y helpers compartidos.
    """

    def __init__(self, report: Report, output_dir: str, timestamp: str):
        self.report     = report
        self.output_dir = Path(output_dir)
        self.timestamp  = timestamp
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def generate(self) -> str:
        """Genera el reporte y retorna la ruta del archivo generado."""
        pass

    # ── Helpers compartidos ───────────────────────────────────────────────────

    def _score_label(self, score: float) -> str:
        if score >= 90:  return "Excellent"
        if score >= 75:  return "Good"
        if score >= 50:  return "Fair"
        if score >= 25:  return "Poor"
        return "Critical"

    def _score_color(self, score: float) -> str:
        if score >= 90:  return "#22c55e"   # green
        if score >= 75:  return "#84cc16"   # lime
        if score >= 50:  return "#f59e0b"   # amber
        if score >= 25:  return "#ef4444"   # red
        return "#7f1d1d"                    # dark red

    def _severity_color(self, severity: str) -> str:
        return {
            "CRITICAL": "#7f1d1d",
            "HIGH":     "#ef4444",
            "MEDIUM":   "#f59e0b",
            "LOW":      "#84cc16",
            "INFO":     "#60a5fa",
        }.get(severity.upper(), "#9ca3af")

    def _severity_emoji(self, severity: str) -> str:
        return {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🟢",
            "INFO":     "🔵",
        }.get(severity.upper(), "⚪")

    def _status_emoji(self, status: str) -> str:
        return {
            "PASS": "✅",
            "FAIL": "❌",
            "SKIP": "⏭️",
        }.get(status.upper(), "❓")

    def _findings_by_service(self) -> dict:
        result = {}
        for f in self.report.findings:
            result.setdefault(f.service, []).append(f)
        return result

    def _findings_by_severity(self) -> dict:
        result = {}
        for f in self.report.findings:
            result.setdefault(f.severity.value, []).append(f)
        return result

    def _critical_findings(self):
        return [
            f for f in self.report.findings
            if f.severity.value == "CRITICAL" and f.status.value == "FAIL"
        ]

    def _failed_findings(self):
        return [f for f in self.report.findings if f.status.value == "FAIL"]

    def _output_path(self, extension: str) -> Path:
        return self.output_dir / f"aws_audit_{self.report.account_id}_{self.timestamp}.{extension}"