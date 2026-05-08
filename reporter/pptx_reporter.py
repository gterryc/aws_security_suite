"""
[REP-03] PPTX reporter — genera presentación ejecutiva en formato PowerPoint (.pptx).
Usa pptxgenjs (Node.js) para la generación del archivo.
Soporta idiomas: 'en' (English) y 'es' (Español).
"""
import json
import subprocess
import tempfile
from pathlib import Path

from reporter.base_reporter import BaseReporter
from utils.logger import get_logger

logger = get_logger(__name__)

# Ruta al script Node.js (relativa al root del proyecto)
PPTX_BUILDER_SCRIPT = Path(__file__).parent / "pptx_builder.js"


class PptxReporter(BaseReporter):

    def __init__(self, report, output_dir: str, timestamp: str, lang: str = "en"):
        super().__init__(report, output_dir, timestamp)
        self.lang = lang if lang in ("en", "es") else "en"

    def _output_path(self, extension: str):
        """Incluye el idioma en el nombre del archivo."""
        return self.output_dir / f"aws_audit_{self.report.account_id}_{self.timestamp}_{self.lang}.{extension}"

    def generate(self) -> str:
        logger.info(f"Generating PPTX report [{self.lang.upper()}]...")
        output_file = self._output_path("pptx")
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Serializar Report a JSON temporal para pasarlo al script Node.js
        report_data = self._serialize_report()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tmp:
            json.dump(report_data, tmp, ensure_ascii=False, default=str)
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                ["node", str(PPTX_BUILDER_SCRIPT.resolve()), tmp_path, str(output_file.resolve()), self.lang],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(PPTX_BUILDER_SCRIPT.parent),  # Node busca node_modules relativo a cwd
            )

            if result.returncode != 0:
                logger.error(f"pptx_builder.js failed: {result.stderr}")
                raise RuntimeError(f"PPTX generation failed: {result.stderr}")

            logger.info(f"PPTX report saved: {output_file}")
            return str(output_file)

        finally:
            # Limpiar archivo temporal
            Path(tmp_path).unlink(missing_ok=True)

    def _serialize_report(self) -> dict:
        """Convierte el Report a un dict plano que el script Node.js puede consumir."""
        r = self.report
        return {
            "account_id":       r.account_id,
            "region":           r.region,
            "generated_at":     r.generated_at.isoformat() if r.generated_at else None,
            "auditor":          r.auditor,
            "total_controls":   r.total_controls,
            "passed_controls":  r.passed_controls,
            "failed_controls":  r.failed_controls,
            "skipped_controls": r.skipped_controls,
            "global_score":     r.global_score,
            "by_severity":      r.by_severity,
            "by_service": [
                {
                    "service": s.service,
                    "total":   s.total,
                    "passed":  s.passed,
                    "failed":  s.failed,
                    "skipped": s.skipped,
                    "score":   s.score,
                }
                for s in r.by_service
            ],
            "findings": [
                {
                    "control_id":   f.control_id,
                    "control_name": f.control_name,
                    "service":      f.service,
                    "severity":     f.severity.value,
                    "status":       f.status.value,
                    "message":      f.message,
                    "remediation":  f.remediation,
                }
                for f in r.findings
            ],
        }