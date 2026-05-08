"""
[REP-01/02/03] Reporter module — genera entregables en PDF, HTML, Markdown, DOCX y PPTX (EN + ES).
"""
from reporter.md_reporter   import MarkdownReporter
from reporter.html_reporter import HtmlReporter
from reporter.pdf_reporter  import PdfReporter
from reporter.docx_reporter import DocxReporter
from reporter.pptx_reporter import PptxReporter
from schemas.report import Report
from utils.logger import get_logger

logger = get_logger(__name__)

REPORTERS = {
    "markdown": MarkdownReporter,
    "html":     HtmlReporter,
    "pdf":      PdfReporter,
    "docx":     DocxReporter,
    "pptx":     PptxReporter,
}

# Formatos que se generan en ambos idiomas (EN + ES)
BILINGUAL_FORMATS = {"docx", "pptx"}


def build_reports(
    report: Report,
    formats: list[str],
    output_dir: str,
    dashboard_dir: str,
    timestamp: str,
) -> dict[str, str]:
    """
    Genera todos los formatos de reporte solicitados.
    Los formatos DOCX y PPTX se generan en inglés y español automáticamente.
    Retorna un dict {formato: ruta_del_archivo}.
    """
    generated = {}

    for fmt in formats:
        fmt = fmt.strip().lower()
        reporter_class = REPORTERS.get(fmt)

        if not reporter_class:
            logger.warning(f"Unknown report format: '{fmt}'. Valid: {list(REPORTERS.keys())}")
            continue

        # DOCX y PPTX se generan en ambos idiomas
        if fmt in BILINGUAL_FORMATS:
            for lang in ["en", "es"]:
                try:
                    reporter = reporter_class(report, output_dir, timestamp, lang=lang)
                    path     = reporter.generate()
                    generated[f"{fmt}_{lang}"] = path
                    logger.info(f"[{fmt.upper()}-{lang.upper()}] Report generated: {path}")
                except Exception as e:
                    logger.error(f"[{fmt.upper()}-{lang.upper()}] Report generation failed: {e}")
            continue

        try:
            reporter = reporter_class(report, output_dir, timestamp)
            path     = reporter.generate()
            generated[fmt] = path
            logger.info(f"[{fmt.upper()}] Report generated: {path}")
        except Exception as e:
            logger.error(f"[{fmt.upper()}] Report generation failed: {e}")

    return generated