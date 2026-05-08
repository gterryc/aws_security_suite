"""
[REP-01] PDF reporter — genera reporte profesional en formato .pdf via WeasyPrint.
Reutiliza el HTML generado por HtmlReporter y lo convierte a PDF.
"""
from reporter.html_reporter import HtmlReporter
from reporter.base_reporter import BaseReporter
from utils.logger import get_logger

logger = get_logger(__name__)


class PdfReporter(BaseReporter):

    def generate(self) -> str:
        logger.info("Generating PDF report...")
        path = self._output_path("pdf")

        try:
            from weasyprint import HTML, CSS
            html_reporter = HtmlReporter(self.report, str(self.output_dir), self.timestamp)
            html_content  = html_reporter._build()

            # Estilos adicionales para impresión PDF
            print_css = CSS(string="""
                @page {
                    size: A4;
                    margin: 1.5cm 1.5cm 2cm 1.5cm;
                    @bottom-center {
                        content: "AWS Security Audit Report — " string(account) " — Page " counter(page) " of " counter(pages);
                        font-size: 8pt;
                        color: #64748b;
                    }
                }
                body { font-size: 10pt; }
                .container { max-width: 100%; padding: 0; }
                .chart-container { height: 180px !important; }
                .grid-4 { grid-template-columns: repeat(4, 1fr); }
                .grid-2 { grid-template-columns: repeat(2, 1fr); }
                .tab-content { display: block !important; }
                .tabs { display: none; }
                table { page-break-inside: avoid; }
                h2 { page-break-before: always; }
                h2:first-of-type { page-break-before: avoid; }
                .alert-critical { page-break-inside: avoid; }
                .card { page-break-inside: avoid; }
            """)

            HTML(string=html_content).write_pdf(str(path), stylesheets=[print_css])
            logger.info(f"PDF report saved: {path}")

        except ImportError:
            logger.warning("WeasyPrint not installed — generating PDF-ready HTML instead.")
            logger.warning("Install with: pip install weasyprint")
            # Fallback: guardar HTML con sufijo _pdf
            fallback_path = self.output_dir / f"aws_audit_{self.report.account_id}_{self.timestamp}_pdf.html"
            html_reporter = HtmlReporter(self.report, str(self.output_dir), self.timestamp)
            fallback_path.write_text(html_reporter._build(), encoding="utf-8")
            logger.info(f"PDF fallback HTML saved: {fallback_path}")
            return str(fallback_path)

        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            raise

        return str(path)