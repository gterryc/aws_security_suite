"""
[REP-01] HTML reporter — genera reporte completo en formato .html con dashboard integrado.
"""
import json
from reporter.base_reporter import BaseReporter
from utils.logger import get_logger

logger = get_logger(__name__)


class HtmlReporter(BaseReporter):

    def generate(self) -> str:
        logger.info("Generating HTML report...")
        path    = self._output_path("html")
        content = self._build()
        path.write_text(content, encoding="utf-8")
        logger.info(f"HTML report saved: {path}")
        return str(path)

    def _build(self) -> str:
        r          = self.report
        score_color = self._score_color(r.global_score)
        score_label = self._score_label(r.global_score)

        # Datos para charts
        severity_data  = json.dumps([r.by_severity.get(s, 0) for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]])
        service_labels = json.dumps([s.service.upper() for s in r.by_service])
        service_scores = json.dumps([s.score for s in r.by_service])
        service_failed = json.dumps([s.failed for s in r.by_service])
        service_passed = json.dumps([s.passed for s in r.by_service])

        by_service    = self._findings_by_service()
        critical      = self._critical_findings()
        all_failed    = self._failed_findings()

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS Security Audit — {r.account_id}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #f1f5f9; --muted: #94a3b8;
    --critical: #7f1d1d; --high: #ef4444; --medium: #f59e0b;
    --low: #22c55e; --info: #60a5fa; --pass: #22c55e; --fail: #ef4444;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
  h1 {{ font-size: 1.75rem; font-weight: 700; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.25rem; font-weight: 600; margin: 2rem 0 1rem; color: #cbd5e1; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
  h3 {{ font-size: 1rem; font-weight: 600; margin-bottom: 0.75rem; }}
  .meta {{ color: var(--muted); font-size: 0.875rem; margin-bottom: 2rem; }}
  .meta span {{ margin-right: 1.5rem; }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }}
  .grid-2 {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-bottom: 2rem; }}
  .grid-3 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1.25rem; }}
  .score-card {{ text-align: center; }}
  .score-value {{ font-size: 3.5rem; font-weight: 800; color: {score_color}; line-height: 1; }}
  .score-label {{ font-size: 0.875rem; color: var(--muted); margin-top: 0.25rem; }}
  .metric-value {{ font-size: 2rem; font-weight: 700; }}
  .metric-label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  .pass   {{ color: var(--pass); }}
  .fail   {{ color: var(--fail); }}
  .skip   {{ color: var(--muted); }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }}
  .badge-critical {{ background: #450a0a; color: #fca5a5; }}
  .badge-high     {{ background: #450a0a; color: #ef4444; }}
  .badge-medium   {{ background: #451a03; color: #f59e0b; }}
  .badge-low      {{ background: #052e16; color: #22c55e; }}
  .badge-info     {{ background: #082f49; color: #60a5fa; }}
  .badge-pass     {{ background: #052e16; color: #22c55e; }}
  .badge-fail     {{ background: #450a0a; color: #ef4444; }}
  .badge-skip     {{ background: #1e293b; color: #94a3b8; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  th {{ text-align: left; padding: 0.75rem 1rem; background: #0f172a; color: var(--muted); font-weight: 500; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 0.75rem 1rem; border-top: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}
  .code {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.8rem; background: #0f172a; padding: 0.15rem 0.4rem; border-radius: 0.25rem; color: #7dd3fc; }}
  .progress-bar {{ background: #1e293b; border-radius: 9999px; height: 6px; overflow: hidden; }}
  .progress-fill {{ height: 100%; border-radius: 9999px; transition: width 0.3s; }}
  .chart-container {{ position: relative; height: 260px; }}
  .section-header {{ display: flex; justify-content: space-between; align-items: center; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
  .collapsible {{ cursor: pointer; user-select: none; }}
  .collapsible:after {{ content: ' ▾'; color: var(--muted); }}
  .collapsible.collapsed:after {{ content: ' ▸'; }}
  details summary {{ list-style: none; cursor: pointer; }}
  details summary::-webkit-details-marker {{ display: none; }}
  .remediation {{ background: #0c1a2e; border-left: 3px solid #3b82f6; padding: 0.75rem 1rem; border-radius: 0 0.5rem 0.5rem 0; font-size: 0.85rem; color: #93c5fd; margin-top: 0.5rem; }}
  .alert-critical {{ background: #1c0a0a; border: 1px solid #7f1d1d; border-radius: 0.5rem; padding: 1rem; margin-bottom: 0.75rem; }}
  .alert-title {{ font-weight: 600; color: #fca5a5; margin-bottom: 0.25rem; }}
  .alert-detail {{ font-size: 0.85rem; color: #fca5a5; opacity: 0.8; }}
  .tabs {{ display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }}
  .tab {{ padding: 0.4rem 1rem; border-radius: 0.375rem; cursor: pointer; font-size: 0.875rem; border: 1px solid var(--border); color: var(--muted); background: transparent; }}
  .tab.active {{ background: #1d4ed8; border-color: #1d4ed8; color: white; }}
  .tab-content {{ display: none; }}
  .tab-content.active {{ display: block; }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <h1>🔒 AWS Security Audit Report</h1>
  <div class="meta">
    <span>📋 Account: <strong>{r.account_id}</strong></span>
    <span>🌍 Region: <strong>{r.region}</strong></span>
    <span>📅 {r.generated_at.strftime('%Y-%m-%d %H:%M UTC')}</span>
    {"<span>👤 Auditor: <strong>" + r.auditor + "</strong></span>" if r.auditor else ""}
    <span>📐 CIS AWS 1.4 + AWS WAF Security Pillar</span>
  </div>

  <!-- Score Cards -->
  <div class="grid-4">
    <div class="card score-card">
      <div class="score-value">{r.global_score}%</div>
      <div class="score-label">Global Score — {score_label}</div>
    </div>
    <div class="card">
      <div class="metric-value">{r.total_controls}</div>
      <div class="metric-label">Total Controls</div>
    </div>
    <div class="card">
      <div class="metric-value pass">{r.passed_controls}</div>
      <div class="metric-label">✅ Passed</div>
    </div>
    <div class="card">
      <div class="metric-value fail">{r.failed_controls}</div>
      <div class="metric-label">❌ Failed</div>
    </div>
  </div>

  <!-- Charts -->
  <div class="grid-2">
    <div class="card">
      <h3>Findings by Severity</h3>
      <div class="chart-container">
        <canvas id="severityChart"></canvas>
      </div>
    </div>
    <div class="card">
      <h3>Score by Service</h3>
      <div class="chart-container">
        <canvas id="serviceChart"></canvas>
      </div>
    </div>
  </div>

  <!-- Service Scores Table -->
  <div class="card" style="margin-bottom:2rem">
    <h3>Service Summary</h3>
    <table>
      <tr><th>Service</th><th>Score</th><th>Progress</th><th>Passed</th><th>Failed</th><th>Skipped</th></tr>
      {"".join(self._service_row(s) for s in r.by_service)}
    </table>
  </div>

  <!-- Critical Findings -->
  {self._critical_section(critical)}

  <!-- Findings by Service (tabbed) -->
  <h2>Findings by Service</h2>
  <div class="tabs">
    {"".join(f'<button class="tab {"active" if i==0 else ""}" onclick="showTab(\'{svc}\', this)">{svc.upper()}</button>' for i, svc in enumerate(sorted(by_service.keys())))}
  </div>
  {"".join(self._service_tab(svc, findings, i==0) for i, (svc, findings) in enumerate(sorted(by_service.items())))}

  <!-- Remediation Plan -->
  <h2>Prioritized Remediation Plan</h2>
  <div class="card">
    <table>
      <tr><th>#</th><th>Control</th><th>Service</th><th>Severity</th><th>Remediation</th></tr>
      {"".join(self._remediation_row(i+1, f) for i, f in enumerate(sorted(all_failed, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity.value))))}
    </table>
  </div>

</div>

<script>
// Severity donut chart
new Chart(document.getElementById('severityChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['CRITICAL','HIGH','MEDIUM','LOW','INFO'],
    datasets: [{{ data: {severity_data}, backgroundColor: ['#7f1d1d','#ef4444','#f59e0b','#22c55e','#60a5fa'], borderWidth: 0 }}]
  }},
  options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ labels: {{ color: '#94a3b8' }} }} }} }}
}});

// Service bar chart
new Chart(document.getElementById('serviceChart'), {{
  type: 'bar',
  data: {{
    labels: {service_labels},
    datasets: [
      {{ label: 'Passed', data: {service_passed}, backgroundColor: '#22c55e' }},
      {{ label: 'Failed', data: {service_failed}, backgroundColor: '#ef4444' }}
    ]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    scales: {{
      x: {{ stacked: true, ticks: {{ color: '#94a3b8' }}, grid: {{ color: '#1e293b' }} }},
      y: {{ stacked: true, ticks: {{ color: '#94a3b8' }}, grid: {{ color: '#1e293b' }} }}
    }},
    plugins: {{ legend: {{ labels: {{ color: '#94a3b8' }} }} }}
  }}
}});

// Tab switching
function showTab(name, btn) {{
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
}}
</script>
</body>
</html>"""

    def _service_row(self, svc) -> str:
        color = self._score_color(svc.score)
        return f"""
        <tr>
          <td><strong>{svc.service.upper()}</strong></td>
          <td style="color:{color};font-weight:700">{svc.score}%</td>
          <td style="width:200px">
            <div class="progress-bar">
              <div class="progress-fill" style="width:{svc.score}%;background:{color}"></div>
            </div>
          </td>
          <td class="pass">{svc.passed}</td>
          <td class="fail">{svc.failed}</td>
          <td class="skip">{svc.skipped}</td>
        </tr>"""

    def _critical_section(self, critical) -> str:
        if not critical:
            return ""
        items = "".join(f"""
        <div class="alert-critical">
          <div class="alert-title">🔴 {f.control_id} — {f.control_name}</div>
          <div class="alert-detail">Resource: {f.resource_id}</div>
          <div class="alert-detail">{f.message}</div>
          <div class="remediation">🔧 {f.remediation}</div>
        </div>""" for f in critical)
        return f"<h2>🔴 Critical Findings ({len(critical)})</h2>{items}"

    def _service_tab(self, svc: str, findings: list, active: bool) -> str:
        failed  = [f for f in findings if f.status.value == "FAIL"]
        passed  = [f for f in findings if f.status.value == "PASS"]
        skipped = [f for f in findings if f.status.value == "SKIP"]

        rows = "".join(self._finding_row(f) for f in sorted(
            findings,
            key=lambda x: (x.status.value != "FAIL", ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity.value))
        ))

        return f"""
        <div id="tab-{svc}" class="tab-content {"active" if active else ""}">
          <div class="card">
            <div style="display:flex;gap:1rem;margin-bottom:1rem">
              <span class="fail">❌ {len(failed)} Failed</span>
              <span class="pass">✅ {len(passed)} Passed</span>
              <span class="skip">⏭️ {len(skipped)} Skipped</span>
            </div>
            <table>
              <tr><th>Control</th><th>Status</th><th>Severity</th><th>Resource</th><th>Message</th></tr>
              {rows}
            </table>
          </div>
        </div>"""

    def _finding_row(self, f) -> str:
        sev_class  = f"badge-{f.severity.value.lower()}"
        stat_class = f"badge-{f.status.value.lower()}"
        resource   = f.resource_id.split(":")[-1][:60]
        message    = f.message[:120]
        return f"""
        <tr>
          <td><span class="code">{f.control_id}</span></td>
          <td><span class="badge {stat_class}">{f.status.value}</span></td>
          <td><span class="badge {sev_class}">{f.severity.value}</span></td>
          <td><span class="code">{resource}</span></td>
          <td>{message}</td>
        </tr>"""

    def _remediation_row(self, i: int, f) -> str:
        sev_class = f"badge-{f.severity.value.lower()}"
        return f"""
        <tr>
          <td style="color:var(--muted)">{i}</td>
          <td><span class="code">{f.control_id}</span><br><small style="color:var(--muted)">{f.control_name[:60]}</small></td>
          <td>{f.service.upper()}</td>
          <td><span class="badge {sev_class}">{f.severity.value}</span></td>
          <td style="font-size:0.8rem">{f.remediation[:150]}</td>
        </tr>"""