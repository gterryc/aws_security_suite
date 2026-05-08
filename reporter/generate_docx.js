/**
 * [REP-02] generate_docx.js
 * Genera el reporte de auditoría AWS en formato Word (.docx)
 * Uso: node generate_docx.js <report.json> <output.docx>
 */

"use strict";

const fs   = require("fs");
const path = require("path");

const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, VerticalAlign, PageNumberElement, PageBreak, LevelFormat,
} = require("docx");

// ── Constantes de diseño ──────────────────────────────────────────────────────

const COLORS = {
  primary:    "1F3864",   // Azul oscuro corporativo
  secondary:  "2E75B6",   // Azul medio
  accent:     "41719C",   // Azul accent
  critical:   "7F0000",   // Rojo oscuro
  high:       "C00000",   // Rojo
  medium:     "ED7D31",   // Naranja
  low:        "70AD47",   // Verde
  info:       "4472C4",   // Azul info
  pass:       "375623",   // Verde oscuro
  fail:       "7F0000",   // Rojo oscuro
  skip:       "595959",   // Gris
  white:      "FFFFFF",
  lightGray:  "F2F2F2",
  medGray:    "D9D9D9",
  darkGray:   "595959",
  headerBg:   "1F3864",
  rowAlt:     "EEF3F8",
};

const FONTS = { body: "Calibri", heading: "Calibri", mono: "Courier New" };

// Ancho de contenido en DXA (US Letter 8.5" - 2" márgenes = 6.5" = 9360 DXA)
const CONTENT_WIDTH = 9360;

// ── Helpers de estilo ─────────────────────────────────────────────────────────

function border(color = COLORS.medGray) {
  return { style: BorderStyle.SINGLE, size: 1, color };
}

function allBorders(color = COLORS.medGray) {
  const b = border(color);
  return { top: b, bottom: b, left: b, right: b };
}

function noBorders() {
  const b = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
  return { top: b, bottom: b, left: b, right: b };
}

function severityColor(sev) {
  return { CRITICAL: COLORS.critical, HIGH: COLORS.high, MEDIUM: COLORS.medium,
           LOW: COLORS.low, INFO: COLORS.info }[sev] || COLORS.darkGray;
}

function statusColor(st) {
  return { PASS: COLORS.pass, FAIL: COLORS.fail, SKIP: COLORS.skip }[st] || COLORS.darkGray;
}

function scoreColor(score) {
  if (score >= 90) return COLORS.low;
  if (score >= 75) return "538135";
  if (score >= 50) return COLORS.medium;
  if (score >= 25) return COLORS.high;
  return COLORS.critical;
}

function scoreLabel(score) {
  if (score >= 90) return "Excellent";
  if (score >= 75) return "Good";
  if (score >= 50) return "Fair";
  if (score >= 25) return "Poor";
  return "Critical";
}

// ── Componentes de párrafo ────────────────────────────────────────────────────

function emptyLine(size = 12) {
  return new Paragraph({
    children: [new TextRun({ text: "", size: size * 2 })],
    spacing: { before: 0, after: 0 },
  });
}

function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text, font: FONTS.heading, size: 36, bold: true, color: COLORS.primary })],
    spacing: { before: 360, after: 120 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: COLORS.secondary, space: 4 } },
  });
}

function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    children: [new TextRun({ text, font: FONTS.heading, size: 28, bold: true, color: COLORS.secondary })],
    spacing: { before: 240, after: 80 },
  });
}

function h3(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    children: [new TextRun({ text, font: FONTS.heading, size: 24, bold: true, color: COLORS.accent })],
    spacing: { before: 180, after: 60 },
  });
}

function bodyText(text, opts = {}) {
  return new Paragraph({
    children: [new TextRun({
      text,
      font: FONTS.body,
      size: opts.size || 22,
      bold: opts.bold || false,
      color: opts.color || "000000",
      italics: opts.italic || false,
    })],
    spacing: { before: 60, after: 60 },
    alignment: opts.align || AlignmentType.LEFT,
  });
}

function bulletItem(text, opts = {}) {
  return new Paragraph({
    numbering: { reference: "bullets", level: 0 },
    children: [new TextRun({
      text,
      font: FONTS.body,
      size: opts.size || 22,
      bold: opts.bold || false,
      color: opts.color || "000000",
    })],
    spacing: { before: 40, after: 40 },
  });
}

function numberedItem(text, opts = {}) {
  return new Paragraph({
    numbering: { reference: "numbers", level: 0 },
    children: [new TextRun({
      text,
      font: FONTS.body,
      size: opts.size || 22,
      bold: opts.bold || false,
      color: opts.color || "000000",
    })],
    spacing: { before: 40, after: 40 },
  });
}

// ── Componentes de tabla ──────────────────────────────────────────────────────

function headerCell(text, widthDxa, opts = {}) {
  return new TableCell({
    width: { size: widthDxa, type: WidthType.DXA },
    borders: allBorders(COLORS.primary),
    shading: { fill: opts.bg || COLORS.headerBg, type: ShadingType.CLEAR },
    margins: { top: 100, bottom: 100, left: 140, right: 140 },
    verticalAlign: VerticalAlign.CENTER,
    children: [new Paragraph({
      children: [new TextRun({
        text,
        font: FONTS.body,
        size: opts.size || 20,
        bold: true,
        color: COLORS.white,
      })],
      alignment: opts.align || AlignmentType.LEFT,
      spacing: { before: 0, after: 0 },
    })],
  });
}

function dataCell(text, widthDxa, opts = {}) {
  return new TableCell({
    width: { size: widthDxa, type: WidthType.DXA },
    borders: allBorders(),
    shading: { fill: opts.bg || COLORS.white, type: ShadingType.CLEAR },
    margins: { top: 80, bottom: 80, left: 140, right: 140 },
    verticalAlign: VerticalAlign.CENTER,
    children: [new Paragraph({
      children: [new TextRun({
        text: String(text || ""),
        font: opts.mono ? FONTS.mono : FONTS.body,
        size: opts.size || 20,
        bold: opts.bold || false,
        color: opts.color || "000000",
      })],
      alignment: opts.align || AlignmentType.LEFT,
      spacing: { before: 0, after: 0 },
    })],
  });
}

// ── Sección: Portada ──────────────────────────────────────────────────────────

function buildCoverPage(report) {
  const score      = report.global_score;
  const scoreClr   = scoreColor(score);
  const scoreLbl   = scoreLabel(score);

  return [
    emptyLine(48),
    new Paragraph({
      children: [new TextRun({
        text: "AWS SECURITY AUDIT REPORT",
        font: FONTS.heading,
        size: 56,
        bold: true,
        color: COLORS.primary,
      })],
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 200 },
      border: { bottom: { style: BorderStyle.SINGLE, size: 12, color: COLORS.secondary, space: 8 } },
    }),
    emptyLine(24),
    new Paragraph({
      children: [new TextRun({
        text: `Account: ${report.account_id}  |  Region: ${report.region}`,
        font: FONTS.body,
        size: 26,
        color: COLORS.darkGray,
      })],
      alignment: AlignmentType.CENTER,
      spacing: { before: 80, after: 80 },
    }),
    new Paragraph({
      children: [new TextRun({
        text: `Generated: ${report.generated_at}  |  Auditor: ${report.auditor}`,
        font: FONTS.body,
        size: 24,
        color: COLORS.darkGray,
        italics: true,
      })],
      alignment: AlignmentType.CENTER,
      spacing: { before: 60, after: 60 },
    }),
    emptyLine(36),
    // Score box
    new Table({
      width: { size: 4000, type: WidthType.DXA },
      columnWidths: [4000],
      alignment: AlignmentType.CENTER,
      rows: [
        new TableRow({ children: [
          new TableCell({
            width: { size: 4000, type: WidthType.DXA },
            borders: allBorders(COLORS.secondary),
            shading: { fill: COLORS.lightGray, type: ShadingType.CLEAR },
            margins: { top: 200, bottom: 200, left: 200, right: 200 },
            children: [
              new Paragraph({
                children: [new TextRun({ text: `${score}%`, font: FONTS.heading, size: 96, bold: true, color: scoreClr })],
                alignment: AlignmentType.CENTER,
                spacing: { before: 0, after: 40 },
              }),
              new Paragraph({
                children: [new TextRun({ text: `Security Score — ${scoreLbl}`, font: FONTS.body, size: 28, color: COLORS.darkGray })],
                alignment: AlignmentType.CENTER,
                spacing: { before: 0, after: 0 },
              }),
            ],
          }),
        ]}),
      ],
    }),
    emptyLine(24),
    // Stats row
    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [2340, 2340, 2340, 2340],
      rows: [
        new TableRow({ children: [
          headerCell("Total Controls", 2340, { bg: COLORS.accent }),
          headerCell("✓ Passed",       2340, { bg: "375623" }),
          headerCell("✗ Failed",       2340, { bg: COLORS.critical }),
          headerCell("— Skipped",      2340, { bg: COLORS.darkGray }),
        ]}),
        new TableRow({ children: [
          dataCell(String(report.total_controls),   2340, { align: AlignmentType.CENTER, bold: true, size: 36 }),
          dataCell(String(report.passed_controls),  2340, { align: AlignmentType.CENTER, bold: true, size: 36, color: COLORS.pass }),
          dataCell(String(report.failed_controls),  2340, { align: AlignmentType.CENTER, bold: true, size: 36, color: COLORS.fail }),
          dataCell(String(report.skipped_controls), 2340, { align: AlignmentType.CENTER, bold: true, size: 36, color: COLORS.skip }),
        ]}),
      ],
    }),
    emptyLine(36),
    new Paragraph({
      children: [new TextRun({
        text: "Framework: CIS AWS Foundations Benchmark v1.4  |  AWS Well-Architected Framework — Security Pillar",
        font: FONTS.body,
        size: 20,
        color: COLORS.darkGray,
        italics: true,
      })],
      alignment: AlignmentType.CENTER,
      spacing: { before: 60, after: 60 },
    }),
    new Paragraph({
      children: [new TextRun({
        text: "CONFIDENTIAL — For authorized personnel only",
        font: FONTS.body,
        size: 20,
        bold: true,
        color: COLORS.critical,
      })],
      alignment: AlignmentType.CENTER,
      spacing: { before: 40, after: 0 },
    }),
    new Paragraph({ children: [new PageBreak()] }),
  ];
}

// ── Sección: Resumen Ejecutivo ────────────────────────────────────────────────

function buildExecutiveSummary(report) {
  const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const sevRows  = sevOrder.map((sev, i) => new TableRow({
    children: [
      dataCell(sev, 3120, { bold: true, color: severityColor(sev), bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
      dataCell(String(report.by_severity[sev] || 0), 3120, { align: AlignmentType.CENTER, bold: true, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
      dataCell(
        report.by_severity[sev] > 0 ? "Requires attention" : "No findings",
        3120,
        { color: report.by_severity[sev] > 0 ? severityColor(sev) : COLORS.pass, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }
      ),
    ],
  }));

  // Critical findings list
  const criticalFindings = report.findings.filter(f => f.severity === "CRITICAL" && f.status === "FAIL");

  const criticalItems = criticalFindings.length > 0
    ? criticalFindings.slice(0, 10).map(f =>
        bulletItem(`[${f.service.toUpperCase()}] ${f.control_id}: ${f.message.substring(0, 120)}${f.message.length > 120 ? "..." : ""}`, { color: COLORS.critical })
      )
    : [bodyText("No critical findings detected.", { color: COLORS.pass })];

  return [
    h1("1. Executive Summary"),
    bodyText(
      `This report presents the results of an AWS security audit performed on account ${report.account_id} ` +
      `(region: ${report.region}) on ${report.generated_at}. The audit evaluated ${report.total_controls} security ` +
      `controls against the CIS AWS Foundations Benchmark v1.4 and the AWS Well-Architected Framework Security Pillar.`
    ),
    emptyLine(6),
    h2("1.1 Overall Security Posture"),
    bodyText(
      `The account achieved a global security score of ${report.global_score}% — ${scoreLabel(report.global_score)}. ` +
      `Out of ${report.total_controls} controls evaluated, ${report.passed_controls} passed, ` +
      `${report.failed_controls} failed, and ${report.skipped_controls} were skipped.`
    ),
    emptyLine(6),
    h2("1.2 Findings by Severity"),
    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [3120, 3120, 3120],
      rows: [
        new TableRow({ children: [
          headerCell("Severity",  3120),
          headerCell("Count",     3120),
          headerCell("Status",    3120),
        ]}),
        ...sevRows,
      ],
    }),
    emptyLine(12),
    h2("1.3 Critical Findings Requiring Immediate Attention"),
    ...(criticalFindings.length > 0
      ? [bodyText(`The following ${Math.min(criticalFindings.length, 10)} critical findings require immediate remediation:`, { bold: true })]
      : []
    ),
    ...criticalItems,
    new Paragraph({ children: [new PageBreak()] }),
  ];
}

// ── Sección: Metodología ──────────────────────────────────────────────────────

function buildMethodology(report) {
  return [
    h1("2. Methodology"),
    h2("2.1 Frameworks Applied"),
    bulletItem("CIS AWS Foundations Benchmark v1.4 — Industry-standard security configuration guidelines for AWS accounts"),
    bulletItem("AWS Well-Architected Framework — Security Pillar — AWS best practices for secure cloud architectures"),
    emptyLine(6),
    h2("2.2 Services Audited"),
    ...report.by_service.map(s => bulletItem(`${s.service.toUpperCase()} — ${s.total} controls evaluated (${s.passed} passed / ${s.failed} failed)`)),
    emptyLine(6),
    h2("2.3 Audit Scope"),
    bodyText(`Account ID: ${report.account_id}`),
    bodyText(`Region: ${report.region}`),
    bodyText(`Date: ${report.generated_at}`),
    bodyText(`Auditor: ${report.auditor}`),
    emptyLine(6),
    h2("2.4 Severity Classification"),
    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [1560, 2340, 5460],
      rows: [
        new TableRow({ children: [
          headerCell("Severity",    1560),
          headerCell("Risk Level",  2340),
          headerCell("Description", 5460),
        ]}),
        ...[
          ["CRITICAL", "Immediate Action", "Exploitation is likely and impact is severe. Must be remediated within 24-48 hours."],
          ["HIGH",     "Urgent",           "High risk of exploitation. Remediate within 1-2 weeks."],
          ["MEDIUM",   "Important",        "Moderate risk. Remediate within 30 days as part of planned work."],
          ["LOW",      "Advisory",         "Low risk. Address in next scheduled maintenance window."],
          ["INFO",     "Informational",    "No immediate risk. Awareness item for security posture improvement."],
        ].map(([sev, risk, desc], i) => new TableRow({ children: [
          dataCell(sev,  1560, { bold: true, color: severityColor(sev), bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
          dataCell(risk, 2340, { bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
          dataCell(desc, 5460, { bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
        ]})),
      ],
    }),
    new Paragraph({ children: [new PageBreak()] }),
  ];
}

// ── Sección: Score por servicio ───────────────────────────────────────────────

function buildServiceScores(report) {
  const rows = report.by_service.map((s, i) => new TableRow({
    children: [
      dataCell(s.service.toUpperCase(), 1560, { bold: true, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
      dataCell(`${s.score}%`,   1560, { bold: true, color: scoreColor(s.score), align: AlignmentType.CENTER, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
      dataCell(String(s.total),   1560, { align: AlignmentType.CENTER, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
      dataCell(String(s.passed),  1560, { align: AlignmentType.CENTER, color: COLORS.pass, bold: true, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
      dataCell(String(s.failed),  1560, { align: AlignmentType.CENTER, color: COLORS.fail, bold: true, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
      dataCell(String(s.skipped), 1560, { align: AlignmentType.CENTER, color: COLORS.skip, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
    ],
  }));

  return [
    h1("3. Results by Service"),
    h2("3.1 Service Score Summary"),
    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [1560, 1560, 1560, 1560, 1560, 1560],
      rows: [
        new TableRow({ children: [
          headerCell("Service",  1560),
          headerCell("Score",    1560),
          headerCell("Total",    1560),
          headerCell("Passed",   1560),
          headerCell("Failed",   1560),
          headerCell("Skipped",  1560),
        ]}),
        ...rows,
      ],
    }),
    emptyLine(12),
  ];
}

// ── Sección: Findings por servicio ────────────────────────────────────────────

function buildServiceFindings(report) {
  const sections = [];
  const serviceOrder = ["iam", "s3", "ec2", "rds", "guardduty", "cloudwatch", "vpc"];
  const byService = {};

  for (const f of report.findings) {
    if (!byService[f.service]) byService[f.service] = [];
    byService[f.service].push(f);
  }

  const services = serviceOrder.filter(s => byService[s]).concat(
    Object.keys(byService).filter(s => !serviceOrder.includes(s))
  );

  for (const svc of services) {
    const findings  = byService[svc] || [];
    const svcScore  = report.by_service.find(s => s.service === svc);
    const failed    = findings.filter(f => f.status === "FAIL")
                              .sort((a, b) => {
                                const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
                                return order.indexOf(a.severity) - order.indexOf(b.severity);
                              });
    const passed    = findings.filter(f => f.status === "PASS");

    sections.push(h2(`3.${services.indexOf(svc) + 2} ${svc.toUpperCase()} — Score: ${svcScore?.score || 0}%`));
    sections.push(bodyText(
      `${findings.length} controls evaluated — ${failed.length} failed, ${passed.length} passed.`,
      { italic: true, color: COLORS.darkGray }
    ));
    sections.push(emptyLine(6));

    if (failed.length > 0) {
      sections.push(h3(`Failed Controls (${failed.length})`));
      sections.push(new Table({
        width: { size: CONTENT_WIDTH, type: WidthType.DXA },
        columnWidths: [1500, 1000, 3860, 3000],
        rows: [
          new TableRow({ children: [
            headerCell("Control ID",   1500),
            headerCell("Severity",     1000),
            headerCell("Finding",      3860),
            headerCell("Remediation",  3000),
          ]}),
          ...failed.map((f, i) => new TableRow({
            children: [
              dataCell(f.control_id,   1500, { mono: true, size: 18, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
              dataCell(f.severity,     1000, { bold: true, color: severityColor(f.severity), bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
              dataCell(f.message.substring(0, 200), 3860, { size: 18, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
              dataCell(f.remediation.substring(0, 200), 3000, { size: 18, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
            ],
          })),
        ],
      }));
      sections.push(emptyLine(12));
    }
  }

  sections.push(new Paragraph({ children: [new PageBreak()] }));
  return sections;
}

// ── Sección: Plan de remediación ──────────────────────────────────────────────

function buildRemediationPlan(report) {
  const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const allFailed = report.findings
    .filter(f => f.status === "FAIL")
    .sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));

  const deduplicated = [];
  const seen = new Set();
  for (const f of allFailed) {
    const key = `${f.control_id}-${f.service}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduplicated.push(f);
    }
  }

  const rows = deduplicated.map((f, i) => new TableRow({
    children: [
      dataCell(String(i + 1),      400,  { align: AlignmentType.CENTER, bold: true, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
      dataCell(f.severity,         900,  { bold: true, color: severityColor(f.severity), bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
      dataCell(f.service.toUpperCase(), 800, { bold: true, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
      dataCell(f.control_id,       1400, { mono: true, size: 18, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
      dataCell(f.remediation.substring(0, 250), 5860, { size: 18, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
    ],
  }));

  const timeframes = {
    CRITICAL: "24–48 hours",
    HIGH:     "1–2 weeks",
    MEDIUM:   "30 days",
    LOW:      "Next maintenance window",
    INFO:     "As resources allow",
  };

  return [
    h1("4. Prioritized Remediation Plan"),
    bodyText(
      "The following table presents all failed controls ordered by severity. Address items in order — " +
      "CRITICAL and HIGH findings should be treated as immediate security incidents."
    ),
    emptyLine(6),
    h2("4.1 Recommended Timeframes"),
    ...Object.entries(timeframes).map(([sev, time]) =>
      bulletItem(`${sev}: ${time}`, { color: severityColor(sev) })
    ),
    emptyLine(12),
    h2("4.2 Remediation Table"),
    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [400, 900, 800, 1400, 5860],
      rows: [
        new TableRow({ children: [
          headerCell("#",           400),
          headerCell("Severity",    900),
          headerCell("Service",     800),
          headerCell("Control",    1400),
          headerCell("Action Required", 5860),
        ]}),
        ...rows,
      ],
    }),
    new Paragraph({ children: [new PageBreak()] }),
  ];
}

// ── Sección: Anexo técnico ────────────────────────────────────────────────────

function buildAnnex(report) {
  const allPassed = report.findings.filter(f => f.status === "PASS");

  const passRows = allPassed.slice(0, 50).map((f, i) => new TableRow({
    children: [
      dataCell(f.control_id,           2000, { mono: true, size: 18, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
      dataCell(f.service.toUpperCase(), 1000, { bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
      dataCell("PASS",                  800,  { bold: true, color: COLORS.pass, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
      dataCell(f.control_name,         5560, { size: 18, bg: i % 2 === 0 ? COLORS.white : COLORS.rowAlt }),
    ],
  }));

  return [
    h1("5. Annexes"),
    h2("5.1 Passed Controls"),
    bodyText(`${allPassed.length} controls passed. Showing first 50.`, { italic: true, color: COLORS.darkGray }),
    emptyLine(6),
    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [2000, 1000, 800, 5560],
      rows: [
        new TableRow({ children: [
          headerCell("Control ID",   2000),
          headerCell("Service",      1000),
          headerCell("Status",        800),
          headerCell("Control Name", 5560),
        ]}),
        ...passRows,
      ],
    }),
    emptyLine(12),
    h2("5.2 Audit Metadata"),
    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [3120, 6240],
      rows: [
        new TableRow({ children: [headerCell("Field", 3120), headerCell("Value", 6240)] }),
        ...[
          ["Account ID",       report.account_id],
          ["Region",           report.region],
          ["Generated At",     report.generated_at],
          ["Auditor",          report.auditor],
          ["Total Controls",   String(report.total_controls)],
          ["Global Score",     `${report.global_score}%`],
          ["Framework",        "CIS AWS Foundations Benchmark v1.4"],
          ["Framework",        "AWS Well-Architected Framework — Security Pillar"],
        ].map(([k, v], i) => new TableRow({ children: [
          dataCell(k, 3120, { bold: true, bg: i % 2 === 0 ? COLORS.lightGray : COLORS.white }),
          dataCell(v, 6240, { bg: i % 2 === 0 ? COLORS.lightGray : COLORS.white }),
        ]})),
      ],
    }),
  ];
}

// ── Tabla de contenidos manual ────────────────────────────────────────────────

function buildManualTOC() {
  const entries = [
    { level: 1, text: "1. Executive Summary" },
    { level: 2, text: "   1.1 Overall Security Posture" },
    { level: 2, text: "   1.2 Findings by Severity" },
    { level: 2, text: "   1.3 Critical Findings Requiring Immediate Attention" },
    { level: 1, text: "2. Methodology" },
    { level: 2, text: "   2.1 Frameworks Applied" },
    { level: 2, text: "   2.2 Services Audited" },
    { level: 2, text: "   2.3 Audit Scope" },
    { level: 2, text: "   2.4 Severity Classification" },
    { level: 1, text: "3. Results by Service" },
    { level: 2, text: "   3.1 Service Score Summary" },
    { level: 2, text: "   3.2+ Detailed Findings per Service" },
    { level: 1, text: "4. Prioritized Remediation Plan" },
    { level: 2, text: "   4.1 Recommended Timeframes" },
    { level: 2, text: "   4.2 Remediation Table" },
    { level: 1, text: "5. Annexes" },
    { level: 2, text: "   5.1 Passed Controls" },
    { level: 2, text: "   5.2 Audit Metadata" },
  ];

  return entries.map(entry => new Paragraph({
    children: [new TextRun({
      text: entry.text,
      font: FONTS.body,
      size: entry.level === 1 ? 24 : 22,
      bold: entry.level === 1,
      color: entry.level === 1 ? COLORS.primary : COLORS.darkGray,
    })],
    spacing: { before: entry.level === 1 ? 120 : 40, after: 40 },
    indent: { left: entry.level === 1 ? 0 : 360 },
  }));
}

// ── Header y Footer ───────────────────────────────────────────────────────────

function buildHeader(report) {
  return new Header({
    children: [
      new Table({
        width: { size: CONTENT_WIDTH, type: WidthType.DXA },
        columnWidths: [6240, 3120],
        borders: { bottom: { style: BorderStyle.SINGLE, size: 4, color: COLORS.secondary } },
        rows: [new TableRow({
          children: [
            new TableCell({
              width: { size: 6240, type: WidthType.DXA },
              borders: noBorders(),
              children: [new Paragraph({
                children: [new TextRun({ text: "AWS Security Audit Report", font: FONTS.body, size: 20, bold: true, color: COLORS.primary })],
                spacing: { before: 0, after: 0 },
              })],
            }),
            new TableCell({
              width: { size: 3120, type: WidthType.DXA },
              borders: noBorders(),
              children: [new Paragraph({
                children: [new TextRun({ text: `Account: ${report.account_id}`, font: FONTS.body, size: 18, color: COLORS.darkGray })],
                alignment: AlignmentType.RIGHT,
                spacing: { before: 0, after: 0 },
              })],
            }),
          ],
        })],
      }),
      emptyLine(4),
    ],
  });
}

function buildFooter() {
  return new Footer({
    children: [
      new Paragraph({
        children: [
          new TextRun({ text: "CONFIDENTIAL  |  Page ", font: FONTS.body, size: 18, color: COLORS.darkGray }),
          new PageNumberElement(),
          new TextRun({ text: "  |  AWS Security Audit Suite", font: FONTS.body, size: 18, color: COLORS.darkGray }),
        ],
        alignment: AlignmentType.CENTER,
        border: { top: { style: BorderStyle.SINGLE, size: 4, color: COLORS.secondary, space: 4 } },
        spacing: { before: 80, after: 0 },
      }),
    ],
  });
}

// ── Document assembly ─────────────────────────────────────────────────────────

async function generateDocx(reportData, outputPath) {
  console.log(`Generating DOCX for account ${reportData.account_id}...`);

  const children = [
    ...buildCoverPage(reportData),
    // Tabla de contenidos manual — compatible con todas las versiones de Word
    new Paragraph({
      children: [new TextRun({ text: "Table of Contents", font: FONTS.heading, size: 32, bold: true, color: COLORS.primary })],
      spacing: { before: 0, after: 120 },
      border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: COLORS.secondary, space: 4 } },
    }),
    emptyLine(8),
    ...buildManualTOC(),
    new Paragraph({ children: [new PageBreak()] }),
    ...buildExecutiveSummary(reportData),
    ...buildMethodology(reportData),
    ...buildServiceScores(reportData),
    ...buildServiceFindings(reportData),
    ...buildRemediationPlan(reportData),
    ...buildAnnex(reportData),
  ];

  const doc = new Document({
    numbering: {
      config: [
        {
          reference: "bullets",
          levels: [{
            level: 0,
            format: LevelFormat.BULLET,
            text: "\u2022",
            alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 720, hanging: 360 } } },
          }],
        },
        {
          reference: "numbers",
          levels: [{
            level: 0,
            format: LevelFormat.DECIMAL,
            text: "%1.",
            alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 720, hanging: 360 } } },
          }],
        },
      ],
    },
    styles: {
      default: {
        document: { run: { font: FONTS.body, size: 22 } },
      },
      paragraphStyles: [
        {
          id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 36, bold: true, font: FONTS.heading, color: COLORS.primary },
          paragraph: { spacing: { before: 360, after: 120 }, outlineLevel: 0 },
        },
        {
          id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 28, bold: true, font: FONTS.heading, color: COLORS.secondary },
          paragraph: { spacing: { before: 240, after: 80 }, outlineLevel: 1 },
        },
        {
          id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 24, bold: true, font: FONTS.heading, color: COLORS.accent },
          paragraph: { spacing: { before: 180, after: 60 }, outlineLevel: 2 },
        },
      ],
    },
    sections: [{
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1080, right: 1080, bottom: 1080, left: 1080 },
        },
      },
      headers: { default: buildHeader(reportData) },
      footers: { default: buildFooter() },
      children,
    }],
  });

  const buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(outputPath, buffer);
  console.log(`DOCX saved: ${outputPath} (${(buffer.length / 1024).toFixed(1)} KB)`);
}

// ── Entry point ───────────────────────────────────────────────────────────────

const [,, jsonPath, outputPath] = process.argv;

if (!jsonPath || !outputPath) {
  console.error("Usage: node generate_docx.js <report.json> <output.docx>");
  process.exit(1);
}

const reportData = JSON.parse(fs.readFileSync(jsonPath, "utf8"));

generateDocx(reportData, outputPath)
  .then(() => process.exit(0))
  .catch(err => {
    console.error("Error:", err.message);
    process.exit(1);
  });