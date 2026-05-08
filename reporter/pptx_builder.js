/**
 * [REP-03] PPTX Builder — Genera presentación ejecutiva de auditoría AWS.
 * Uso: node pptx_builder.js <input.json> <output.pptx> <lang>
 *
 * El JSON de entrada contiene todos los datos del Report serializados.
 * lang = "en" | "es"
 */
const pptxgen = require("pptxgenjs");
const fs = require("fs");

// ── Args ────────────────────────────────────────────────────────────────────
const [,, inputPath, outputPath, lang = "en"] = process.argv;
if (!inputPath || !outputPath) {
  console.error("Usage: node pptx_builder.js <input.json> <output.pptx> [en|es]");
  process.exit(1);
}

const data = JSON.parse(fs.readFileSync(inputPath, "utf8"));

// ── Color Palette — Midnight Executive ──────────────────────────────────────
const P = {
  navy:      "1E2761",
  darkNavy:  "141C3D",
  iceBlue:   "CADCFC",
  white:     "FFFFFF",
  lightGray: "F2F4F8",
  midGray:   "94A3B8",
  darkGray:  "475569",
  pass:      "16A34A",
  fail:      "DC2626",
  skip:      "94A3B8",
  critical:  "7F1D1D",
  high:      "DC2626",
  medium:    "EA580C",
  low:       "16A34A",
  info:      "2563EB",
};

const SEV_COLORS = { CRITICAL: P.critical, HIGH: P.high, MEDIUM: P.medium, LOW: P.low, INFO: P.info };
const STATUS_COLORS = { PASS: P.pass, FAIL: P.fail, SKIP: P.skip };

// ── Texts ───────────────────────────────────────────────────────────────────
const T = {
  en: {
    title: "AWS Security Audit",
    subtitle: "Executive Presentation",
    account: "Account", region: "Region", date: "Date", auditor: "Auditor",
    framework: "CIS AWS Foundations Benchmark v1.4 + AWS WAF Security Pillar",
    confidential: "CONFIDENTIAL — For authorized personnel only",
    execSummary: "Executive Summary",
    securityScore: "Security Score",
    totalControls: "Total Controls", passed: "Passed", failed: "Failed", skipped: "Skipped",
    findingsBySev: "Findings by Severity",
    criticalFindings: "Critical & High Findings",
    requireImmediate: "These findings require immediate attention",
    resultsByService: "Results by Service",
    remediationPlan: "Prioritized Remediation Plan",
    remediationNote: "Address CRITICAL and HIGH items first",
    num: "#", severity: "Severity", service: "Service", control: "Control", action: "Action",
    nextSteps: "Next Steps",
    step1: "Remediate CRITICAL findings within 24-48 hours",
    step2: "Address HIGH severity items in the current sprint",
    step3: "Plan MEDIUM fixes within 30 days",
    step4: "Schedule LOW/INFO items for next maintenance window",
    step5: "Re-run audit to validate remediation effectiveness",
    thanksTitle: "Thank You",
    thanksBody: "Questions & Discussion",
    excellent: "Excellent", good: "Good", fair: "Fair", poor: "Poor", criticalLbl: "Critical",
    controlInventory: "Controls Inventory Summary",
    inventoryNote: "Complete visibility of all evaluated controls",
    score: "Score",
  },
  es: {
    title: "Auditoría de Seguridad AWS",
    subtitle: "Presentación Ejecutiva",
    account: "Cuenta", region: "Región", date: "Fecha", auditor: "Auditor",
    framework: "CIS AWS Foundations Benchmark v1.4 + AWS WAF — Pilar de Seguridad",
    confidential: "CONFIDENCIAL — Solo para personal autorizado",
    execSummary: "Resumen Ejecutivo",
    securityScore: "Puntuación de Seguridad",
    totalControls: "Total Controles", passed: "Aprobados", failed: "Fallidos", skipped: "Omitidos",
    findingsBySev: "Hallazgos por Severidad",
    criticalFindings: "Hallazgos Críticos y Altos",
    requireImmediate: "Estos hallazgos requieren atención inmediata",
    resultsByService: "Resultados por Servicio",
    remediationPlan: "Plan de Remediación Priorizado",
    remediationNote: "Abordar CRITICAL y HIGH primero",
    num: "#", severity: "Severidad", service: "Servicio", control: "Control", action: "Acción",
    nextSteps: "Próximos Pasos",
    step1: "Remediar hallazgos CRITICAL en 24-48 horas",
    step2: "Abordar items HIGH en el sprint actual",
    step3: "Planificar correcciones MEDIUM en 30 días",
    step4: "Programar items LOW/INFO en la próxima ventana de mantenimiento",
    step5: "Re-ejecutar auditoría para validar la remediación",
    thanksTitle: "Gracias",
    thanksBody: "Preguntas y Discusión",
    excellent: "Excelente", good: "Bueno", fair: "Regular", poor: "Deficiente", criticalLbl: "Crítico",
    controlInventory: "Inventario de Controles",
    inventoryNote: "Visibilidad completa de todos los controles evaluados",
    score: "Puntuación",
  },
};

const t = T[lang] || T.en;

// ── Helpers ─────────────────────────────────────────────────────────────────
function scoreLabel(score) {
  if (score >= 90) return t.excellent;
  if (score >= 75) return t.good;
  if (score >= 50) return t.fair;
  if (score >= 25) return t.poor;
  return t.criticalLbl;
}

function scoreColor(score) {
  if (score >= 90) return P.pass;
  if (score >= 75) return "15803D";
  if (score >= 50) return P.medium;
  if (score >= 25) return P.high;
  return P.critical;
}

function makeShadow() {
  return { type: "outer", color: "000000", blur: 6, offset: 2, angle: 135, opacity: 0.12 };
}

// ── Build Presentation ──────────────────────────────────────────────────────
const pres = new pptxgen();
pres.layout = "LAYOUT_16x9";
pres.author = data.auditor || "Security Auditor";
pres.title = `${t.title} — ${data.account_id}`;

const dateStr = data.generated_at ? data.generated_at.substring(0, 10) : new Date().toISOString().substring(0, 10);

// ════════════════════════════════════════════════════════════════════════════
// SLIDE 1 — Title
// ════════════════════════════════════════════════════════════════════════════
{
  const slide = pres.addSlide();
  slide.background = { color: P.darkNavy };

  // Left accent bar
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 0.06, h: 5.625, fill: { color: P.iceBlue }
  });

  slide.addText(t.title.toUpperCase(), {
    x: 0.8, y: 1.2, w: 8.4, h: 1.0,
    fontSize: 38, fontFace: "Georgia", bold: true, color: P.white,
    charSpacing: 3
  });

  slide.addText(t.subtitle, {
    x: 0.8, y: 2.1, w: 8.4, h: 0.6,
    fontSize: 20, fontFace: "Calibri", color: P.iceBlue, italic: true
  });

  // Metadata grid
  const meta = [
    [t.account, data.account_id],
    [t.region, data.region],
    [t.date, dateStr],
    [t.auditor, data.auditor || "N/A"],
  ];
  const metaText = meta.map(([k, v]) =>
    ({ text: `${k}: ${v}`, options: { breakLine: true, fontSize: 13, fontFace: "Calibri", color: P.midGray } })
  );
  slide.addText(metaText, { x: 0.8, y: 3.2, w: 8, h: 1.2 });

  slide.addText(t.framework, {
    x: 0.8, y: 4.6, w: 8.4, h: 0.35,
    fontSize: 10, fontFace: "Calibri", italic: true, color: P.midGray
  });

  slide.addText(t.confidential, {
    x: 0.8, y: 5.0, w: 8.4, h: 0.35,
    fontSize: 10, fontFace: "Calibri", bold: true, color: P.fail
  });
}

// ════════════════════════════════════════════════════════════════════════════
// SLIDE 2 — Executive Summary (score + stat cards)
// ════════════════════════════════════════════════════════════════════════════
{
  const slide = pres.addSlide();
  slide.background = { color: P.white };

  slide.addText(t.execSummary, {
    x: 0.5, y: 0.3, w: 9, h: 0.6,
    fontSize: 28, fontFace: "Georgia", bold: true, color: P.navy, margin: 0
  });

  // Score circle area
  const sc = data.global_score;
  const scClr = scoreColor(sc);
  slide.addShape(pres.shapes.OVAL, {
    x: 0.8, y: 1.3, w: 2.2, h: 2.2,
    fill: { color: scClr, transparency: 10 },
    line: { color: scClr, width: 3 }
  });
  slide.addText(`${sc}%`, {
    x: 0.8, y: 1.5, w: 2.2, h: 1.4,
    fontSize: 44, fontFace: "Georgia", bold: true, color: scClr,
    align: "center", valign: "middle"
  });
  slide.addText(`${t.securityScore}\n${scoreLabel(sc)}`, {
    x: 0.8, y: 2.85, w: 2.2, h: 0.65,
    fontSize: 11, fontFace: "Calibri", color: P.darkGray,
    align: "center", valign: "top"
  });

  // Stat cards — right side
  const stats = [
    { label: t.totalControls, val: data.total_controls, clr: P.navy },
    { label: t.passed, val: data.passed_controls, clr: P.pass },
    { label: t.failed, val: data.failed_controls, clr: P.fail },
    { label: t.skipped, val: data.skipped_controls, clr: P.skip },
  ];
  const cardW = 1.4, gap = 0.15, startX = 3.4;
  stats.forEach((s, i) => {
    const cx = startX + i * (cardW + gap);
    slide.addShape(pres.shapes.RECTANGLE, {
      x: cx, y: 1.3, w: cardW, h: 2.2,
      fill: { color: P.lightGray }, shadow: makeShadow()
    });
    slide.addText(String(s.val), {
      x: cx, y: 1.5, w: cardW, h: 1.2,
      fontSize: 40, fontFace: "Georgia", bold: true, color: s.clr,
      align: "center", valign: "middle"
    });
    slide.addText(s.label, {
      x: cx, y: 2.7, w: cardW, h: 0.5,
      fontSize: 12, fontFace: "Calibri", color: P.darkGray,
      align: "center", valign: "top"
    });
  });

  // Severity bar chart (native)
  const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const sevVals = sevOrder.map(s => data.by_severity[s] || 0);
  if (sevVals.some(v => v > 0)) {
    slide.addText(t.findingsBySev, {
      x: 0.5, y: 3.8, w: 4, h: 0.4,
      fontSize: 14, fontFace: "Calibri", bold: true, color: P.navy, margin: 0
    });
    slide.addChart(pres.charts.BAR, [{
      name: t.severity,
      labels: sevOrder,
      values: sevVals,
    }], {
      x: 0.5, y: 4.15, w: 9, h: 1.3,
      barDir: "col",
      chartColors: [P.critical, P.high, P.medium, P.low, P.info],
      showValue: true,
      dataLabelPosition: "outEnd",
      dataLabelColor: P.darkGray,
      catAxisLabelColor: P.darkGray,
      valAxisLabelColor: P.darkGray,
      valGridLine: { style: "none" },
      catGridLine: { style: "none" },
      showLegend: false,
      chartArea: { fill: { color: P.white } },
    });
  }
}

// ════════════════════════════════════════════════════════════════════════════
// SLIDE 3 — Results by Service (score cards)
// ════════════════════════════════════════════════════════════════════════════
{
  const slide = pres.addSlide();
  slide.background = { color: P.white };

  slide.addText(t.resultsByService, {
    x: 0.5, y: 0.3, w: 9, h: 0.6,
    fontSize: 28, fontFace: "Georgia", bold: true, color: P.navy, margin: 0
  });

  const services = data.by_service || [];
  const cols = Math.min(services.length, 4);
  const rows = Math.ceil(services.length / cols);
  const cw = 2.1, ch = 1.55, gapX = 0.2, gapY = 0.2;
  const totalW = cols * cw + (cols - 1) * gapX;
  const sx = (10 - totalW) / 2;
  const sy = 1.1;

  services.forEach((svc, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);
    const cx = sx + col * (cw + gapX);
    const cy = sy + row * (ch + gapY);
    const sClr = scoreColor(svc.score);

    slide.addShape(pres.shapes.RECTANGLE, {
      x: cx, y: cy, w: cw, h: ch,
      fill: { color: P.lightGray }, shadow: makeShadow()
    });
    // Left accent
    slide.addShape(pres.shapes.RECTANGLE, {
      x: cx, y: cy, w: 0.06, h: ch,
      fill: { color: sClr }
    });

    slide.addText(svc.service.toUpperCase(), {
      x: cx + 0.15, y: cy + 0.1, w: cw - 0.25, h: 0.35,
      fontSize: 13, fontFace: "Calibri", bold: true, color: P.navy, margin: 0
    });
    slide.addText(`${svc.score}%`, {
      x: cx + 0.15, y: cy + 0.45, w: cw - 0.25, h: 0.5,
      fontSize: 30, fontFace: "Georgia", bold: true, color: sClr, margin: 0
    });
    slide.addText(`${svc.passed}P / ${svc.failed}F / ${svc.skipped}S`, {
      x: cx + 0.15, y: cy + 1.05, w: cw - 0.25, h: 0.35,
      fontSize: 10, fontFace: "Calibri", color: P.darkGray, margin: 0
    });
  });
}

// ════════════════════════════════════════════════════════════════════════════
// SLIDE 4 — Critical & High Findings
// ════════════════════════════════════════════════════════════════════════════
{
  const critHigh = (data.findings || [])
    .filter(f => f.status === "FAIL" && (f.severity === "CRITICAL" || f.severity === "HIGH"))
    .slice(0, 10);

  if (critHigh.length > 0) {
    const slide = pres.addSlide();
    slide.background = { color: P.white };

    slide.addText(t.criticalFindings, {
      x: 0.5, y: 0.3, w: 9, h: 0.6,
      fontSize: 28, fontFace: "Georgia", bold: true, color: P.navy, margin: 0
    });
    slide.addText(t.requireImmediate, {
      x: 0.5, y: 0.85, w: 9, h: 0.3,
      fontSize: 12, fontFace: "Calibri", italic: true, color: P.darkGray, margin: 0
    });

    const rows = [[
      { text: t.severity, options: { bold: true, color: P.white, fill: { color: P.navy }, fontSize: 10, fontFace: "Calibri" } },
      { text: t.service, options: { bold: true, color: P.white, fill: { color: P.navy }, fontSize: 10, fontFace: "Calibri" } },
      { text: t.control, options: { bold: true, color: P.white, fill: { color: P.navy }, fontSize: 10, fontFace: "Calibri" } },
      { text: t.action, options: { bold: true, color: P.white, fill: { color: P.navy }, fontSize: 10, fontFace: "Calibri" } },
    ]];

    critHigh.forEach(f => {
      rows.push([
        { text: f.severity, options: { color: SEV_COLORS[f.severity] || P.darkGray, bold: true, fontSize: 9, fontFace: "Calibri" } },
        { text: f.service.toUpperCase(), options: { fontSize: 9, fontFace: "Calibri", color: P.darkGray } },
        { text: f.control_id, options: { fontSize: 9, fontFace: "Calibri", color: P.navy } },
        { text: (f.remediation || "").substring(0, 120), options: { fontSize: 9, fontFace: "Calibri", color: P.darkGray } },
      ]);
    });

    slide.addTable(rows, {
      x: 0.5, y: 1.25, w: 9, h: 0.3,
      colW: [1.0, 1.0, 1.5, 5.5],
      border: { pt: 0.5, color: "E2E8F0" },
      rowH: [0.35, ...Array(critHigh.length).fill(0.35)],
      autoPage: false,
    });
  }
}

// ════════════════════════════════════════════════════════════════════════════
// SLIDE 5 — Controls Inventory Summary
// ════════════════════════════════════════════════════════════════════════════
{
  const slide = pres.addSlide();
  slide.background = { color: P.white };

  slide.addText(t.controlInventory, {
    x: 0.5, y: 0.3, w: 9, h: 0.6,
    fontSize: 28, fontFace: "Georgia", bold: true, color: P.navy, margin: 0
  });
  slide.addText(t.inventoryNote, {
    x: 0.5, y: 0.85, w: 9, h: 0.3,
    fontSize: 12, fontFace: "Calibri", italic: true, color: P.darkGray, margin: 0
  });

  // Summary stat line
  slide.addText(
    `${data.total_controls} ${t.totalControls}   |   ${data.passed_controls} ${t.passed}   |   ${data.failed_controls} ${t.failed}   |   ${data.skipped_controls} ${t.skipped}`,
    {
      x: 0.5, y: 1.25, w: 9, h: 0.4,
      fontSize: 14, fontFace: "Calibri", bold: true, color: P.navy, margin: 0
    }
  );

  // Stacked bar chart by service
  const services = data.by_service || [];
  const labels = services.map(s => s.service.toUpperCase());
  const passVals = services.map(s => s.passed);
  const failVals = services.map(s => s.failed);
  const skipVals = services.map(s => s.skipped);

  slide.addChart(pres.charts.BAR, [
    { name: t.passed, labels, values: passVals },
    { name: t.failed, labels, values: failVals },
    { name: t.skipped, labels, values: skipVals },
  ], {
    x: 0.5, y: 1.75, w: 9, h: 3.5,
    barDir: "bar",
    barGrouping: "stacked",
    chartColors: [P.pass, P.fail, P.skip],
    showValue: true,
    dataLabelColor: P.white,
    dataLabelPosition: "center",
    catAxisLabelColor: P.darkGray,
    catAxisLabelFontSize: 11,
    valGridLine: { color: "E2E8F0", size: 0.5 },
    catGridLine: { style: "none" },
    showLegend: true,
    legendPos: "b",
    legendFontSize: 10,
    chartArea: { fill: { color: P.white } },
  });
}

// ════════════════════════════════════════════════════════════════════════════
// SLIDE 6 — Remediation Plan (top 15)
// ════════════════════════════════════════════════════════════════════════════
{
  const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const allFailed = (data.findings || [])
    .filter(f => f.status === "FAIL")
    .sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity))
    .slice(0, 15);

  if (allFailed.length > 0) {
    const slide = pres.addSlide();
    slide.background = { color: P.white };

    slide.addText(t.remediationPlan, {
      x: 0.5, y: 0.3, w: 9, h: 0.6,
      fontSize: 28, fontFace: "Georgia", bold: true, color: P.navy, margin: 0
    });
    slide.addText(t.remediationNote, {
      x: 0.5, y: 0.85, w: 9, h: 0.3,
      fontSize: 12, fontFace: "Calibri", italic: true, color: P.darkGray, margin: 0
    });

    const rows = [[
      { text: t.num, options: { bold: true, color: P.white, fill: { color: P.navy }, fontSize: 9, fontFace: "Calibri" } },
      { text: t.severity, options: { bold: true, color: P.white, fill: { color: P.navy }, fontSize: 9, fontFace: "Calibri" } },
      { text: t.service, options: { bold: true, color: P.white, fill: { color: P.navy }, fontSize: 9, fontFace: "Calibri" } },
      { text: t.control, options: { bold: true, color: P.white, fill: { color: P.navy }, fontSize: 9, fontFace: "Calibri" } },
      { text: t.action, options: { bold: true, color: P.white, fill: { color: P.navy }, fontSize: 9, fontFace: "Calibri" } },
    ]];

    allFailed.forEach((f, i) => {
      rows.push([
        { text: String(i + 1), options: { fontSize: 8, fontFace: "Calibri", color: P.darkGray } },
        { text: f.severity, options: { color: SEV_COLORS[f.severity] || P.darkGray, bold: true, fontSize: 8, fontFace: "Calibri" } },
        { text: f.service.toUpperCase(), options: { fontSize: 8, fontFace: "Calibri", color: P.darkGray } },
        { text: f.control_id, options: { fontSize: 8, fontFace: "Calibri", color: P.navy } },
        { text: (f.remediation || "").substring(0, 100), options: { fontSize: 8, fontFace: "Calibri", color: P.darkGray } },
      ]);
    });

    const rh = Math.min(0.3, 3.8 / allFailed.length);
    slide.addTable(rows, {
      x: 0.5, y: 1.25, w: 9,
      colW: [0.4, 0.9, 0.8, 1.3, 5.6],
      border: { pt: 0.5, color: "E2E8F0" },
      rowH: [0.3, ...Array(allFailed.length).fill(rh)],
      autoPage: false,
    });
  }
}

// ════════════════════════════════════════════════════════════════════════════
// SLIDE 7 — Next Steps
// ════════════════════════════════════════════════════════════════════════════
{
  const slide = pres.addSlide();
  slide.background = { color: P.white };

  slide.addText(t.nextSteps, {
    x: 0.5, y: 0.3, w: 9, h: 0.6,
    fontSize: 28, fontFace: "Georgia", bold: true, color: P.navy, margin: 0
  });

  const steps = [t.step1, t.step2, t.step3, t.step4, t.step5];
  const stepItems = steps.map((s, i) => ({
    text: s,
    options: {
      bullet: true, breakLine: true,
      fontSize: 15, fontFace: "Calibri", color: P.darkGray,
      paraSpaceAfter: 14,
    }
  }));

  slide.addText(stepItems, {
    x: 0.8, y: 1.2, w: 8.4, h: 3.5,
  });

  // Timeline visual
  const timeframes = [
    { label: "24-48h", sev: "CRITICAL", clr: P.critical },
    { label: "1-2 wk", sev: "HIGH", clr: P.high },
    { label: "30 days", sev: "MEDIUM", clr: P.medium },
    { label: "Next maint.", sev: "LOW", clr: P.low },
  ];
  const barY = 4.6, barH = 0.6, barStartX = 0.8, barTotalW = 8.4;
  const segW = barTotalW / timeframes.length;

  timeframes.forEach((tf, i) => {
    slide.addShape(pres.shapes.RECTANGLE, {
      x: barStartX + i * segW, y: barY, w: segW - 0.05, h: barH,
      fill: { color: tf.clr },
    });
    slide.addText(`${tf.sev}\n${tf.label}`, {
      x: barStartX + i * segW, y: barY, w: segW - 0.05, h: barH,
      fontSize: 10, fontFace: "Calibri", bold: true, color: P.white,
      align: "center", valign: "middle",
    });
  });
}

// ════════════════════════════════════════════════════════════════════════════
// SLIDE 8 — Thank You / Closing
// ════════════════════════════════════════════════════════════════════════════
{
  const slide = pres.addSlide();
  slide.background = { color: P.darkNavy };

  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 0.06, h: 5.625, fill: { color: P.iceBlue }
  });

  slide.addText(t.thanksTitle, {
    x: 0.8, y: 1.5, w: 8.4, h: 1.2,
    fontSize: 44, fontFace: "Georgia", bold: true, color: P.white,
    align: "center", charSpacing: 4,
  });

  slide.addText(t.thanksBody, {
    x: 0.8, y: 2.8, w: 8.4, h: 0.6,
    fontSize: 20, fontFace: "Calibri", italic: true, color: P.iceBlue,
    align: "center",
  });

  slide.addText(`${data.auditor || "Security Auditor"}  |  ${dateStr}`, {
    x: 0.8, y: 4.2, w: 8.4, h: 0.4,
    fontSize: 12, fontFace: "Calibri", color: P.midGray,
    align: "center",
  });

  slide.addText(t.confidential, {
    x: 0.8, y: 4.8, w: 8.4, h: 0.35,
    fontSize: 10, fontFace: "Calibri", bold: true, color: P.fail,
    align: "center",
  });
}

// ── Write ───────────────────────────────────────────────────────────────────
pres.writeFile({ fileName: outputPath })
  .then(() => console.log(`PPTX saved: ${outputPath}`))
  .catch(err => { console.error("Error:", err); process.exit(1); });