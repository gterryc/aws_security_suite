from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

from schemas.finding import Finding, Severity, Status


class ServiceSummary(BaseModel):
    service:  str
    total:    int
    passed:   int
    failed:   int
    skipped:  int
    score:    float = Field(..., description="passed / (total - skipped) * 100")


class Report(BaseModel):
    # Metadata
    account_id:    str
    region:        str
    generated_at:  datetime      = Field(default_factory=datetime.utcnow)
    auditor:       Optional[str] = None

    # Hallazgos
    findings:      list[Finding] = Field(default_factory=list)

    # Resumen calculado
    total_controls:   int = 0
    passed_controls:  int = 0
    failed_controls:  int = 0
    skipped_controls: int = 0
    global_score:     float = 0.0

    by_severity:   dict[str, int] = Field(default_factory=dict)
    by_service:    list[ServiceSummary] = Field(default_factory=list)

    def compute_summary(self) -> None:
        self.total_controls   = len(self.findings)
        self.passed_controls  = sum(1 for f in self.findings if f.status == Status.PASS)
        self.failed_controls  = sum(1 for f in self.findings if f.status == Status.FAIL)
        self.skipped_controls = sum(1 for f in self.findings if f.status == Status.SKIP)

        evaluable = self.total_controls - self.skipped_controls
        self.global_score = round(self.passed_controls / evaluable * 100, 1) if evaluable else 0.0

        self.by_severity = {s.value: 0 for s in Severity}
        for f in self.findings:
            self.by_severity[f.severity.value] += 1

        services = {}
        for f in self.findings:
            if f.service not in services:
                services[f.service] = {"total": 0, "passed": 0, "failed": 0, "skipped": 0}
            services[f.service]["total"] += 1
            if f.status == Status.PASS:
                services[f.service]["passed"] += 1
            elif f.status == Status.FAIL:
                services[f.service]["failed"] += 1
            else:
                services[f.service]["skipped"] += 1

        self.by_service = []
        for svc, counts in services.items():
            ev = counts["total"] - counts["skipped"]
            score = round(counts["passed"] / ev * 100, 1) if ev else 0.0
            self.by_service.append(ServiceSummary(service=svc, score=score, **counts))