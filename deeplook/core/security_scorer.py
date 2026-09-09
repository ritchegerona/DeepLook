"""Security scoring engine for DeepLook."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"


@dataclass
class Finding:
    category: str
    check: str
    status: FindingStatus
    risk: RiskLevel
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""


@dataclass
class CategoryScore:
    name: str
    score: int
    weight: float
    findings: list[Finding] = field(default_factory=list)

    @property
    def status_emoji(self) -> str:
        if self.score >= 80:
            return "GOOD"
        if self.score >= 60:
            return "PARTIAL"
        if self.score >= 40:
            return "NEEDS ATTENTION"
        return "POOR"


@dataclass
class SecurityReport:
    target: str
    overall_score: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    categories: list[CategoryScore] = field(default_factory=list)
    all_findings: list[Finding] = field(default_factory=list)

    @property
    def risk_emoji(self) -> str:
        return {
            RiskLevel.CRITICAL: "CRITICAL",
            RiskLevel.HIGH: "HIGH RISK",
            RiskLevel.MEDIUM: "MODERATE RISK",
            RiskLevel.LOW: "LOW RISK",
            RiskLevel.INFO: "INFO",
        }.get(self.risk_level, "UNKNOWN")

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.all_findings if f.risk == RiskLevel.CRITICAL]

    @property
    def high_findings(self) -> list[Finding]:
        return [f for f in self.all_findings if f.risk == RiskLevel.HIGH]

    @property
    def medium_findings(self) -> list[Finding]:
        return [f for f in self.all_findings if f.risk == RiskLevel.MEDIUM]


class SecurityScorer:
    """Calculate security scores from plugin results."""

    CATEGORY_WEIGHTS = {
        "SSL/TLS Security": 0.20,
        "DNS Security": 0.20,
        "Security Headers": 0.20,
        "Email Security": 0.15,
        "Exposure Risk": 0.15,
        "Breach Status": 0.10,
    }

    def __init__(self) -> None:
        self._findings: list[Finding] = []

    def add_finding(self, finding: Finding) -> None:
        self._findings.append(finding)

    def add_findings(self, findings: list[Finding]) -> None:
        self._findings.extend(findings)

    def calculate(self, target: str) -> SecurityReport:
        report = SecurityReport(target=target)
        report.all_findings = list(self._findings)

        category_findings: dict[str, list[Finding]] = {}
        for f in self._findings:
            category_findings.setdefault(f.category, []).append(f)

        for cat_name, weight in self.CATEGORY_WEIGHTS.items():
            findings = category_findings.get(cat_name, [])
            score = self._calculate_category_score(findings)
            cat_score = CategoryScore(
                name=cat_name,
                score=score,
                weight=weight,
                findings=findings,
            )
            report.categories.append(cat_score)

        if report.categories:
            report.overall_score = sum(int(c.score * c.weight) for c in report.categories)

        report.risk_level = self._determine_risk(report)
        return report

    def _calculate_category_score(self, findings: list[Finding]) -> int:
        if not findings:
            return 100

        total = len(findings)
        passed = sum(1 for f in findings if f.status == FindingStatus.PASS)
        warned = sum(1 for f in findings if f.status == FindingStatus.WARN)
        failed = sum(1 for f in findings if f.status == FindingStatus.FAIL)

        score = ((passed * 100) + (warned * 50) + (failed * 0)) / total
        return max(0, min(100, int(score)))

    def _determine_risk(self, report: SecurityReport) -> RiskLevel:
        if report.overall_score >= 80:
            return RiskLevel.LOW
        if report.overall_score >= 60:
            return RiskLevel.MEDIUM
        if report.overall_score >= 40:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL
