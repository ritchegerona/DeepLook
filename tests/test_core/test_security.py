"""Tests for security scorer."""

from deeplook.core.security_scorer import (
    Finding,
    FindingStatus,
    RiskLevel,
    SecurityScorer,
)


class TestSecurityScorer:
    def test_calculate_all_pass(self):
        scorer = SecurityScorer()
        scorer.add_finding(
            Finding(
                category="SSL/TLS Security",
                check="ssl_version",
                status=FindingStatus.PASS,
                risk=RiskLevel.INFO,
                message="Strong SSL",
            )
        )
        report = scorer.calculate("example.com")
        assert report.overall_score >= 80
        assert report.risk_level == RiskLevel.LOW

    def test_calculate_all_fail(self):
        scorer = SecurityScorer()
        scorer.add_finding(
            Finding(
                category="SSL/TLS Security",
                check="ssl_version",
                status=FindingStatus.FAIL,
                risk=RiskLevel.CRITICAL,
                message="Weak SSL",
            )
        )
        report = scorer.calculate("example.com")
        ssl_cat = next(c for c in report.categories if c.name == "SSL/TLS Security")
        assert ssl_cat.score == 0
        assert report.overall_score < 100

    def test_calculate_mixed(self):
        scorer = SecurityScorer()
        scorer.add_finding(
            Finding(
                category="SSL/TLS Security",
                check="ssl_version",
                status=FindingStatus.PASS,
                risk=RiskLevel.INFO,
                message="Strong SSL",
            )
        )
        scorer.add_finding(
            Finding(
                category="DNS Security",
                check="dmarc",
                status=FindingStatus.FAIL,
                risk=RiskLevel.CRITICAL,
                message="No DMARC",
            )
        )
        report = scorer.calculate("example.com")
        assert 0 <= report.overall_score <= 100
        assert len(report.categories) == 6

    def test_critical_findings(self):
        scorer = SecurityScorer()
        scorer.add_finding(
            Finding(
                category="SSL/TLS Security",
                check="ssl_version",
                status=FindingStatus.FAIL,
                risk=RiskLevel.CRITICAL,
                message="Critical issue",
            )
        )
        report = scorer.calculate("example.com")
        assert len(report.critical_findings) == 1

    def test_empty_findings(self):
        scorer = SecurityScorer()
        report = scorer.calculate("example.com")
        assert report.overall_score == 100
        assert report.risk_level == RiskLevel.LOW
