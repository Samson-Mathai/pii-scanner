"""Unit tests for PIIClassifier risk scoring and categorization.

Zero try-except blocks used.
"""

from scanner.classifier import PIIClassifier


def test_classifier_personal_data():
    classifier = PIIClassifier()
    raw_finding = {
        "finding_type": "National ID",
        "value": "28475910",
        "start": 10,
        "end": 18,
    }
    enriched = classifier.classify_finding(raw_finding)
    assert enriched["category"] == "Personal Data"
    assert enriched["severity"] == "High"
    assert "Section 2" in enriched["legal_basis"]


def test_classifier_sensitive_personal_data():
    classifier = PIIClassifier()
    raw_finding = {
        "finding_type": "Sensitive Keyword",
        "sub_category": "Health Data",
        "value": "HIV",
        "start": 5,
        "end": 8,
    }
    enriched = classifier.classify_finding(raw_finding)
    assert enriched["category"] == "Sensitive Personal Data"
    assert enriched["severity"] == "Critical"
    assert "Section 44" in enriched["legal_basis"]


def test_file_risk_scoring_empty():
    classifier = PIIClassifier()
    risk = classifier.compute_file_risk([])
    assert risk["risk_score"] == 0
    assert risk["risk_level"] == "Low"
    assert risk["total_findings"] == 0


def test_file_risk_scoring_high_with_sensitive_data():
    classifier = PIIClassifier()
    findings = [
        {"finding_type": "Sensitive Keyword", "category": "Sensitive Personal Data", "severity": "Critical", "weight": 10},
        {"finding_type": "National ID", "category": "Personal Data", "severity": "High", "weight": 5},
        {"finding_type": "KRA PIN", "category": "Personal Data", "severity": "High", "weight": 5},
    ]
    risk = classifier.compute_file_risk(findings)
    assert risk["sensitive_data_count"] == 1
    assert risk["personal_data_count"] == 2
    # Because sensitive data is present, base score >= 65 -> High or Critical
    assert risk["risk_score"] >= 65
    assert risk["risk_level"] in ("High", "Critical")
