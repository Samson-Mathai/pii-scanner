"""Unit tests for the PIIDetector scanning engine.

Zero try-except blocks used.
"""

from scanner.detector import PIIDetector


def test_detector_phone():
    detector = PIIDetector()
    text = "Please reach our office representative at +254 722 123 456 or 0712345678."
    findings = detector.scan_phones(text)
    assert len(findings) == 2
    types = [f["finding_type"] for f in findings]
    assert all(t == "Phone Number" for t in types)


def test_detector_national_id_with_keyword():
    detector = PIIDetector()
    text = "The applicant's National ID No: 28475910 was submitted on form."
    findings = detector.scan_national_ids(text)
    assert len(findings) == 1
    assert findings[0]["value"] == "28475910"
    assert findings[0]["finding_type"] == "National ID"


def test_detector_national_id_false_positive_prevention():
    """Crucial requirement: 7-8 digit numbers WITHOUT context keywords MUST NOT be flagged."""
    detector = PIIDetector()
    control_text = "Warehouse SKU 28475910 and item batch 12345678 were shipped in crate 87654321."
    findings = detector.scan_national_ids(control_text)
    # MUST be 0 findings because no ID keywords are present
    assert len(findings) == 0, f"Expected 0 findings but got: {findings}"


def test_detector_kra_pin():
    detector = PIIDetector()
    text = "Tax compliance certificate issued under KRA PIN A123456789Z."
    findings = detector.scan_kra_pins(text)
    assert len(findings) == 1
    assert findings[0]["value"] == "A123456789Z"
    assert findings[0]["finding_type"] == "KRA PIN"


def test_detector_mpesa_code():
    detector = PIIDetector()
    text = "QA12BC34DE Confirmed. Ksh 4,500 sent to Alice on M-Pesa."
    findings = detector.scan_mpesa_codes(text)
    assert len(findings) == 1
    assert findings[0]["value"] == "QA12BC34DE"
    assert findings[0]["finding_type"] == "M-Pesa Code"


def test_detector_bank_account():
    detector = PIIDetector()
    text = "Please deposit monthly funds into Bank Account Number: 010203040506."
    findings = detector.scan_bank_accounts(text)
    assert len(findings) == 1
    assert findings[0]["value"] == "010203040506"
    assert findings[0]["finding_type"] == "Bank Account Number"


def test_detector_sensitive_keywords():
    detector = PIIDetector()
    text = "The clinical report confirms the diagnosis and HIV treatment plan, along with monthly salary KES 90,000."
    findings = detector.scan_sensitive_keywords(text)
    assert len(findings) >= 3
    sub_cats = [f["sub_category"] for f in findings]
    assert "Health Data" in sub_cats
    assert "Financial & Property Data" in sub_cats


def test_detector_comprehensive_scan():
    detector = PIIDetector()
    sample_text = (
        "Client Wanjiku Kimani, National ID: 28475910, KRA PIN: P051234567X, "
        "Phone: 0722123456, Email: wanjiku@example.co.ke. "
        "Submitted biometric fingerprint for verification."
    )
    results = detector.scan(sample_text)
    assert len(results) >= 5
    types_found = {r["finding_type"] for r in results}
    assert "National ID" in types_found
    assert "KRA PIN" in types_found
    assert "Phone Number" in types_found
    assert "Email Address" in types_found
    assert "Sensitive Keyword" in types_found
