"""Unit tests for PIIRedactor masking, full redaction, and hashing.

Zero try-except blocks used.
"""

import os
from scanner.redactor import PIIRedactor


def test_redactor_mask_values():
    redactor = PIIRedactor()

    # Phone masking (preserve prefix and last 2 digits)
    masked_phone = redactor.mask_value("0712345678", "Phone Number")
    assert masked_phone.startswith("07")
    assert masked_phone.endswith("78")
    assert "*" in masked_phone

    # National ID masking
    masked_id = redactor.mask_value("28475910", "National ID")
    assert masked_id == "******10"

    # KRA PIN masking
    masked_pin = redactor.mask_value("A123456789Z", "KRA PIN")
    assert masked_pin == "A*********Z"

    # Email masking
    masked_email = redactor.mask_value("wanjiku@gmail.com", "Email Address")
    assert masked_email.startswith("w***@")
    assert masked_email.endswith(".com")


def test_redactor_full_redact():
    redactor = PIIRedactor()
    res = redactor.full_redact_value("28475910", "National ID")
    assert res == "[REDACTED_NATIONAL_ID]"


def test_redactor_hash_value():
    redactor = PIIRedactor()
    res = redactor.hash_value("A123456789Z", "KRA PIN")
    assert res.startswith("[SHA256:")
    assert res.endswith("]")


def test_redactor_text_multi_offset():
    redactor = PIIRedactor()
    text = "User John Doe has National ID: 28475910 and Phone: 0722123456."
    findings = [
        {"value": "28475910", "finding_type": "National ID", "start": 31, "end": 39},
        {"value": "0722123456", "finding_type": "Phone Number", "start": 51, "end": 61},
    ]

    redacted = redactor.redact_text(text, findings, method="mask")
    assert "28475910" not in redacted
    assert "0722123456" not in redacted
    assert "******10" in redacted
    assert "07******56" in redacted


def test_save_redacted_copy_non_destructive(tmp_path):
    redactor = PIIRedactor()
    orig_file = tmp_path / "original.txt"
    orig_file.write_text("Original confidential text with ID 12345678")

    out_dir = tmp_path / "redacted_output"
    redacted_text = "Original confidential text with ID ******78"

    saved_path = redactor.save_redacted_copy(str(orig_file), redacted_text, output_dir=str(out_dir))

    assert os.path.exists(saved_path)
    assert os.path.dirname(saved_path) == str(out_dir)
    # Ensure original was never modified or overwritten
    assert orig_file.read_text() == "Original confidential text with ID 12345678"
    assert "redacted_original.txt" in os.path.basename(saved_path)
