"""Unit tests for KenyaShield regex patterns.

Zero try-except blocks used.
"""

from scanner.patterns import (
    KENYAN_PHONE_PATTERN,
    NATIONAL_ID_CANDIDATE_PATTERN,
    KRA_PIN_PATTERN,
    EMAIL_PATTERN,
    MPESA_CODE_CANDIDATE_PATTERN,
    BANK_ACCOUNT_CANDIDATE_PATTERN,
)


def test_kenyan_phone_pattern():
    valid_phones = [
        "+254712345678",
        "+254 722 123 456",
        "+254-733-987-654",
        "0712345678",
        "0722-123-456",
        "0110123456",
        "0112 345 678",
    ]
    for p in valid_phones:
        assert KENYAN_PHONE_PATTERN.search(p) is not None, f"Failed on phone: {p}"

    invalid_phones = [
        "123456",
        "+1234567890",
        "0812345678",  # 08 is not a Kenyan prefix
    ]
    for p in invalid_phones:
        assert KENYAN_PHONE_PATTERN.search(p) is None, f"Should not match: {p}"


def test_kra_pin_pattern():
    valid_pins = [
        "A123456789Z",
        "P051234567X",
        "a987654321b",
    ]
    for pin in valid_pins:
        assert KRA_PIN_PATTERN.search(pin) is not None, f"Failed on KRA PIN: {pin}"

    invalid_pins = [
        "123456789",
        "AB123456789Z",  # 2 letters at start
        "A12345678Z",    # Only 8 digits
        "A1234567890Z",  # 10 digits
    ]
    for pin in invalid_pins:
        assert KRA_PIN_PATTERN.search(pin) is None, f"Should not match: {pin}"


def test_email_pattern():
    valid_emails = [
        "john.doe@gmail.com",
        "wanjiku@enterprise.co.ke",
        "user+test@sub.domain.org",
    ]
    for email in valid_emails:
        assert EMAIL_PATTERN.search(email) is not None, f"Failed on email: {email}"

    invalid_emails = [
        "notanemail",
        "@missinguser.com",
        "missingdomain@.com",
    ]
    for email in invalid_emails:
        assert EMAIL_PATTERN.search(email) is None, f"Should not match: {email}"


def test_mpesa_candidate_pattern():
    valid_codes = [
        "QA12BC34DE",
        "SB45F6789Z",
        "QK89LM4321",
    ]
    for code in valid_codes:
        assert MPESA_CODE_CANDIDATE_PATTERN.search(code) is not None, f"Failed on M-Pesa: {code}"

    invalid_codes = [
        "SHORT1",
        "TOOLONGCODE1234",
        "lowercase1",
    ]
    for code in invalid_codes:
        assert MPESA_CODE_CANDIDATE_PATTERN.search(code) is None, f"Should not match: {code}"


def test_bank_account_candidate_pattern():
    valid_accounts = [
        "0123456789",      # 10 digits
        "12345678901234",  # 14 digits
    ]
    for acc in valid_accounts:
        assert BANK_ACCOUNT_CANDIDATE_PATTERN.search(acc) is not None, f"Failed on account: {acc}"

    invalid_accounts = [
        "12345678",        # 8 digits (too short)
        "123456789012345", # 15 digits (too long)
    ]
    for acc in invalid_accounts:
        assert BANK_ACCOUNT_CANDIDATE_PATTERN.search(acc) is None, f"Should not match: {acc}"
