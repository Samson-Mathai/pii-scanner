"""Regex patterns and keyword definitions for Kenyan PII detection.

Aligned with the Kenya Data Protection Act 2019.
Zero try-except blocks used.
"""

import re

# Phone Number Pattern: Kenyan prefixes (+254 or 0 followed by 7xx or 1xx and 6 digits)
# Supports optional hyphens and spaces after country code and within digits
KENYAN_PHONE_PATTERN = re.compile(
    r"(?:\+254|0)[\s\-]?(?:7[0-9]{2}|1[0-9]{2})[\s\-]?[0-9]{3}[\s\-]?[0-9]{3}\b"
)

# National ID Pattern: 7 or 8 digits
NATIONAL_ID_CANDIDATE_PATTERN = re.compile(r"\b[0-9]{7,8}\b")

# Keywords that must appear within context of a National ID to avoid false positives
NATIONAL_ID_CONTEXT_KEYWORDS = [
    "national id",
    "id no",
    "id num",
    "id number",
    "id#",
    "id:",
    "id -",
    "kitambulisho",
    "identity card",
    "identity no",
    "nat id",
    "kenyan id",
    "national identity",
    "id ",
]

# KRA PIN Pattern: 1 letter + 9 digits + 1 letter (e.g., A123456789Z)
KRA_PIN_PATTERN = re.compile(r"\b[A-Za-z][0-9]{9}[A-Za-z]\b")

# Email Address Pattern (RFC 5322 compatible)
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# M-Pesa Transaction Code: 10 uppercase alphanumeric characters
MPESA_CODE_CANDIDATE_PATTERN = re.compile(r"\b[A-Z0-9]{10}\b")

# Context keywords for M-Pesa codes
MPESA_CONTEXT_KEYWORDS = [
    "mpesa",
    "m-pesa",
    "transaction",
    "txn",
    "receipt",
    "paybill",
    "till",
    "confirmation",
    "confirmed",
    "lipa na m-pesa",
    "sent to",
    "received from",
    "pesa",
]

# Bank Account Number: 10-14 digits near banking context
BANK_ACCOUNT_CANDIDATE_PATTERN = re.compile(r"\b[0-9]{10,14}\b")

# Bank Account Context Keywords
BANK_ACCOUNT_CONTEXT_KEYWORDS = [
    "account",
    "acc no",
    "a/c no",
    "a/c",
    "acct",
    "account number",
    "bank account",
    "bank acc",
    "bank a/c",
    "acc:",
    "a/c:",
]

# Sensitive Personal Data Keywords (Sections 2 & 44, Kenya Data Protection Act 2019)
SENSITIVE_KEYWORDS_MAP = {
    "Health Data": [
        "diagnosis",
        "hiv",
        "aids",
        "medical",
        "treatment",
        "patient",
        "prescription",
        "cancer",
        "tuberculosis",
        "clinical notes",
        "hospital admission",
        "doctor note",
        "illness",
    ],
    "Biometric Data": [
        "fingerprint",
        "biometric",
        "retina scan",
        "iris scan",
        "facial recognition",
        "dna",
        "genetic data",
    ],
    "Financial & Property Data": [
        "salary",
        "net pay",
        "gross pay",
        "remuneration",
        "payslip",
        "basic salary",
        "allowance",
        "property details",
        "mortgage balance",
        "credit score",
    ],
    "Beliefs & Private Status": [
        "religion",
        "religious belief",
        "ethnicity",
        "ethnic group",
        "philosophical belief",
        "sexual orientation",
        "marital status",
    ],
}
