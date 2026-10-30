"""Scanning engine combining regex patterns, context validation, and spaCy NER.

Zero try-except blocks used.
"""

import re
import spacy
from scanner.patterns import (
    KENYAN_PHONE_PATTERN,
    NATIONAL_ID_CANDIDATE_PATTERN,
    NATIONAL_ID_CONTEXT_KEYWORDS,
    KRA_PIN_PATTERN,
    EMAIL_PATTERN,
    MPESA_CODE_CANDIDATE_PATTERN,
    MPESA_CONTEXT_KEYWORDS,
    BANK_ACCOUNT_CANDIDATE_PATTERN,
    BANK_ACCOUNT_CONTEXT_KEYWORDS,
    SENSITIVE_KEYWORDS_MAP,
)


class PIIDetector:
    """Core PII and sensitive data scanner for Kenyan context."""

    def __init__(self):
        # Defensive initialization of spaCy without try-except
        if spacy.util.is_package("en_core_web_sm"):
            self.nlp = spacy.load("en_core_web_sm")
        else:
            self.nlp = spacy.blank("en")

    def _extract_context(self, text: str, start: int, end: int, window: int = 40) -> str:
        """Extract a snippet of text surrounding the match."""
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        return text[ctx_start:ctx_end]

    def _calculate_line_number(self, text: str, start: int) -> int:
        """Return 1-based line number for a character offset."""
        if start <= 0:
            return 1
        return text[:start].count("\n") + 1

    def _has_context_keyword(self, context_text: str, keywords: list[str]) -> bool:
        """Check if any keyword appears in the given context (case-insensitive)."""
        lower_ctx = context_text.lower()
        for kw in keywords:
            if kw.lower() in lower_ctx:
                return True
        return False

    def scan_phones(self, text: str) -> list[dict]:
        """Detect Kenyan telephone numbers."""
        findings = []
        for match in KENYAN_PHONE_PATTERN.finditer(text):
            val = match.group(0).strip()
            findings.append({
                "finding_type": "Phone Number",
                "value": val,
                "start": match.start(),
                "end": match.end(),
                "context": self._extract_context(text, match.start(), match.end()),
                "line_number": self._calculate_line_number(text, match.start()),
            })
        return findings

    def scan_national_ids(self, text: str) -> list[dict]:
        """Detect Kenyan National IDs, strictly requiring context keywords."""
        findings = []
        for match in NATIONAL_ID_CANDIDATE_PATTERN.finditer(text):
            val = match.group(0)
            context = self._extract_context(text, match.start(), match.end(), window=45)
            # Only flag as National ID when explicitly near relevant ID keywords
            if self._has_context_keyword(context, NATIONAL_ID_CONTEXT_KEYWORDS):
                findings.append({
                    "finding_type": "National ID",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "context": context,
                    "line_number": self._calculate_line_number(text, match.start()),
                })
        return findings

    def scan_kra_pins(self, text: str) -> list[dict]:
        """Detect Kenya Revenue Authority (KRA) Tax PINs."""
        findings = []
        for match in KRA_PIN_PATTERN.finditer(text):
            val = match.group(0).upper()
            findings.append({
                "finding_type": "KRA PIN",
                "value": val,
                "start": match.start(),
                "end": match.end(),
                "context": self._extract_context(text, match.start(), match.end()),
                "line_number": self._calculate_line_number(text, match.start()),
            })
        return findings

    def scan_emails(self, text: str) -> list[dict]:
        """Detect email addresses."""
        findings = []
        for match in EMAIL_PATTERN.finditer(text):
            val = match.group(0)
            findings.append({
                "finding_type": "Email Address",
                "value": val,
                "start": match.start(),
                "end": match.end(),
                "context": self._extract_context(text, match.start(), match.end()),
                "line_number": self._calculate_line_number(text, match.start()),
            })
        return findings

    def scan_mpesa_codes(self, text: str) -> list[dict]:
        """Detect M-Pesa transaction reference codes with context verification."""
        findings = []
        for match in MPESA_CODE_CANDIDATE_PATTERN.finditer(text):
            val = match.group(0)
            # M-Pesa codes have both letters and digits, or follow 10-char uppercase convention
            has_letter = any(c.isalpha() for c in val)
            has_digit = any(c.isdigit() for c in val)
            if not (has_letter and has_digit):
                continue

            context = self._extract_context(text, match.start(), match.end(), window=50)
            if self._has_context_keyword(context, MPESA_CONTEXT_KEYWORDS):
                findings.append({
                    "finding_type": "M-Pesa Code",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "context": context,
                    "line_number": self._calculate_line_number(text, match.start()),
                })
        return findings

    def scan_bank_accounts(self, text: str) -> list[dict]:
        """Detect Bank Account numbers (10-14 digits) near banking context."""
        findings = []
        for match in BANK_ACCOUNT_CANDIDATE_PATTERN.finditer(text):
            val = match.group(0)
            context = self._extract_context(text, match.start(), match.end(), window=45)
            if self._has_context_keyword(context, BANK_ACCOUNT_CONTEXT_KEYWORDS):
                findings.append({
                    "finding_type": "Bank Account Number",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "context": context,
                    "line_number": self._calculate_line_number(text, match.start()),
                })
        return findings

    def scan_sensitive_keywords(self, text: str) -> list[dict]:
        """Detect keywords indicating sensitive personal data under the Act."""
        findings = []
        lower_text = text.lower()
        for category, keywords in SENSITIVE_KEYWORDS_MAP.items():
            for kw in keywords:
                # Word boundary match for sensitive keywords
                pattern = re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
                for match in pattern.finditer(text):
                    findings.append({
                        "finding_type": "Sensitive Keyword",
                        "sub_category": category,
                        "value": match.group(0),
                        "start": match.start(),
                        "end": match.end(),
                        "context": self._extract_context(text, match.start(), match.end()),
                        "line_number": self._calculate_line_number(text, match.start()),
                    })
        return findings

    def scan_entities_ner(self, text: str) -> list[dict]:
        """Extract person names and locations using spaCy NER."""
        findings = []
        if not hasattr(self.nlp, "pipe_names") or "ner" not in self.nlp.pipe_names:
            return findings

        # Limit text chunk size if very large to prevent memory overhead
        process_text = text[:100000]
        doc = self.nlp(process_text)

        for ent in doc.ents:
            if ent.label_ == "PERSON":
                val = ent.text.strip()
                # Skip trivial single-character names or common words
                if len(val) >= 3 and "\n" not in val:
                    findings.append({
                        "finding_type": "Person Name",
                        "value": val,
                        "start": ent.start_char,
                        "end": ent.end_char,
                        "context": self._extract_context(text, ent.start_char, ent.end_char),
                        "line_number": self._calculate_line_number(text, ent.start_char),
                    })
            elif ent.label_ in ("GPE", "LOC"):
                val = ent.text.strip()
                if len(val) >= 3 and "\n" not in val:
                    findings.append({
                        "finding_type": "Location",
                        "value": val,
                        "start": ent.start_char,
                        "end": ent.end_char,
                        "context": self._extract_context(text, ent.start_char, ent.end_char),
                        "line_number": self._calculate_line_number(text, ent.start_char),
                    })
        return findings

    def scan(self, text: str) -> list[dict]:
        """Perform comprehensive scan across all detector modules."""
        if not text or not isinstance(text, str):
            return []

        all_findings = []
        all_findings.extend(self.scan_phones(text))
        all_findings.extend(self.scan_national_ids(text))
        all_findings.extend(self.scan_kra_pins(text))
        all_findings.extend(self.scan_emails(text))
        all_findings.extend(self.scan_mpesa_codes(text))
        all_findings.extend(self.scan_bank_accounts(text))
        all_findings.extend(self.scan_sensitive_keywords(text))
        all_findings.extend(self.scan_entities_ner(text))

        # Deduplicate overlapping matches: keep more specific pattern if overlap occurs
        all_findings.sort(key=lambda f: (f["start"], -(f["end"] - f["start"])))

        deduped = []
        last_end = -1
        for item in all_findings:
            if item["start"] >= last_end:
                deduped.append(item)
                last_end = item["end"]

        return deduped
