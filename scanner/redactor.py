"""Redaction engine supporting masking, full redaction, and cryptographic hashing.

Zero try-except blocks used.
Never overwrites original files.
"""

import os
import hashlib


class PIIRedactor:
    """Non-destructive redaction utilities for PII and sensitive data."""

    @staticmethod
    def mask_value(val: str, finding_type: str) -> str:
        """Produce partially masked representation of a sensitive value."""
        if not val or not isinstance(val, str):
            return ""

        length = len(val)

        if finding_type == "Phone Number":
            # Mask phone numbers: preserve leading prefix (07/01/+254) and last 2 digits
            digits_only = "".join(c for c in val if c.isdigit())
            if len(digits_only) >= 10:
                prefix = val[:2] if val.startswith("0") else val[:4]
                suffix = val[-2:]
                return f"{prefix}******{suffix}"
            return "07******45"

        elif finding_type == "National ID":
            # Mask national ID: keep only last 2 digits
            if length > 2:
                return "*" * (length - 2) + val[-2:]
            return "******"

        elif finding_type == "KRA PIN":
            # Mask KRA PIN: A123456789Z -> A*******Z
            if length >= 2:
                return val[0] + "*" * (length - 2) + val[-1]
            return "A*******Z"

        elif finding_type == "Email Address":
            # Mask email: j***@***.com
            if "@" in val:
                user_part, domain_part = val.split("@", 1)
                masked_user = user_part[0] + "***" if len(user_part) > 1 else "***"
                if "." in domain_part:
                    dot_idx = domain_part.rfind(".")
                    ext = domain_part[dot_idx:]
                    masked_domain = "***" + ext
                else:
                    masked_domain = "***.com"
                return f"{masked_user}@{masked_domain}"
            return "****@****.com"

        elif finding_type == "Bank Account Number":
            # Mask bank account: keep last 4 digits
            if length > 4:
                return "*" * (length - 4) + val[-4:]
            return "******1234"

        elif finding_type == "M-Pesa Code":
            # Mask M-Pesa: keep first 2 and last 2
            if length >= 4:
                return val[:2] + "*" * (length - 4) + val[-2:]
            return "QA******DE"

        elif finding_type == "Person Name":
            # Mask names: John Doe -> J*** D***
            parts = val.split()
            masked_parts = []
            for p in parts:
                if len(p) > 1:
                    masked_parts.append(p[0] + "***")
                else:
                    masked_parts.append("***")
            return " ".join(masked_parts) if masked_parts else "***"

        elif finding_type == "Sensitive Keyword":
            return "[CONFIDENTIAL-SENSITIVE]"

        # Default fallback masking
        if length > 4:
            return val[:2] + "*" * (length - 4) + val[-2:]
        return "*" * length

    @staticmethod
    def full_redact_value(val: str, finding_type: str) -> str:
        """Produce full redaction label."""
        type_clean = finding_type.upper().replace(" ", "_")
        return f"[REDACTED_{type_clean}]"

    @staticmethod
    def hash_value(val: str, finding_type: str, short: bool = True) -> str:
        """Produce one-way SHA-256 cryptographic digest of value."""
        digest = hashlib.sha256(val.strip().encode("utf-8")).hexdigest()
        digest_view = digest[:12] if short else digest
        return f"[SHA256:{digest_view}]"

    def redact_text(self, text: str, findings: list[dict], method: str = "mask") -> str:
        """Redact text using specified method ('mask', 'redact', 'hash')."""
        if not text or not findings:
            return text

        # Sort findings descending by start position to avoid index drift
        sorted_findings = sorted(findings, key=lambda f: f["start"], reverse=True)

        redacted = text
        for f in sorted_findings:
            start = f.get("start", -1)
            end = f.get("end", -1)
            val = f.get("value", "")
            ftype = f.get("finding_type", "Personal Data")

            if start < 0 or end > len(redacted) or start >= end:
                continue

            if method == "mask":
                replacement = self.mask_value(val, ftype)
            elif method == "hash":
                replacement = self.hash_value(val, ftype)
            else:
                replacement = self.full_redact_value(val, ftype)

            redacted = redacted[:start] + replacement + redacted[end:]

        return redacted

    def save_redacted_copy(
        self, original_path: str, redacted_content: str, output_dir: str = "data/redacted"
    ) -> str:
        """Persist redacted file in separate output folder, never overwriting original."""
        os.makedirs(output_dir, exist_ok=True)

        base_name = os.path.basename(original_path) if original_path else "document.txt"
        name_root, ext = os.path.splitext(base_name)
        if not ext:
            ext = ".txt"

        destination_name = f"redacted_{name_root}{ext}"
        destination_path = os.path.join(output_dir, destination_name)

        # Ensure unique filename if collision exists
        counter = 1
        while os.path.exists(destination_path):
            destination_name = f"redacted_{name_root}_{counter}{ext}"
            destination_path = os.path.join(output_dir, destination_name)
            counter += 1

        with open(destination_path, "w", encoding="utf-8") as f:
            f.write(redacted_content)

        return destination_path
