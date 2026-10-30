"""Classification and risk scoring under the Kenya Data Protection Act 2019.

Zero try-except blocks used.
"""


class PIIClassifier:
    """Classifies findings into Personal vs Sensitive Personal Data and calculates risk scores."""

    SEVERITY_WEIGHTS = {
        "Low": 1,
        "Medium": 3,
        "High": 5,
        "Critical": 10,
    }

    TYPE_CONFIG = {
        "Email Address": {
            "category": "Personal Data",
            "severity": "Low",
            "legal_basis": "Section 2, Kenya Data Protection Act 2019 (Identifier)",
        },
        "Location": {
            "category": "Personal Data",
            "severity": "Low",
            "legal_basis": "Section 2, Kenya Data Protection Act 2019 (Location Data)",
        },
        "Phone Number": {
            "category": "Personal Data",
            "severity": "Medium",
            "legal_basis": "Section 2, Kenya Data Protection Act 2019 (Direct Identifier)",
        },
        "Person Name": {
            "category": "Personal Data",
            "severity": "Medium",
            "legal_basis": "Section 2, Kenya Data Protection Act 2019 (Identity Data)",
        },
        "M-Pesa Code": {
            "category": "Personal Data",
            "severity": "Medium",
            "legal_basis": "Section 2, Kenya Data Protection Act 2019 (Transaction Identifier)",
        },
        "National ID": {
            "category": "Personal Data",
            "severity": "High",
            "legal_basis": "Section 2, Kenya Data Protection Act 2019 (National Identification)",
        },
        "KRA PIN": {
            "category": "Personal Data",
            "severity": "High",
            "legal_basis": "Section 2, Kenya Data Protection Act 2019 (Statutory Tax Identifier)",
        },
        "Bank Account Number": {
            "category": "Personal Data",
            "severity": "High",
            "legal_basis": "Section 2, Kenya Data Protection Act 2019 (Financial Account Identifier)",
        },
        "Sensitive Keyword": {
            "category": "Sensitive Personal Data",
            "severity": "Critical",
            "legal_basis": "Section 44, Kenya Data Protection Act 2019 (Special Category Data)",
        },
    }

    def classify_finding(self, finding: dict) -> dict:
        """Enrich a finding dictionary with classification, severity, and legal reference."""
        ftype = finding.get("finding_type", "Personal Data")
        cfg = self.TYPE_CONFIG.get(ftype, {
            "category": "Personal Data",
            "severity": "Medium",
            "legal_basis": "Kenya Data Protection Act 2019",
        })

        enriched = dict(finding)
        enriched["category"] = cfg["category"]
        enriched["severity"] = cfg["severity"]
        enriched["legal_basis"] = cfg["legal_basis"]
        enriched["weight"] = self.SEVERITY_WEIGHTS.get(cfg["severity"], 2)
        return enriched

    def classify_all(self, findings: list[dict]) -> list[dict]:
        """Classify a list of raw findings."""
        if not findings:
            return []
        return [self.classify_finding(f) for f in findings]

    def compute_file_risk(self, enriched_findings: list[dict]) -> dict:
        """Compute file-level risk score, severity distributions, and summary metrics."""
        if not enriched_findings:
            return {
                "total_findings": 0,
                "personal_data_count": 0,
                "sensitive_data_count": 0,
                "risk_score": 0,
                "risk_level": "Low",
                "severity_counts": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
                "type_counts": {},
            }

        personal_count = 0
        sensitive_count = 0
        severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        type_counts = {}
        raw_weighted_score = 0

        for f in enriched_findings:
            category = f.get("category", "Personal Data")
            if category == "Sensitive Personal Data":
                sensitive_count += 1
            else:
                personal_count += 1

            sev = f.get("severity", "Low")
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts[sev] = 1

            ftype = f.get("finding_type", "Unknown")
            type_counts[ftype] = type_counts.get(ftype, 0) + 1

            raw_weighted_score += f.get("weight", 1)

        # Scale risk score to 0 - 100
        # If any Critical finding exists, baseline score is at least 65 (High)
        base_score = 65 if sensitive_count > 0 else 0
        scaled_score = min(100, base_score + int(raw_weighted_score * 2.5))
        if len(enriched_findings) == 0:
            scaled_score = 0

        if scaled_score <= 25:
            risk_level = "Low"
        elif scaled_score <= 60:
            risk_level = "Medium"
        elif scaled_score <= 85:
            risk_level = "High"
        else:
            risk_level = "Critical"

        return {
            "total_findings": len(enriched_findings),
            "personal_data_count": personal_count,
            "sensitive_data_count": sensitive_count,
            "risk_score": scaled_score,
            "risk_level": risk_level,
            "severity_counts": severity_counts,
            "type_counts": type_counts,
        }
