# Privacy by Design Analysis: KenyaShield Architecture

Aligned with Dr. Ann Cavoukian's 7 Foundational Principles of **Privacy by Design (PbD)** and statutory guidelines under the **Office of the Data Protection Commissioner (ODPC) Kenya**.

---

## 1. Proactive not Reactive; Preventative not Remedial
- **Implementation**: KenyaShield intercepts unencrypted documents *before* they are shared, published, or transmitted to third parties.
- **Preventative Controls**: Instead of reacting to data breaches after personal data has been leaked, KenyaShield identifies unmasked identifiers (e.g., KRA PINs, National IDs, M-Pesa transaction histories) and enforces remediation prior to distribution.

## 2. Privacy as the Default Setting
- **Default Redaction**: In the redaction workflow, the default option is **Masking** (preserving operational utility while anonymizing personal identifiers).
- **Zero Cloud Leakage**: KenyaShield operates 100% locally on the host machine. Uploaded files are processed in memory and never transmitted to external APIs or remote third-party cloud servers.

## 3. Privacy Embedded into Design
- **Core Architecture**: Data protection rules are not retrofitted; the scanner's classification hierarchy directly encodes Section 2 and Section 44 of the Kenya Data Protection Act 2019 into the detector and classifier classes.
- **Zero Try-Except Architecture**: Strict defensive programming ensures system reliability, eliminating silent failures or unhandled data states.

## 4. Full Functionality – Positive-Sum, not Zero-Sum
- **Operational Utility Retained**: Data masking allows analytical workflows (such as customer distribution modeling or billing audits) to continue unobstructed without exposing plain-text phone numbers or national IDs.
- **Multiple Redaction Paradigms**: Provides granular choices between partial masking (`07******45`), full redaction (`[REDACTED_PHONE_NUMBER]`), and cryptographic pseudonymization (`[SHA256:...]`).

## 5. End-to-End Security – Full Lifecycle Protection
- **Non-Destructive Processing**: KenyaShield strictly isolates redacted outputs in separate destination folders (`data/redacted/`), guaranteeing that original raw records are never overwritten or corrupted.
- **Deterministic Pseudonymization**: SHA-256 cryptographic digests allow analysts to perform record linkages across datasets without reversing plain-text identifiers.

## 6. Visibility and Transparency – Keep it Open
- **Explainable Detections**: Every detection reported in the register details the exact character slice, surrounding context snippet, line number, and specific statutory section under the Kenya Data Protection Act 2019.
- **False-Positive Prevention**: Clear documentation and automated benchmark suites (`tests/test_detector.py`) demonstrate why numbers are included or excluded from categorization.

## 7. Respect for User Privacy – Keep it User-Centric
- **Local Control**: Data Protection Officers and Privacy Analysts retain full control over file retention, export locations, and redaction levels.
- **Synthetic Test Benchmarks**: Development and onboarding do not require access to actual customer records; comprehensive synthetic Faker datasets allow full functional validation without privacy liability.
