# KenyaShield: Kenyan PII Scanner & Risk Assessor

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.59+-red.svg)](https://streamlit.io/)
[![spaCy](https://img.shields.io/badge/spaCy-3.8+-green.svg)](https://spacy.io/)

> [!WARNING]
> ### ⚠️ SYNTHETIC DATA ONLY NOTICE
> All sample datasets, names, national ID numbers, phone numbers, KRA PINs, M-Pesa codes, and medical records included in this repository and its test suite are **strictly synthetic and procedurally generated using Faker**. No real-world individuals, corporate entities, or data subjects are depicted.

---

## 🎯 Overview
**KenyaShield** is an automated personal data (PII) scanning and compliance auditing platform tailored to the statutory framework of the **Kenya Data Protection Act (KDPA) 2019**.

It inspects unstructured and structured documents (`.txt`, `.csv`, `.pdf`, `.docx`), extracts Kenyan identifiers, classifies findings into Personal vs. Sensitive Personal Data, computes file-level risk scores, and offers non-destructive redaction (masking, full redaction, SHA-256 hashing).

---

## 🛡️ Supported Data Types & Detection Logic

| Identifier | Detection Strategy | Statutory Reference |
| :--- | :--- | :--- |
| **Kenyan Phone Numbers** | Regex matching `+254` / `07xx` / `01xx` prefixes with 8 trailing digits. Supports spaces and dashes. | Section 2 (Direct Identifier) |
| **National ID (7-8 digits)** | Regex candidate search coupled with **proximity context verification** (`ID`, `National ID`, `Kitambulisho`, `ID No`). Rejects non-ID numbers (SKUs, order IDs). | Section 2 (National Identity) |
| **KRA Tax PIN** | Strict format validation: Letter + 9 Digits + Letter (`A123456789Z`, `P051234567X`). | Section 2 (Statutory Tax ID) |
| **Email Addresses** | RFC 5322 compatible regex email pattern. | Section 2 (Electronic Identifier) |
| **M-Pesa Transaction Codes** | 10-character alphanumeric syntax verified against transaction context keywords (`M-Pesa`, `Confirmed`, `Txn`, `Paybill`). | Section 2 (Financial Txn ID) |
| **Bank Account Numbers** | 10-14 digit candidate search near banking context keywords (`Account`, `A/C`, `Acc No`). | Section 2 (Financial Data) |
| **Names & Locations** | Natural Language Processing with **spaCy NER** (`PERSON`, `GPE`, `LOC`). | Section 2 (Personal Data) |
| **Sensitive Personal Data** | Keyword boundary detection across health (HIV, diagnosis), biometric (fingerprint, iris), and remuneration (salary, payslip). | Sections 2 & 44 (Special Category) |

---

## ⚖️ Mapping Features to Kenya Data Protection Act Principles

| KDPA Principle (Section 25 / Act) | KenyaShield Technical Implementation |
| :--- | :--- |
| **Section 25(a): Lawfulness, Fairness & Transparency** | Categorizes findings into formal legal categories and displays the statutory basis for every detected item. |
| **Section 25(b): Data Minimization** | Provides immediate in-app masking and redaction tools so analysts can strip unnecessary personal details from documents. |
| **Section 25(c): Purpose Limitation** | Identifies specific data categories to assist Data Protection Officers (DPOs) in validating whether collected data matches declared purposes. |
| **Section 25(f): Integrity and Confidentiality** | Implements non-destructive cryptographic pseudonymization (SHA-256) and stores redacted copies in separate directories without touching originals. |
| **Section 44: Processing Sensitive Personal Data** | Specifically isolates health, biometric, and financial data with high-visibility alerts and critical severity weighting. |

---

## 🔬 False-Positive Mitigation

Kenyan National ID numbers consist of 7 or 8 digits. A generic 8-digit regex would mistakenly flag product barcodes, warehouse SKUs, dates, and order numbers. 

KenyaShield enforces **Context-Aware Proximity Filtering**:
- An 8-digit sequence like `28475910` in `"Order # 28475910 completed"` is **ignored**.
- The same sequence in `"National ID No: 28475910"` is **flagged**.
- Verified in `tests/test_detector.py::test_detector_national_id_false_positive_prevention` and `data/synthetic/false_positive_control.txt`.

---

## 🚀 Quickstart & Installation

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.10, 3.11, 3.12, 3.14)
- Virtual environment recommended

### 2. Install Dependencies
```bash
cd pii-scanner
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 3. Generate Synthetic Benchmark Datasets
```bash
python generate_data.py
```

### 4. Run Pytest Test Suite
```bash
python -m pytest tests -v
```

### 5. Launch Streamlit Application
```bash
streamlit run app.py
```
Access the dashboard at `http://localhost:8501`.

---

## 🧪 Limitations & Engineering Considerations
1. **Regex Boundary Nuances**: Regular expressions match deterministic patterns. Heavily obfuscated numbers (e.g. written out phonetically) will require deep NLP models.
2. **Context Window Sizing**: The context window is calibrated to 40–50 characters. IDs separated from keywords by large paragraphs may require table-aware layout parsing.
3. **spaCy Corpora**: spaCy's `en_core_web_sm` model is pre-trained on English web text. Highly localized Kenyan colloquial names may benefit from gazetteer enrichment.

---

## 💼 Resume Entry
> **KenyaShield (Python, Streamlit, spaCy, Pandas, PyMuPDF, Plotly)**: Built an automated Kenyan personal data (PII) scanner aligned with the Kenya Data Protection Act 2019, detecting national IDs, KRA PINs, M-Pesa codes, and sensitive health/financial data across TXT, CSV, PDF, and DOCX files with zero-overwriting redaction.
