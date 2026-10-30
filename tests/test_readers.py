"""Unit tests for DocumentReader (.txt, .csv, .pdf, .docx).

Zero try-except blocks used.
"""

import os
from scanner.readers import DocumentReader


def test_read_txt(tmp_path):
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("Hello KenyaShield Scanner", encoding="utf-8")

    res = DocumentReader.read_file(str(sample_file))
    assert res["valid"] is True
    assert res["file_type"] == "TXT"
    assert "Hello KenyaShield Scanner" in res["text"]


def test_read_csv(tmp_path):
    sample_csv = tmp_path / "sample.csv"
    sample_csv.write_text("Name,Phone\nWanjiku,0722123456\nKamau,0712345678\n", encoding="utf-8")

    res = DocumentReader.read_file(str(sample_csv))
    assert res["valid"] is True
    assert res["file_type"] == "CSV"
    assert res["dataframe"] is not None
    assert len(res["dataframe"]) == 2
    assert "Wanjiku" in res["text"]


def test_read_pdf_synthetic():
    pdf_path = os.path.join("data", "synthetic", "customer_kyc_statement.pdf")
    if os.path.exists(pdf_path):
        res = DocumentReader.read_file(pdf_path)
        assert res["valid"] is True
        assert res["file_type"] == "PDF"
        assert "CO-OPERATIVE BANK" in res["text"]
        assert "National ID" in res["text"]


def test_read_docx_synthetic():
    docx_path = os.path.join("data", "synthetic", "vendor_contract.docx")
    if os.path.exists(docx_path):
        res = DocumentReader.read_file(docx_path)
        assert res["valid"] is True
        assert res["file_type"] == "DOCX"
        assert "SERVICE LEVEL AGREEMENT" in res["text"]


def test_read_unsupported():
    res = DocumentReader.read_file("image.png")
    assert res["valid"] is False
    assert res["file_type"] == "UNSUPPORTED"
