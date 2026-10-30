"""Document reader utilities for TXT, CSV, PDF, and DOCX files.

Zero try-except blocks used.
Handles file paths and Streamlit UploadedFile stream buffers.
"""

import io
import os
import pandas as pd
import pypdf
import docx


class DocumentReader:
    """Safely reads text content from supported file formats without try-except."""

    SUPPORTED_EXTENSIONS = [".txt", ".csv", ".pdf", ".docx"]

    @staticmethod
    def get_extension(file_reference) -> str:
        """Determine lower-cased file extension from a file path or UploadedFile."""
        if isinstance(file_reference, str):
            _, ext = os.path.splitext(file_reference)
            return ext.lower()
        if hasattr(file_reference, "name") and isinstance(file_reference.name, str):
            _, ext = os.path.splitext(file_reference.name)
            return ext.lower()
        return ""

    @staticmethod
    def get_filename(file_reference) -> str:
        """Extract base filename from path or file object."""
        if isinstance(file_reference, str):
            return os.path.basename(file_reference)
        if hasattr(file_reference, "name") and isinstance(file_reference.name, str):
            return file_reference.name
        return "uploaded_document"

    @classmethod
    def read_txt(cls, file_source) -> str:
        """Read plain text content safely."""
        if isinstance(file_source, str):
            if not os.path.exists(file_source) or not os.path.isfile(file_source):
                return ""
            with open(file_source, "r", encoding="utf-8", errors="replace") as f:
                return f.read()

        if hasattr(file_source, "read"):
            if hasattr(file_source, "seek"):
                file_source.seek(0)
            raw = file_source.read()
            if isinstance(raw, bytes):
                return raw.decode("utf-8", errors="replace")
            return str(raw)

        return ""

    @classmethod
    def read_csv(cls, file_source) -> tuple[str, pd.DataFrame | None]:
        """Read CSV file and extract textual representation alongside DataFrame."""
        df = None
        if isinstance(file_source, str):
            if not os.path.exists(file_source) or not os.path.isfile(file_source):
                return "", None
            df = pd.read_csv(file_source, dtype=str, keep_default_na=False)

        elif hasattr(file_source, "read"):
            if hasattr(file_source, "seek"):
                file_source.seek(0)
            df = pd.read_csv(file_source, dtype=str, keep_default_na=False)

        if df is None or df.empty:
            return "", df

        # Build readable text including header and rows
        lines = []
        lines.append(" | ".join(str(c) for c in df.columns))
        for _, row in df.iterrows():
            row_str = " | ".join(str(v) for v in row.values)
            lines.append(row_str)

        text_content = "\n".join(lines)
        return text_content, df

    @classmethod
    def read_pdf(cls, file_source) -> str:
        """Read text from PDF using pypdf."""
        reader = None
        if isinstance(file_source, str):
            if not os.path.exists(file_source) or not os.path.isfile(file_source):
                return ""
            reader = pypdf.PdfReader(file_source)
        elif hasattr(file_source, "read"):
            if hasattr(file_source, "seek"):
                file_source.seek(0)
            reader = pypdf.PdfReader(file_source)

        if reader is None:
            return ""

        extracted_pages = []
        for idx, page in enumerate(reader.pages):
            page_text = page.extract_text()
            if page_text and isinstance(page_text, str):
                extracted_pages.append(f"--- Page {idx + 1} ---\n{page_text}")

        return "\n\n".join(extracted_pages)

    @classmethod
    def read_docx(cls, file_source) -> str:
        """Read text from Word document using python-docx."""
        doc = None
        if isinstance(file_source, str):
            if not os.path.exists(file_source) or not os.path.isfile(file_source):
                return ""
            doc = docx.Document(file_source)
        elif hasattr(file_source, "read"):
            if hasattr(file_source, "seek"):
                file_source.seek(0)
            doc = docx.Document(file_source)

        if doc is None:
            return ""

        sections = []
        for p in doc.paragraphs:
            if p.text and p.text.strip():
                sections.append(p.text.strip())

        # Extract table cells
        for table in doc.tables:
            for row in table.rows:
                row_cells = [c.text.strip() for c in row.cells if c.text.strip()]
                if row_cells:
                    sections.append(" | ".join(row_cells))

        return "\n".join(sections)

    @classmethod
    def read_file(cls, file_source) -> dict:
        """Unified dispatch to read any supported document format."""
        ext = cls.get_extension(file_source)
        filename = cls.get_filename(file_source)

        if ext == ".txt":
            content = cls.read_txt(file_source)
            return {
                "filename": filename,
                "file_type": "TXT",
                "text": content,
                "dataframe": None,
                "valid": True,
            }

        if ext == ".csv":
            content, df = cls.read_csv(file_source)
            return {
                "filename": filename,
                "file_type": "CSV",
                "text": content,
                "dataframe": df,
                "valid": True,
            }

        if ext == ".pdf":
            content = cls.read_pdf(file_source)
            return {
                "filename": filename,
                "file_type": "PDF",
                "text": content,
                "dataframe": None,
                "valid": True,
            }

        if ext == ".docx":
            content = cls.read_docx(file_source)
            return {
                "filename": filename,
                "file_type": "DOCX",
                "text": content,
                "dataframe": None,
                "valid": True,
            }

        return {
            "filename": filename,
            "file_type": "UNSUPPORTED",
            "text": "",
            "dataframe": None,
            "valid": False,
        }
