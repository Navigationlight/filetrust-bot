from filetrust.analyzers.common import check_name, check
from filetrust.detect import inspect_file
from filetrust.models import Finding
from filetrust.scoring.engine import score

def ids(findings):
    return [f.id for f in findings]

def test_double_extension():
    assert "DOUBLE_EXT" in ids(check_name("invoice.pdf.exe"))

def test_rtlo():
    assert "RTLO" in ids(check_name("photo\u202egpj.exe"))

def test_clean_name():
    assert check_name("report.pdf") == []

def test_pdf_pretending_to_be_exe(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")
    info = inspect_file(p, "setup.exe")
    assert info.kind == "pdf"
    assert "TYPE_MISMATCH" in ids(check(info))

def test_score_levels():
    assert "ВИСОКИЙ" in score([Finding("A", 70, "")])[1]
    assert score([Finding("A", 80, ""), Finding("B", 80, "")])[0] == 100
