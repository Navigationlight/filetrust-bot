from filetrust.analyzers.common import check_name, check
from filetrust.detect import inspect_file
from filetrust.models import Finding
from filetrust.scoring.engine import score
import zipfile
from filetrust.analyzers.archive import check_zip
from filetrust.pipeline import analyze

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
def test_double_extension_is_high_risk():
    total, verdict = score(check_name("invoice.pdf.exe"))
    assert "ВИСОКИЙ" in verdict


def test_type_mismatch_is_at_least_suspicious(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"<!DOCTYPE html><html><body>hi</body></html>")
    info = inspect_file(p, "invoice.pdf")
    total, verdict = score(check(info))
    assert "ПІДОЗРІЛО" in verdict

def make_zip(path, files):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)


def test_zip_with_exe(tmp_path):
    p = tmp_path / "a.zip"
    make_zip(p, {"setup.exe": b"MZ" + b"\x00" * 100})
    info = inspect_file(p, "a.zip")
    assert info.kind == "zip"
    assert "ARCHIVE_EXEC" in ids(check_zip(info))


def test_zip_clean(tmp_path):
    p = tmp_path / "b.zip"
    make_zip(p, {"photo.jpg": b"x", "notes.txt": b"hello"})
    info = inspect_file(p, "b.zip")
    assert check_zip(info) == []


def test_zip_double_extension_inside(tmp_path):
    p = tmp_path / "c.zip"
    make_zip(p, {"invoice.pdf.exe": b"x"})
    info = inspect_file(p, "c.zip")
    assert "ARCHIVE_DOUBLE_EXT" in ids(check_zip(info))


def test_zip_path_traversal(tmp_path):
    p = tmp_path / "d.zip"
    make_zip(p, {"../evil.txt": b"x"})
    info = inspect_file(p, "d.zip")
    assert "ARCHIVE_PATH_TRAVERSAL" in ids(check_zip(info))


def test_pipeline_zip_with_exe_is_red(tmp_path):
    p = tmp_path / "e.zip"
    make_zip(p, {"setup.exe": b"MZ" + b"\x00" * 100})
    info, findings = analyze(p, "documents.zip")
    assert "ВИСОКИЙ" in score(findings)[1]
