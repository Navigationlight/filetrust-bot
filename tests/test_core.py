from filetrust.analyzers.common import check_name, check
from filetrust.detect import inspect_file
from filetrust.models import Finding
from filetrust.scoring.engine import score
import zipfile
from filetrust.analyzers.archive import check_zip
from filetrust.pipeline import analyze
import zlib
from filetrust.analyzers.pdf import check_pdf
from filetrust.report import defang
from filetrust.analyzers.html_page import check_html
from filetrust.analyzers.links import bad_link_reason

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
def make_pdf(path, body: bytes):
    path.write_bytes(b"%PDF-1.4\n" + body + b"\n%%EOF\n")


def test_pdf_clean(tmp_path):
    p = tmp_path / "a.pdf"
    make_pdf(p, b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj")
    info = inspect_file(p, "a.pdf")
    assert info.kind == "pdf"
    assert check_pdf(info) == []


def test_pdf_javascript_autorun_is_red(tmp_path):
    p = tmp_path / "b.pdf"
    make_pdf(p, b"1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n"
                b"2 0 obj\n<< /S /JavaScript /JS (app.alert(1)) >>\nendobj")
    findings = check_pdf(inspect_file(p, "b.pdf"))
    assert "PDF_JAVASCRIPT" in ids(findings)
    assert "PDF_AUTO_RUN" in ids(findings)
    assert "ВИСОКИЙ" in score(findings)[1]


def test_pdf_launch_is_red(tmp_path):
    p = tmp_path / "c.pdf"
    make_pdf(p, b"1 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj")
    findings = check_pdf(inspect_file(p, "c.pdf"))
    assert "PDF_LAUNCH" in ids(findings)
    assert "ВИСОКИЙ" in score(findings)[1]


def test_pdf_obfuscated_name(tmp_path):
    p = tmp_path / "d.pdf"
    make_pdf(p, b"1 0 obj\n<< /S /J#61vaScript /JS (x) >>\nendobj")
    findings = check_pdf(inspect_file(p, "d.pdf"))
    assert "PDF_OBFUSCATED" in ids(findings)
    assert "PDF_JAVASCRIPT" in ids(findings)


def test_pdf_ip_link(tmp_path):
    p = tmp_path / "e.pdf"
    make_pdf(p, b"1 0 obj\n<< /S /URI /URI (http://192.168.1.5/login) >>\nendobj")
    findings = check_pdf(inspect_file(p, "e.pdf"))
    assert "PDF_SUSPICIOUS_LINK" in ids(findings)


def test_pdf_normal_link_ok(tmp_path):
    p = tmp_path / "f.pdf"
    make_pdf(p, b"1 0 obj\n<< /S /URI /URI (https://example.com/page) >>\nendobj")
    assert check_pdf(inspect_file(p, "f.pdf")) == []


def test_pdf_js_hidden_in_object_stream(tmp_path):
    p = tmp_path / "g.pdf"
    packed = zlib.compress(b"<< /S /JavaScript /JS (x) >>")
    make_pdf(p, b"1 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode >>\n"
                b"stream\n" + packed + b"\nendstream\nendobj")
    findings = check_pdf(inspect_file(p, "g.pdf"))
    assert "PDF_JAVASCRIPT" in ids(findings)


def test_pdf_ignores_noise_in_binary_stream(tmp_path):
    p = tmp_path / "h.pdf"
    make_pdf(p, b"1 0 obj\n<< /Length 20 >>\nstream\n"
                b"\x00\x01/JS /AA /Launch \x02\nendstream\nendobj")
    assert check_pdf(inspect_file(p, "h.pdf")) == []


def test_pdf_embedded_exe(tmp_path):
    p = tmp_path / "i.pdf"
    make_pdf(p, b"1 0 obj\n<< /Type /EmbeddedFile >>\nendobj\n"
                b"2 0 obj\n<< /F (invoice.exe) /EF << /F 1 0 R >> >>\nendobj")
    findings = check_pdf(inspect_file(p, "i.pdf"))
    assert "PDF_EMBEDDED_EXEC" in ids(findings)

def test_defang_makes_links_inert():
    assert (defang("Посилання: http://192.168.0.10/login (IP)")
            == "Посилання: hxxp://192[.]168[.]0[.]10/login (IP)")
    assert "[.]" not in defang("setup.exe")
def test_script_file_is_flagged(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"WScript.Echo('hi')")
    info = inspect_file(p, "update.js")
    assert "EXEC_FILE" in ids(check(info))
    assert "ВИСОКИЙ" in score(check(info))[1]


def test_plain_text_is_not_flagged(tmp_path):
    p = tmp_path / "y.bin"
    p.write_bytes(b"hello")
    info = inspect_file(p, "notes.txt")
    assert check(info) == []
def make_html(path, body: str):
    path.write_text(body, encoding="utf-8")


def test_html_clean(tmp_path):
    p = tmp_path / "a.html"
    make_html(p, "<html><body><h1>Hello</h1>"
                 "<a href='/about'>about</a></body></html>")
    info = inspect_file(p, "a.html")
    assert info.kind == "html"
    assert check_html(info) == []


def test_html_phishing_form_is_red(tmp_path):
    p = tmp_path / "b.html"
    make_html(p, '<html><body><form action="https://login-check.example/post" '
                 'method="post"><input type="text" name="u">'
                 '<input type="password" name="p"></form></body></html>')
    findings = check_html(inspect_file(p, "b.html"))
    assert "HTML_PASSWORD_FORM" in ids(findings)
    assert "HTML_FORM_EXTERNAL" in ids(findings)
    assert "ВИСОКИЙ" in score(findings)[1]


def test_html_smuggling_is_red(tmp_path):
    p = tmp_path / "c.html"
    make_html(p, "<html><script>var d=atob('QUJD');var b=new Blob([d]);"
                 "var u=URL.createObjectURL(b);</script></html>")
    findings = check_html(inspect_file(p, "c.html"))
    assert "HTML_SMUGGLING" in ids(findings)
    assert "ВИСОКИЙ" in score(findings)[1]


def test_html_hidden_iframe(tmp_path):
    p = tmp_path / "d.html"
    make_html(p, '<html><iframe src="x" width="0" height="0"></iframe></html>')
    assert "HTML_HIDDEN_IFRAME" in ids(check_html(inspect_file(p, "d.html")))


def test_html_redirect(tmp_path):
    p = tmp_path / "e.html"
    make_html(p, '<html><head><meta http-equiv="refresh" '
                 'content="0;url=https://example.org/x"></head></html>')
    assert "HTML_REDIRECT" in ids(check_html(inspect_file(p, "e.html")))


def test_html_ip_link(tmp_path):
    p = tmp_path / "f.html"
    make_html(p, '<html><a href="http://10.0.0.5/x">click</a></html>')
    assert "HTML_SUSPICIOUS_LINK" in ids(check_html(inspect_file(p, "f.html")))


def test_html_obfuscation(tmp_path):
    p = tmp_path / "g.html"
    make_html(p, "<html><script>eval(unescape('%61'))</script></html>")
    assert "HTML_OBFUSCATED_JS" in ids(check_html(inspect_file(p, "g.html")))


def test_bad_link_reason():
    assert bad_link_reason("http://10.0.0.5/x")
    assert bad_link_reason("https://bit.ly/abc")
    assert bad_link_reason("https://xn--80ak6aa92e.com")
    assert bad_link_reason("https://example.com") is None
    assert bad_link_reason("/relative/path") is None