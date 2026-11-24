
import io
import random
import time
import zipfile

import pytest

from filetrust.pipeline import analyze
from filetrust.scoring.explain import assess

MZ = b"MZ" + b"\x90\x00" * 100


def make_pe() -> bytes:
    """Мінімальний справжній PE, який libmagic впізнає як виконуваний."""
    dos = bytearray(b"MZ" + b"\x00" * 62)
    dos[0x3C:0x40] = (0x40).to_bytes(4, "little")
    coff = b"PE\0\0" + (0x14C).to_bytes(2, "little") + (1).to_bytes(2, "little") + b"\0" * 12 \
        + (0xE0).to_bytes(2, "little") + (0x0102).to_bytes(2, "little")
    opt = (0x10B).to_bytes(2, "little") + b"\0" * 0xDE
    section = b".text\0\0\0" + b"\0" * 32
    return bytes(dos) + coff + opt + section + b"\0" * 512


PE = make_pe()
SLOW_LIMIT = 5.0      # секунд на один файл


def run(tmp_path, name, data):
    p = tmp_path / "s.bin"
    p.write_bytes(data)
    t = time.perf_counter()
    info, findings = analyze(p, name)
    return assess(findings), time.perf_counter() - t


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in files.items():
            z.writestr(n, d)
    return buf.getvalue()


def pdf(body):
    return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog " + body + b" >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"


# ---------- обхід через назву ----------
@pytest.mark.parametrize("name", [
    "invoice.pdf.exe", "INVOICE.PDF.EXE", "Invoice.Pdf.Exe",
    "invoice.pdf.exe.", "invoice.pdf.exe ", "invoice.pdf.exe...",
    "invoice.pdf.exe\u200b", "invoice.pdf\u200b.exe", "invoice.pdf .exe",
    "invoice\u202efdp.exe", "invoice.docx.scr", "photo.jpg.js",
])
def test_exe_name_tricks_are_caught(tmp_path, name):
    a, _ = run(tmp_path, name, MZ)
    assert a.total >= 60, (name, a.total)


@pytest.mark.parametrize("name", ["report.pdf", "REPORT.PDF", "report.pdf.", "photo.JPG", "a.docx"])
def test_exe_hidden_under_document_name(tmp_path, name):
    a, _ = run(tmp_path, name, PE)
    assert a.total >= 60, a.total


def test_exe_inside_zip_any_case(tmp_path):
    for inner in ["setup.exe", "SETUP.EXE", "a.pdf.exe", "run.SCR"]:
        a, _ = run(tmp_path, "docs.zip", make_zip({inner: MZ}))
        assert a.total >= 60, inner


# ---------- обхід через PDF ----------
@pytest.mark.parametrize("js_name", [
    b"/JavaScript", b"/J#61vaScript", b"/#4AavaScript", b"/JavaScr#69pt",
])
def test_pdf_javascript_hex_names(tmp_path, js_name):
    body = b"/OpenAction << /S " + js_name + b" /JS (app.alert(1)) >>"
    a, _ = run(tmp_path, "doc.pdf", pdf(body))
    assert a.total >= 60, (js_name, a.total)


def test_pdf_launch(tmp_path):
    a, _ = run(tmp_path, "doc.pdf", pdf(b"/OpenAction << /S /Launch /F (cmd.exe) >>"))
    assert a.total >= 60


# ---------- хибні спрацювання, чисті файли лишаються чистими ----------
def test_clean_files_stay_clean(tmp_path):
    clean = {
        "a.pdf": pdf(b"/Pages 2 0 R"),
        "a.txt": "звичайний текст\n".encode(),
        "a.zip": make_zip({"readme.txt": b"hello", "img/a.png": b"x" * 50}),
        "a.html": b"<html><body><p>hi</p><a href='https://example.com'>x</a></body></html>",
    }
    for name, data in clean.items():
        a, _ = run(tmp_path, name, data)
        assert a.total < 30, (name, a.total)


# ---------- повільні й ворожі файли ----------
def test_pdf_many_streams_is_fast(tmp_path):
    """Раніше PDF на 156 КБ аналізувався понад хвилину (регулярка працювала квадратично)."""
    for n in (200_000, 500_000):
        _, dt = run(tmp_path, "a.pdf", b"%PDF-1.4\n" + b"stream\nA" * n)
        assert dt < SLOW_LIMIT, (n, dt)


def test_pdf_many_endstreams_and_crlf(tmp_path):
    data = b"%PDF-1.4\n" + (b"stream\r\nAAAA\r\nendstream\n" * 100_000)
    _, dt = run(tmp_path, "a.pdf", data)
    assert dt < SLOW_LIMIT


@pytest.mark.parametrize("payload", [
    b"<a href=" * 200_000,
    b"<form " * 200_000,
    b"A" * 5_000_000,
    b"<script>" + b"eval(" * 300_000,
    b"<meta http-equiv=refresh content=url=" * 100_000,
])
def test_html_adversarial_is_fast(tmp_path, payload):
    _, dt = run(tmp_path, "a.html", b"<html>" + payload)
    assert dt < SLOW_LIMIT


@pytest.mark.parametrize("payload", [
    b"<Relationship " * 100_000,
    b'<Relationship Target="http://a" ' * 100_000,
    b"<w:instrText>" * 100_000,
    b"<f " * 100_000,
])
def test_office_adversarial_is_fast(tmp_path, payload):
    data = make_zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": payload,
                     "word/_rels/document.xml.rels": payload})
    _, dt = run(tmp_path, "a.docx", data)
    assert dt < SLOW_LIMIT


def test_zip_with_many_entries(tmp_path):
    data = make_zip({f"f{i}.txt": b"x" for i in range(3000)})
    _, dt = run(tmp_path, "a.zip", data)
    assert dt < SLOW_LIMIT


# ---------- випадкові і зіпсовані дані ----------
def _damaged(rng, base):
    b = bytearray(base)
    for _ in range(rng.randint(1, 20)):
        if b:
            b[rng.randrange(len(b))] = rng.randrange(256)
    return bytes(b[: rng.randint(0, len(b))] if rng.random() < 0.4 else b)


def test_damaged_samples_never_crash(tmp_path):
    rng = random.Random(7)
    bases = {
        "a.pdf": pdf(b"/OpenAction << /S /JavaScript /JS (x) >>"),
        "a.zip": make_zip({"a.exe": MZ, "b.txt": b"x"}),
        "a.docx": make_zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>"}),
        "a.html": b"<html><form><input type=password></form></html>",
        "a.exe": MZ,
    }
    for _ in range(300):
        name = rng.choice(list(bases))
        _, dt = run(tmp_path, name, _damaged(rng, bases[name]))
        assert dt < SLOW_LIMIT


def test_hypothesis_random_bytes(tmp_path):
    hyp = pytest.importorskip("hypothesis")
    st = pytest.importorskip("hypothesis.strategies")

    @hyp.settings(max_examples=150, deadline=None)
    @hyp.given(st.binary(max_size=4000),
               st.sampled_from(["a.pdf", "a.zip", "a.docx", "a.html", "a.exe", "a.txt", "a.7z", "a.doc"]),
               st.text(max_size=30))
    def check(data, ext, junk):
        a, dt = run(tmp_path, junk + ext, data)
        assert 0 <= a.total <= 100 and dt < SLOW_LIMIT

    check()
