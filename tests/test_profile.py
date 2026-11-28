"""Додаткові характеристики файлу і їх відображення у звіті."""
import json
import os
import struct
import zipfile
from html.parser import HTMLParser
from pathlib import Path

from filetrust.models import FileInfo, Finding
from filetrust.pipeline import analyze
from filetrust.profile import build
from filetrust.report import entropy_label, format_links, format_report, url_rows
from filetrust.scoring.explain import assess


ALLOWED = {"b", "i", "code", "pre", "blockquote", "a"}


class _Checker(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack, self.bad = [], []

    def handle_starttag(self, tag, attrs):
        if tag not in ALLOWED:
            self.bad.append(tag)
        self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack.pop() != tag:
            self.bad.append("/" + tag)


def valid(text: str) -> bool:
    c = _Checker()
    c.feed(text)
    c.close()
    return not c.bad and not c.stack



def run(path: Path, name: str):
    info, findings = analyze(path, name)
    a = assess(findings)
    return info, a, format_report(info, a.total, a.verdict, a.findings, a.story)


def test_entropy_of_zeros_and_random(tmp_path):
    z = tmp_path / "z.txt"
    z.write_bytes(b"\x00" * 20000)
    r = tmp_path / "r.bin"
    r.write_bytes(os.urandom(20000))
    assert analyze(z, "z.txt")[0].meta["entropy"] == 0.0
    assert analyze(r, "r.bin")[0].meta["entropy"] > 7.9


def test_hashes_match_hashlib(tmp_path):
    import hashlib
    p = tmp_path / "a.txt"
    p.write_bytes(b"hello")
    m = analyze(p, "a.txt")[0].meta
    assert m["md5"] == hashlib.md5(b"hello").hexdigest()
    assert m["sha1"] == hashlib.sha1(b"hello").hexdigest()


def test_meta_is_json_serializable_and_never_raises(tmp_path):
    p = tmp_path / "g.bin"
    p.write_bytes(os.urandom(5000))
    for kind in ("zip", "ooxml", "pdf", "html", "image", "exe", "text"):
        info = FileInfo("g.bin", p, 5000, "0" * 64, "x/x", kind)
        json.dumps(build(info))


def test_zip_counts_executables_and_encryption(tmp_path):
    p = tmp_path / "a.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("doc.txt", "x")
        z.writestr("run.exe", "MZ")
    m = analyze(p, "a.zip")[0].meta
    assert m["entries"] == 2 and m["execs"] == 1 and m["encrypted"] == 0


def test_ooxml_metadata_and_macro_flag(tmp_path):
    p = tmp_path / "a.docx"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w/>")
        z.writestr("word/vbaProject.bin", b"x")
        z.writestr("docProps/core.xml", "<cp><dc:creator>Іван &amp; Co</dc:creator></cp>")
    info, a, text = run(p, "a.docx")
    assert info.meta["macro"] is True and info.meta["author"] == "Іван & Co"
    assert "Макроси" in text and "Іван &amp; Co" in text and valid(text)


def test_pdf_tail_after_eof_is_reported(tmp_path):
    p = tmp_path / "a.pdf"
    p.write_bytes(b"%PDF-1.4\n1 0 obj\n<</Type/Page>>\nendobj\n%%EOF\nEXTRA DATA HERE")
    m = analyze(p, "a.pdf")[0].meta
    assert m["pages"] == 1 and m["tail"] == len(b"EXTRA DATA HERE")


def test_pe_metrics_do_not_crash_on_broken_header(tmp_path):
    p = tmp_path / "a.exe"
    p.write_bytes(b"MZ" + b"\x00" * 100)
    info, a, text = run(p, "a.exe")
    assert valid(text) and "Ентропія" in text


def test_report_card_valid_and_escapes_metadata(tmp_path):
    p = tmp_path / "a.docx"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("docProps/core.xml", "<cp><dc:creator>&lt;b&gt;x&lt;/b&gt;</dc:creator></cp>")
    _, _, text = run(p, "a.docx")
    assert valid(text) and "<b>x</b>" not in text


def test_entropy_label_depends_on_kind():
    assert entropy_label("zip", 7.9)[0] == "✅"
    assert entropy_label("exe", 7.6)[0] == "🔥"
    assert entropy_label("text", 6.5)[0] == "🔥"
    assert entropy_label("text", 3.0)[0] == "✅"


def test_url_rows_params_and_defang():
    rows = "\n".join(url_rows("http://xn--pypal-4ve.xyz:8080/a?b=1&c=2"))
    assert "http " in rows or "🔓" in rows
    assert "Punycode" in rows and "8080" in rows and "Параметрів" in rows
    assert "xyz" in rows and "://" not in rows


def test_url_rows_ip_and_garbage():
    assert "IP-адреса" in "\n".join(url_rows("http://8.8.4.4/x"))
    assert url_rows("") == [] and isinstance(url_rows("http://[::1"), list)


def test_links_report_card_is_valid_html():
    a = assess([Finding("LINK_BRAND", 60, "Імітує бренд")])
    text = format_links([("https://paypa1-login.xyz/a?x=1", a)])
    assert valid(text) and "<pre>" in text and "http://" not in text and "https://" not in text
