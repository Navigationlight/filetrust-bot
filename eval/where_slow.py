
import hashlib
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

import magic                                              # noqa: E402
from html.parser import HTMLParser                        # noqa: E402
from filetrust.analyzers import html_page                 # noqa: E402
from filetrust.pipeline import analyze                    # noqa: E402

CASES = {
    "form": b"<html>" + b"<form " * 200_000,
    "a_href": b"<html>" + b"<a href=" * 200_000,
}


def timed(label, fn):
    t = time.perf_counter()
    fn()
    print(f"    {label:<22}{time.perf_counter() - t:7.2f} с", flush=True)


for name, data in CASES.items():
    print(name, f"({len(data) // 1024} КБ)", flush=True)
    p = Path(tempfile.mkdtemp()) / "s.bin"
    p.write_bytes(data)
    text = data.decode("utf-8", "ignore")
    timed("sha256", lambda: hashlib.sha256(data).hexdigest())
    timed("libmagic", lambda: magic.from_file(str(p), mime=True))
    timed("sanitize", lambda: html_page._sanitize(text))
    clean = html_page._sanitize(text)
    timed("HTMLParser (після)", lambda: (lambda h: (h.feed(clean), h.close()))(HTMLParser()))
    timed("повний analyze", lambda: analyze(p, "a.html"))
