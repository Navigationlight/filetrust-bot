"""Показує, на якому кроці йде час. Використання: python eval/where_slow.py"""
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

import magic                                              # noqa: E402
from filetrust.pipeline import analyze                    # noqa: E402

CASES = {
    "form": b"<html>" + b"<form " * 200_000,
    "a_href": b"<html>" + b"<a href=" * 200_000,
}


def timed(label, fn):
    t = time.perf_counter()
    fn()
    print(f"    {label:<28}{time.perf_counter() - t:7.2f} с", flush=True)


for name, data in CASES.items():
    print(name, f"({len(data) // 1024} КБ)", flush=True)
    d = Path(tempfile.mkdtemp())
    p, p2 = d / "s.bin", d / "copy.bin"
    p.write_bytes(data)
    timed("перше читання файлу", lambda: p.read_bytes())
    timed("libmagic, 1-й виклик", lambda: magic.from_file(str(p), mime=True))
    timed("libmagic, 2-й виклик", lambda: magic.from_file(str(p), mime=True))
    shutil.copy(p, p2)
    timed("libmagic, нова копія", lambda: magic.from_file(str(p2), mime=True))
    timed("libmagic, з пам'яті", lambda: magic.from_buffer(data[:1048576], mime=True))
    timed("повний analyze", lambda: analyze(p, "a.html"))
