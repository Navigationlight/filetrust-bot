
import hashlib
import html
import re
import struct
import time
import zipfile
from pathlib import Path

from filetrust.analyzers.common import EXEC_EXTS
from filetrust.models import FileInfo

MAX_READ = 16 * 1024 * 1024
BLOCK = 4096
MAX_ENTRIES = 5000
ARCH = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"}
EXEC_IN_ARCHIVE = EXEC_EXTS | {".pif", ".dll", ".vhd", ".iso"}
URL_RE = re.compile(rb"https?://[^\s\"'<>)]{4,200}", re.I)


def _h(counts) -> float:
    import numpy as np
    n = int(counts.sum())
    if n == 0:
        return 0.0
    p = counts[counts > 0] / n
    return float(-(p * np.log2(p)).sum())


def _short(s: str, n: int = 60) -> str:
    return html.unescape(s).strip()[:n]


def _stats(data: bytes, m: dict) -> None:
    """Ентропія (загальна й по блоках 4 КБ), частка друкованих символів і нулів."""
    import numpy as np
    arr = np.frombuffer(data, dtype=np.uint8)
    total = np.bincount(arr, minlength=256)
    m["entropy"] = round(_h(total), 2)
    n = len(arr)
    if n:
        printable = int(total[32:127].sum() + total[9] + total[10] + total[13])
        m["printable"] = round(100 * printable / n)
        m["nulls"] = round(100 * int(total[0]) / n)
    blocks = [_h(np.bincount(arr[i:i + BLOCK], minlength=256))
              for i in range(0, n - BLOCK + 1, BLOCK)]
    if len(blocks) >= 2:
        m["ent_max"] = round(max(blocks), 2)
        m["hot_pct"] = round(100 * sum(b >= 7.5 for b in blocks) / len(blocks))


def _hashes(path: Path, m: dict) -> None:
    md5, sha1 = hashlib.md5(), hashlib.sha1()           # лише для пошуку в базах, не для захисту
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
    m["md5"], m["sha1"] = md5.hexdigest(), sha1.hexdigest()


def _zip(path: Path, m: dict, ooxml: bool) -> None:
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()[:MAX_ENTRIES]
        names = [i.filename for i in infos]
        files = [i for i in infos if not i.filename.endswith("/")]
        m["entries"] = len(files)
        m["unpacked"] = sum(i.file_size for i in files)
        m["encrypted"] = sum(1 for i in files if i.flag_bits & 1)
        m["execs"] = sum(1 for n in names if Path(n).suffix.lower() in EXEC_IN_ARCHIVE)
        if ooxml:
            m["macro"] = any(n.lower().endswith("vbaproject.bin") for n in names)
            m["activex"] = any("/activex/" in n.lower() for n in names)
            m["embedded"] = sum(1 for n in names if "/embeddings/" in n.lower())
            m["external_rels"] = _external_rels(zf, names)
            core = _read(zf, "docProps/core.xml")
            app = _read(zf, "docProps/app.xml")
            for key, pat, src in (
                ("author", r"<dc:creator>(.*?)</dc:creator>", core),
                ("modified_by", r"<cp:lastModifiedBy>(.*?)</cp:lastModifiedBy>", core),
                ("created", r"<dcterms:created[^>]*>(.*?)<", core),
                ("modified", r"<dcterms:modified[^>]*>(.*?)<", core),
                ("app", r"<Application>(.*?)</Application>", app),
            ):
                found = re.search(pat, src, re.S)
                if found and found.group(1).strip():
                    m[key] = _short(found.group(1))


def _read(zf: zipfile.ZipFile, name: str) -> str:
    try:
        with zf.open(name) as f:
            return f.read(65536).decode("utf-8", "ignore")
    except (KeyError, RuntimeError, zipfile.BadZipFile):
        return ""


def _external_rels(zf: zipfile.ZipFile, names: list[str]) -> int:
    count = 0
    for n in names:
        if n.lower().endswith(".rels") and count < 1000:
            count += _read(zf, n).count('TargetMode="External"')
    return count


def _pdf(data: bytes, m: dict, complete: bool) -> None:
    v = re.search(rb"%PDF-(\d\.\d)", data[:1024])
    if v:
        m["version"] = v.group(1).decode()
    m["pages"] = len(re.findall(rb"/Type\s*/Page(?![s\w])", data))
    m["objects"] = len(re.findall(rb"\d+\s+\d+\s+obj\b", data))
    m["pdf_links"] = data.count(b"/URI")
    m["pdf_encrypted"] = b"/Encrypt" in data
    eof = data.rfind(b"%%EOF")
    if complete and eof != -1:
        m["tail"] = len(data[eof + 5:].strip())


def _html(data: bytes, m: dict) -> None:
    low = data[:2_000_000].lower()
    m["scripts"] = low.count(b"<script")
    m["iframes"] = low.count(b"<iframe")
    m["forms"] = low.count(b"<form")
    m["urls"] = len(set(URL_RE.findall(data[:2_000_000])))


def _image(data: bytes, m: dict, complete: bool) -> None:
    from filetrust.analyzers import image
    if data.startswith(b"\x89PNG") and len(data) >= 24:
        m["width"], m["height"] = struct.unpack(">II", data[16:24])
    end = image._image_end(data) if complete else None
    if end is not None:
        m["tail"] = max(0, len(data) - end)


def _pe(data: bytes, m: dict) -> None:
    import numpy as np
    from filetrust.analyzers.pe import _PE
    try:
        pe = _PE(data)
    except (ValueError, struct.error):
        m["pe_broken"] = True
        return
    m["arch"] = ARCH.get(pe.machine, hex(pe.machine))
    if pe.stamp:
        m["compiled"] = time.strftime("%Y-%m-%d", time.gmtime(pe.stamp))
        m["compiled_fake"] = pe.stamp > time.time() or pe.stamp < 631152000   # після 1990-го
    m["sections"] = len(pe.sections)
    sec = []
    for name, _, _, rsize, roff, _ in pe.sections:
        if rsize >= 512:
            arr = np.frombuffer(data[roff:roff + min(rsize, 1_000_000)], dtype=np.uint8)
            if len(arr):
                sec.append([name.decode("latin-1")[:8], round(_h(np.bincount(arr, minlength=256)), 2)])
    m["sec_ent"] = sec[:8]
    cert = pe.dd[4] if len(pe.dd) > 4 else (0, 0)
    m["signed"] = bool(cert[0] and cert[1])
    try:
        m["imports"] = len([n for n in pe.imports() if n])
    except (struct.error, IndexError, ValueError):
        pass
    end = max((s[4] + s[3] for s in pe.sections), default=0)
    m["overlay"] = max(0, len(data) - end - (cert[1] if cert[0] else 0))


def build(info: FileInfo) -> dict:
    
    m: dict = {}
    steps = []
    try:
        with info.path.open("rb") as f:
            data = f.read(MAX_READ)
    except OSError:
        return m
    complete = info.size <= MAX_READ
    suffixes = [s.lower() for s in Path(info.name).suffixes[-3:]]
    m["ext_chain"] = "".join(suffixes)
    m["magic"] = data[:8].hex(" ").upper()
    if not complete:
        m["sampled_mb"] = MAX_READ // (1024 * 1024)
    steps += [lambda: _hashes(info.path, m), lambda: _stats(data, m)]
    kind = info.kind
    if kind in ("zip", "ooxml"):
        steps.append(lambda: _zip(info.path, m, kind == "ooxml"))
    elif kind == "pdf":
        steps.append(lambda: _pdf(data, m, complete))
    elif kind == "html":
        steps.append(lambda: _html(data, m))
    elif kind == "image":
        steps.append(lambda: _image(data, m, complete))
    elif kind == "exe":
        steps.append(lambda: _pe(data, m))
    for step in steps:
        try:
            step()
        except Exception:                      # метрики другорядні: збій не валить аналіз
            continue
    return m
