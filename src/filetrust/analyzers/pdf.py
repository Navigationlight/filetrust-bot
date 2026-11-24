import re
import zlib
from collections import Counter

from filetrust.analyzers.links import bad_link_reason
from filetrust.analyzers.common import EXEC_EXTS
from filetrust.models import FileInfo, Finding

MAX_READ = 20 * 1024 * 1024    # читаємо не більше 20 МБ
MAX_STREAMS = 500              # розпаковуємо не більше 500 потоків
MAX_DECOMP = 5 * 1024 * 1024   # і не більше 5 МБ з одного потоку

NAME_RE = re.compile(rb"/([A-Za-z0-9#_.\-]{1,40})")
HEX_RE = re.compile(rb"#([0-9A-Fa-f]{2})")
URI_RE = re.compile(rb"/URI\s*\(([^)]{1,300})\)")
FILE_RE = re.compile(rb"/(?:UF|F)\s*\(([^)]{1,120})\)")

# імена, які варто перевіряти на приховане кодування
WATCHED = {"JavaScript", "JS", "OpenAction", "AA", "Launch",
           "EmbeddedFile", "RichMedia", "URI"}

def _decode_name(raw: bytes) -> str:
    """/J#61vaScript -> JavaScript"""
    fixed = HEX_RE.sub(lambda m: bytes([int(m.group(1), 16)]), raw)
    return fixed.decode("latin-1")


def _split_streams(data: bytes):
    """Ділить PDF на текст поза потоками і список потоків (початок, вміст).

    Це лінійний пошук через find. Регулярка stream(.*?)endstream працювала
    квадратично: PDF на 156 КБ аналізувався понад хвилину.
    """
    outside: list[bytes] = []
    streams: list[tuple[int, bytes]] = []
    last = 0
    pos = 0
    while True:
        s = data.find(b"stream", pos)
        if s == -1:
            break
        pos = s + 6
        if data[max(0, s - 3):s] == b"end":
            continue
        body_start = s + 6
        if data[body_start:body_start + 2] == b"\r\n":
            body_start += 2
        elif data[body_start:body_start + 1] == b"\n":
            body_start += 1
        else:
            continue
        e = data.find(b"endstream", body_start)
        if e == -1:
            break
        body = data[body_start:e]
        if body.endswith(b"\r\n"):
            body = body[:-2]
        elif body.endswith(b"\n"):
            body = body[:-1]
        outside.append(data[last:s])
        streams.append((s, body))
        last = pos = e + 9
    outside.append(data[last:])
    return b"".join(outside), streams


def _object_streams(data: bytes, streams):
    """Розпаковує лише об'єктні потоки (/ObjStm): там ховаються словники."""
    count = 0
    for start, body in streams:
        if b"/ObjStm" not in data[max(0, start - 300):start]:
            continue
        count += 1
        if count > MAX_STREAMS:
            break
        try:
            yield zlib.decompressobj().decompress(body, MAX_DECOMP)
        except zlib.error:
            continue




# PDF не відкривається бібліотекою-рендерером, тому експлойт не спрацює під час аналізу.
# Шукаємо ключові імена (/JavaScript, /Launch, /OpenAction) і приховане кодування #xx.
def check_pdf(info: FileInfo) -> list[Finding]:
    with info.path.open("rb") as f:
        data = f.read(MAX_READ)

    # звичайні потоки прибираємо
    outside, streams = _split_streams(data)
    texts = [outside] + list(_object_streams(data, streams))

    names: Counter = Counter()
    obfuscated: set[str] = set()
    links: list[str] = []

    for t in texts:
        for m in NAME_RE.finditer(t):
            raw = m.group(1)
            name = _decode_name(raw)
            names[name] += 1
            if b"#" in raw and name in WATCHED:
                obfuscated.add(name)
        links += [u.decode("latin-1") for u in URI_RE.findall(t)]

    embedded: list[str] = []
    if names["EmbeddedFile"]:
        for t in texts:
            embedded += [n.decode("latin-1") for n in FILE_RE.findall(t)]
    has_js = names["JavaScript"] or names["JS"]
    has_launch = names["Launch"]
    auto = names["OpenAction"] or names["AA"]
    findings: list[Finding] = []

    if has_launch:
        findings.append(Finding(
            "PDF_LAUNCH", 70,
            "PDF може запускати зовнішню програму (/Launch)"))
    if has_js:
        findings.append(Finding(
            "PDF_JAVASCRIPT", 40, "Усередині PDF є JavaScript"))
    if auto and (has_js or has_launch):
        findings.append(Finding(
            "PDF_AUTO_RUN", 30,
            "Дії виконуються автоматично під час відкриття (/OpenAction, /AA)"))
    if names["EmbeddedFile"]:
        exe = [n for n in embedded
               if n.strip().lower().endswith(tuple(EXEC_EXTS))]
        if exe:
            findings.append(Finding(
                "PDF_EMBEDDED_EXEC", 60,
                f"У PDF вкладено виконуваний файл: «{exe[0]}»"))
        else:
            findings.append(Finding(
                "PDF_EMBEDDED_FILE", 30, "У PDF вкладено інший файл"))
    if names["RichMedia"]:
        findings.append(Finding(
            "PDF_RICHMEDIA", 30,
            "У PDF вбудовані мультимедіа (/RichMedia), застарілий і ризикований механізм"))

    bad_links = []
    for u in links:
        why = bad_link_reason(u)
        if why:
            bad_links.append(f"{u[:80]} ({why})")
    if bad_links:
        findings.append(Finding(
            "PDF_SUSPICIOUS_LINK", 30,
            "Підозрілі посилання: " + ", ".join(bad_links[:3])))
    if obfuscated:
        findings.append(Finding(
            "PDF_OBFUSCATED", 50,
            "Назви елементів приховані кодуванням #xx: "
            + ", ".join(sorted(obfuscated))))
    return findings
