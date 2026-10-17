import ipaddress
import re
import zlib
from collections import Counter
from urllib.parse import urlparse

from filetrust.analyzers.common import EXEC_EXTS
from filetrust.models import FileInfo, Finding

MAX_READ = 20 * 1024 * 1024    # читаємо не більше 20 МБ
MAX_STREAMS = 500              # розпаковуємо не більше 500 потоків
MAX_DECOMP = 5 * 1024 * 1024   # і не більше 5 МБ з одного потоку

NAME_RE = re.compile(rb"/([A-Za-z0-9#_.\-]{1,40})")
HEX_RE = re.compile(rb"#([0-9A-Fa-f]{2})")
STREAM_RE = re.compile(rb"(?<!end)stream\r?\n(.*?)\r?\nendstream", re.S)
URI_RE = re.compile(rb"/URI\s*\(([^)]{1,300})\)")
FILE_RE = re.compile(rb"/(?:UF|F)\s*\(([^)]{1,120})\)")

# імена, які варто перевіряти на приховане кодування
WATCHED = {"JavaScript", "JS", "OpenAction", "AA", "Launch",
           "EmbeddedFile", "RichMedia", "URI"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
              "rebrand.ly", "ow.ly", "tiny.cc", "shorturl.at", "t.ly"}

def _decode_name(raw: bytes) -> str:
    """/J#61vaScript -> JavaScript"""
    fixed = HEX_RE.sub(lambda m: bytes([int(m.group(1), 16)]), raw)
    return fixed.decode("latin-1")


def _object_streams(data: bytes):
    """Розпаковує лише об'єктні потоки (/ObjStm): там ховаються словники."""
    count = 0
    for m in STREAM_RE.finditer(data):
        if b"/ObjStm" not in data[max(0, m.start() - 300):m.start()]:
            continue
        count += 1
        if count > MAX_STREAMS:
            break
        try:
            yield zlib.decompressobj().decompress(m.group(1), MAX_DECOMP)
        except zlib.error:
            continue


def _bad_link_reason(url: str) -> str | None:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower()
    try:
        ipaddress.ip_address(host)
        return "адреса IP замість домену"
    except ValueError:
        pass
    if host in SHORTENERS:
        return "скорочувач посилань"
    if "xn--" in host:
        return "домен у punycode (можлива підміна символів)"
    return None

def check_pdf(info: FileInfo) -> list[Finding]:
    with info.path.open("rb") as f:
        data = f.read(MAX_READ)

    # звичайні потоки прибираємо: у стиснутих даних випадкові «імена»
    texts = [STREAM_RE.sub(b"", data)] + list(_object_streams(data))

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
        why = _bad_link_reason(u)
        if why:
            bad_links.append(f"{u[:80]} ({why})")
    if bad_links:
        findings.append(Finding(
            "PDF_SUSPICIOUS_LINK", 30,
            "Підозрілі посилання: " + "; ".join(bad_links[:3])))
    if obfuscated:
        findings.append(Finding(
            "PDF_OBFUSCATED", 50,
            "Назви елементів приховані кодуванням #xx: "
            + ", ".join(sorted(obfuscated))))
    return findings