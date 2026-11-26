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




# Функції, які PDF-форми використовують для форматування полів (Adobe AcroForm)
FORM_JS_RE = re.compile(
    r"\b(?:AF[A-Z][A-Za-z_]*|event\.(?:value|rc|willCommit|target|change)"
    r"|this\.(?:getField|calculateNow|resetForm|dirty|pageNum)"
    r"|util\.(?:printf|printd|scand)|app\.alert)\b")
# Усе, що виходить за межі форматування полів: мережа, запуск, обфускація, файли
DANGER_JS_RE = re.compile(
    r"(?:launchURL|submitForm|getURL|mailDoc|exportDataObject|importDataObject"
    r"|eval\s*\(|unescape|fromCharCode|util\.stream|Collab\.|media\.|ActiveX"
    r"|SOAP|Net\.|app\.(?:launch|execMenuItem)|this\.(?:saveAs|print\()|OpenDoc|XMLHttp"
    r"|https?://|\\x[0-9a-f]{2}|%u[0-9a-f]{4})", re.I)
OBJ_RE = re.compile(rb"(?<![0-9])(\d{1,7})\s+(\d{1,5})\s+obj\b")
JS_LIT_RE = re.compile(rb"/JS\s*\(((?:[^()\\]|\\.){0,20000})\)", re.S)
JS_HEX_RE = re.compile(rb"/JS\s*<([0-9A-Fa-f\s]{2,40000})>")
JS_REF_RE = re.compile(rb"/JS\s+(\d{1,7})\s+\d{1,5}\s+R")


def _stream_text(body: bytes) -> str:
    try:
        raw = zlib.decompressobj().decompress(body, MAX_DECOMP)
    except zlib.error:
        raw = body
    return raw.decode("latin-1")


def _js_sources(data: bytes, streams, texts) -> tuple[list[str], bool]:
    """Витягує текст JavaScript. Повертає (код, чи_все_прочитано)."""
    codes: list[str] = []
    complete = True
    for t in texts:
        for m in JS_LIT_RE.finditer(t):
            codes.append(m.group(1).decode("latin-1"))
        for m in JS_HEX_RE.finditer(t):
            try:
                codes.append(bytes.fromhex(re.sub(rb"\s", b"", m.group(1)).decode()).decode("latin-1"))
            except ValueError:
                complete = False
    refs = {int(m.group(1)) for t in texts for m in JS_REF_RE.finditer(t)}
    if refs:
        objs = {int(m.group(1)): m.end() for m in OBJ_RE.finditer(data)}
        by_pos = sorted(streams)
        for n in refs:
            pos = objs.get(n)
            if pos is None:
                complete = False   # об'єкт у ObjStm або відсутній
                continue
            nxt = next(((s, b) for s, b in by_pos if s >= pos), None)
            end = data.find(b"endobj", pos)
            if nxt and (end == -1 or nxt[0] < end):
                codes.append(_stream_text(nxt[1]))
            else:   # рядковий об'єкт: /JS 5 0 R -> 5 0 obj (...)
                m = re.match(rb"\s*\(((?:[^()\\]|\\.)*)\)", data[pos:pos + 20000], re.S)
                if m:
                    codes.append(m.group(1).decode("latin-1"))
                else:
                    complete = False
    return codes, complete


def _is_form_js_only(codes: list[str], complete: bool) -> bool:
    """JS є лише форматуванням полів форми: відомі AF*-функції, без мережі й запуску."""
    if not complete or not codes:
        return False
    joined = "\n".join(codes)
    return bool(FORM_JS_RE.search(joined)) and not DANGER_JS_RE.search(joined)



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
    form_js_only = False
    if has_js and not has_launch:
        codes, complete = _js_sources(data, streams, texts)
        form_js_only = _is_form_js_only(codes, complete)

    if has_launch:
        findings.append(Finding(
            "PDF_LAUNCH", 70,
            "PDF може запускати зовнішню програму (/Launch)"))
    if form_js_only:
        findings.append(Finding(
            "PDF_FORM_JS", 5,
            "JavaScript лише форматує поля форми "))
    elif has_js:
        findings.append(Finding(
            "PDF_JAVASCRIPT", 40, "Усередині PDF є JavaScript"))
    if auto and (has_launch or (has_js and not form_js_only)):
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
