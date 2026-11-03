import re
import zipfile
from pathlib import PurePath, PurePosixPath

from filetrust.analyzers.common import EXEC_EXTS
from filetrust.analyzers.links import bad_link_reason
from filetrust.models import FileInfo, Finding

MAX_ENTRIES = 10_000
MAX_PART = 5 * 1024 * 1024     # скільки читаємо з одного файлу всередині
MAX_XML_PARTS = 200            # скільки xml-частин переглядаємо

NO_MACRO_EXTS = {".docx", ".xlsx", ".pptx"}
REMOTE_TYPES = ("attachedtemplate", "oleobject", "frame",
                "subdocument", "externallink")
STRONG = ("shell", "powershell", "urldownloadtofile", "createobject",
          "xmlhttp", "adodb.stream", "wscript", "cmd")

REL_RE = re.compile(rb"<Relationship\b([^>]*)>", re.I)
ATTR_RE = re.compile(rb"""(\w+)\s*=\s*["']([^"']*)["']""")
DDE_WORD_RE = re.compile(rb"<w:instrText[^>]*>[^<]*\bDDE(?:AUTO)?\b", re.I)
DDE_XL_RE = re.compile(rb"<f(?:\s[^>]*)?>[^<]*\b(?:cmd|powershell)\s*\|", re.I)


def _read(zf: zipfile.ZipFile, name: str) -> bytes:
    """Читає не більше MAX_PART байтів файлу з архіву; помилка = порожньо."""
    try:
        with zf.open(name) as f:
            return f.read(MAX_PART)
    except Exception:
        return b""


def _olevba_scan(path) -> tuple[bool, list]:
    """(є_макроси, результати аналізу від olevba). Помилка розбору = (False, [])."""
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return False, []
    try:
        parser = VBA_Parser(str(path))
    except Exception:
        return False, []
    try:
        has = bool(parser.detect_vba_macros())
        results: list = []
        if has:
            try:
                results = list(parser.analyze_macros())
            except Exception:
                results = []
        return has, results
    except Exception:
        return False, []
    finally:
        parser.close()


def macro_findings(results: list) -> list[Finding]:
    """results: список (тип, ключове слово, опис) від olevba."""
    findings = [Finding("OFFICE_MACRO", 40, "У документі є макроси (VBA)")]
    auto = sorted({k for t, k, _ in results if t == "AutoExec"})
    susp = sorted({k for t, k, _ in results if t == "Suspicious"})
    iocs = sorted({k for t, k, _ in results if t == "IOC"})
    if auto:
        findings.append(Finding(
            "OFFICE_MACRO_AUTOEXEC", 15,
            "Макрос запускається автоматично: " + ", ".join(auto[:3])))
    if any(s in k.lower() for k in susp for s in STRONG):
        findings.append(Finding(
            "OFFICE_MACRO_SUSPICIOUS", 35,
            "Макрос виконує підозрілі дії: " + ", ".join(susp[:5])))
    if iocs:
        findings.append(Finding(
            "OFFICE_MACRO_IOC", 20,
            "У макросі знайдено адреси або імена файлів: " + ", ".join(iocs[:3])))
    return findings


def check_ooxml(info: FileInfo) -> list[Finding]:
    """docx / xlsx / pptx / docm ...: це zip з xml усередині."""
    try:
        zf = zipfile.ZipFile(info.path)
    except zipfile.BadZipFile:
        return []

    remote: list[str] = []
    bad_links: list[str] = []
    dde = False

    with zf:
        names = zf.namelist()[:MAX_ENTRIES]
        if "[Content_Types].xml" not in names:
            return []  # це не документ Office

        macro_names = [n for n in names if n.lower().endswith("vbaproject.bin")]

        # зовнішні зв'язки: шаблони, об'єкти, посилання
        for n in names:
            if not n.endswith(".rels"):
                continue
            for raw in REL_RE.findall(_read(zf, n)):
                a = {k.decode("latin-1").lower(): v.decode("utf-8", "ignore")
                     for k, v in ATTR_RE.findall(raw)}
                if a.get("targetmode", "").lower() != "external":
                    continue
                rtype = a.get("type", "").lower()
                target = a.get("target", "")
                if rtype.endswith(REMOTE_TYPES):
                    remote.append(target)
                elif rtype.endswith("hyperlink"):
                    why = bad_link_reason(target)
                    if why:
                        bad_links.append(f"{target[:60]} ({why})")

        # DDE у Word і Excel
        parts = 0
        for n in names:
            word = n.startswith("word/") and n.endswith(".xml")
            sheet = n.startswith("xl/worksheets/") and n.endswith(".xml")
            if not (word or sheet):
                continue
            parts += 1
            if parts > MAX_XML_PARTS:
                break
            data = _read(zf, n)
            if (word and DDE_WORD_RE.search(data)) or \
               (sheet and DDE_XL_RE.search(data)):
                dde = True
                break

    embedded_exec = [
        PurePosixPath(n).name for n in names
        if "/embeddings/" in n and PurePosixPath(n).suffix.lower() in EXEC_EXTS
    ]

    findings: list[Finding] = []
    if macro_names:
        _, results = _olevba_scan(info.path)
        findings += macro_findings(results)
        ext = PurePath(info.name).suffix.lower().strip()
        if ext in NO_MACRO_EXTS:
            findings.append(Finding(
                "OFFICE_MACRO_HIDDEN_EXT", 20,
                f"Розширення {ext} обіцяє документ без макросів, "
                f"але всередині вони є"))
    if remote:
        findings.append(Finding(
            "OFFICE_REMOTE_CONTENT", 50,
            "Документ підтягує зовнішній вміст (шаблон або об'єкт) "
            f"із зовнішньої адреси: {remote[0][:80]}"))
    if bad_links:
        findings.append(Finding(
            "OFFICE_SUSPICIOUS_LINK", 30,
            "Підозрілі посилання: " + "; ".join(bad_links[:3])))
    if dde:
        findings.append(Finding(
            "OFFICE_DDE", 50,
            "У документі є поле DDE: так запускають команди без макросів"))
    if embedded_exec:
        findings.append(Finding(
            "OFFICE_EMBEDDED_EXEC", 60,
            f"У документі вкладено виконуваний файл: «{embedded_exec[0]}»"))
    return findings


def check_ole(info: FileInfo) -> list[Finding]:
    """Старі формати doc / xls / ppt: макроси розбирає olevba."""
    has, results = _olevba_scan(info.path)
    return macro_findings(results) if has else []