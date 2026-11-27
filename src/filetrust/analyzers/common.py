import re
from pathlib import PurePath
from filetrust.models import FileInfo, Finding

EXEC_EXTS = {".exe", ".scr", ".com", ".bat", ".cmd", ".js",
             ".vbs", ".ps1", ".hta", ".lnk", ".jar", ".msi"}
DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".txt", ".jpg", ".jpeg", ".png", ".zip", ".rar"}

# розширення і який вид файлу очікуємо
EXPECTED_KIND = {
    ".pdf": "pdf",
    ".docx": "ooxml", ".xlsx": "ooxml", ".pptx": "ooxml",
    ".docm": "ooxml", ".xlsm": "ooxml",
    ".doc": "ole", ".xls": "ole", ".ppt": "ole",
    ".zip": "zip", ".rar": "rar", ".7z": "7z",
    ".html": "html", ".htm": "html",
    ".jpg": "image", ".jpeg": "image", ".png": "image", ".gif": "image",
    ".txt": "text", ".exe": "exe", ".apk": "zip",
}
# які реальні види вважаємо допустимими для очікуваного
COMPATIBLE = {
    "ooxml": {"ooxml", "zip"},   # старий libmagic може бачити docx як zip
    "ole": {"ole", "ooxml"},     # .doc, що насправді docx, трапляється
    "html": {"html", "text"},
}
REAL_EXEC_KINDS = {"exe", "elf", "lnk"}

# невидимі символи і керування напрямком тексту: ними ховають справжнє розширення
_INVISIBLE_RE = re.compile("[\u200b-\u200f\u2060\ufeff\u00ad]")
_BIDI_CONTROLS = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"


def normalize_name(name: str) -> str:
    """Назва, якою її побачить Windows: без невидимих символів, пробілів і крапок у кінці.

    Windows відкидає кінцеві крапки та пробіли, тому invoice.pdf.exe. запускається як exe.
    """
    return _INVISIBLE_RE.sub("", name).rstrip(" .")

def check_name(name: str) -> list[Finding]:
    """Перевірки тільки за назвою ."""
    findings = []
    suffixes = [s.lower().strip() for s in PurePath(normalize_name(name)).suffixes]
    if any(c in name for c in _BIDI_CONTROLS):
        findings.append(Finding(
            "RTLO", 60,
            "У назві прихований символ, що перевертає розширення (прийом RTLO)"))
    if (len(suffixes) >= 2 and suffixes[-1] in EXEC_EXTS
            and suffixes[-2] in DOC_EXTS):
        findings.append(Finding(
            "DOUBLE_EXT", 60,
            f"Подвійне розширення: виглядає як документ, "
            f"а насправді {suffixes[-1]}"))
    return findings

def _pdf_header_near_start(info: FileInfo) -> bool:
    try:
        with info.path.open("rb") as f:
            return b"%PDF-" in f.read(1024)
    except OSError:
        return False


def check_type(info: FileInfo) -> list[Finding]:
    """Розширення і реальний тип за вмістом."""
    ext = PurePath(normalize_name(info.name)).suffix.lower().strip()
    expected = EXPECTED_KIND.get(ext)
    if expected is None or info.kind == "unknown":
        return []
    if info.kind in COMPATIBLE.get(expected, {expected}):
        return []
    # Вьюери відкривають PDF, якщо %PDF- є в перших 1024 байтах (не обов'язково на початку)
    if expected == "pdf" and _pdf_header_near_start(info):
        return []
    if info.kind in REAL_EXEC_KINDS:
        return [Finding(
             "DISGUISED_EXEC", 70,
            f"Розширення {ext}, але всередині виконуваний файл ({info.kind})")]
    return [Finding(
        "TYPE_MISMATCH", 30,
        f"Розширення {ext}, але вміст виглядає як «{info.kind}»")]

def check_exec(info: FileInfo) -> list[Finding]:
    """Файл є виконуваним за розширенням або за вмістом."""
    ext = PurePath(normalize_name(info.name)).suffix.lower().strip()
    if ext not in EXEC_EXTS and info.kind not in REAL_EXEC_KINDS:
        return []
    return [Finding(
        "EXEC_FILE", 60,
        "Це виконуваний файл або скрипт: запускайте його лише тоді, "
        "коли повністю довіряєте відправнику")]


def check(info: FileInfo) -> list[Finding]:
    findings = check_name(info.name) + check_type(info)
    # DISGUISED_EXEC вже каже, що це exe: дубль EXEC_FILE не додаємо
    if not any(f.id == "DISGUISED_EXEC" for f in findings):
        findings += check_exec(info)
    return findings
