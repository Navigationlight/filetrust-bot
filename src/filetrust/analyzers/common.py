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

def check_name(name: str) -> list[Finding]:
    """Перевірки тільки за назвою (не потребують файлу)."""
    findings = []
    suffixes = [s.lower().strip() for s in PurePath(name).suffixes]
    if "\u202e" in name:
        findings.append(Finding(
            "RTLO", 40,
            "У назві прихований символ, що перевертає розширення (прийом RTLO)"))
    if (len(suffixes) >= 2 and suffixes[-1] in EXEC_EXTS
            and suffixes[-2] in DOC_EXTS):
        findings.append(Finding(
            "DOUBLE_EXT", 40,
            f"Подвійне розширення: виглядає як документ, "
            f"а насправді {suffixes[-1]}"))
    return findings

def check_type(info: FileInfo) -> list[Finding]:
    """Розширення ↔ реальний тип за вмістом."""
    ext = PurePath(info.name).suffix.lower().strip()
    expected = EXPECTED_KIND.get(ext)
    if expected is None or info.kind == "unknown":
        return []
    if info.kind in COMPATIBLE.get(expected, {expected}):
        return []
    if info.kind in REAL_EXEC_KINDS:
        return [Finding(
            "DISGUISED_EXEC", 50,
            f"Розширення {ext}, але всередині виконуваний файл ({info.kind})")]
    return [Finding(
        "TYPE_MISMATCH", 25,
        f"Розширення {ext}, але вміст виглядає як «{info.kind}»")]

def check(info: FileInfo) -> list[Finding]:
    return check_name(info.name) + check_type(info)
