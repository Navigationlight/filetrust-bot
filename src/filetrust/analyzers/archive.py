import zipfile
from pathlib import PurePosixPath
from filetrust.analyzers.common import EXEC_EXTS, check_name
from filetrust.models import FileInfo, Finding

MAX_ENTRIES = 10_000                 
BOMB_RATIO = 100                     
BOMB_MIN_SIZE = 100 * 1024 * 1024    

def _short(names: list[str], limit: int = 3) -> str:
    shown = ", ".join(f"«{n}»" for n in names[:limit])
    extra = len(names) - limit
    return shown + (f" та ще {extra}" if extra > 0 else "")


def _is_unsafe_path(name: str) -> bool:
    n = name.replace("\\", "/")
    return (n.startswith("/")
            or ".." in n.split("/")
            or (len(n) > 1 and n[1] == ":"))

def check_zip(info: FileInfo) -> list[Finding]:
    try:
        zf = zipfile.ZipFile(info.path)
    except zipfile.BadZipFile:
        return [Finding("ARCHIVE_UNREADABLE", 20,
                        "Архів пошкоджений або має нестандартну структуру")]

    exec_names, encrypted, traversal, masked = [], [], [], []
    total_unc = total_comp = 0

    with zf:
        entries = [e for e in zf.infolist()[:MAX_ENTRIES] if not e.is_dir()]

    for e in entries:
        base = PurePosixPath(e.filename.replace("\\", "/")).name
        total_unc += e.file_size
        total_comp += e.compress_size
        if e.flag_bits & 0x1:
            encrypted.append(base)
        if _is_unsafe_path(e.filename):
            traversal.append(e.filename)
        if PurePosixPath(base).suffix.lower() in EXEC_EXTS:
            exec_names.append(base)
        for f in check_name(base):
            masked.append((base, f))

    findings: list[Finding] = []
    if exec_names:
        findings.append(Finding(
            "ARCHIVE_EXEC", 60,
            f"Усередині архіву виконувані файли: {_short(exec_names)}"))
    for base, f in masked[:3]:
        findings.append(Finding(
            "ARCHIVE_" + f.id, f.points, f"В архіві «{base}»: {f.text}"))
    if traversal:
        findings.append(Finding(
            "ARCHIVE_PATH_TRAVERSAL", 50,
            f"Шляхи виходять за межі папки розпакування: {_short(traversal)}"))
    if encrypted:
        findings.append(Finding(
            "ARCHIVE_ENCRYPTED", 40,
            f"Файли в архіві захищені паролем ({len(encrypted)}), "
            f"вміст перевірити неможливо"))
    if (total_unc >= BOMB_MIN_SIZE and total_comp > 0
            and total_unc / total_comp > BOMB_RATIO):
        findings.append(Finding(
            "ARCHIVE_BOMB", 40,
            f"Дуже сильне стиснення: розпакується до {total_unc // (1024 * 1024)} МБ"))
    return findings
