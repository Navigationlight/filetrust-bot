import zipfile
from pathlib import PurePosixPath
from typing import NamedTuple

from filetrust.analyzers.common import EXEC_EXTS, check_name
from filetrust.models import FileInfo, Finding

MAX_ENTRIES = 10_000                 # не обходимо більше записів
BOMB_RATIO = 100                     # у скільки разів стиснуто
BOMB_MIN_SIZE = 100 * 1024 * 1024    # і розпакується мінімум 100 МБ


class Entry(NamedTuple):
    name: str         # повний шлях усередині архіву
    size: int         # розмір після розпакування
    encrypted: bool   # захищений паролем


def _short(names: list[str], limit: int = 3) -> str:
    shown = ", ".join(f"«{n}»" for n in names[:limit])
    extra = len(names) - limit
    return shown + (f" та ще {extra}" if extra > 0 else "")


def _is_unsafe_path(name: str) -> bool:
    n = name.replace("\\", "/")
    return (n.startswith("/")
            or ".." in n.split("/")
            or (len(n) > 1 and n[1] == ":"))


def analyze_entries(entries: list[Entry], archive_size: int) -> list[Finding]:
    """Спільна логіка для zip та 7z: список записів -> знахідки."""
    exec_names: list[str] = []
    encrypted: list[str] = []
    traversal: list[str] = []
    masked: list[tuple[str, Finding]] = []
    total_unc = 0

    for e in entries:
        base = PurePosixPath(e.name.replace("\\", "/")).name
        total_unc += e.size
        if e.encrypted:
            encrypted.append(base)
        if _is_unsafe_path(e.name):
            traversal.append(e.name)
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
    if (total_unc >= BOMB_MIN_SIZE and archive_size > 0
            and total_unc / archive_size > BOMB_RATIO):
        findings.append(Finding(
            "ARCHIVE_BOMB", 40,
            f"Дуже сильне стиснення: розпакується до "
            f"{total_unc // (1024 * 1024)} МБ"))
    return findings


def check_zip(info: FileInfo) -> list[Finding]:
    try:
        zf = zipfile.ZipFile(info.path)
    except zipfile.BadZipFile:
        return [Finding("ARCHIVE_UNREADABLE", 20,
                        "Архів пошкоджений або має нестандартну структуру")]
    with zf:
        entries = [
            Entry(e.filename, e.file_size, bool(e.flag_bits & 0x1))
            for e in zf.infolist()[:MAX_ENTRIES] if not e.is_dir()
        ]
    return analyze_entries(entries, info.size)


def check_7z(info: FileInfo) -> list[Finding]:
    try:
        import py7zr
    except ImportError:
        return []
    try:
        with py7zr.SevenZipFile(str(info.path), mode="r") as z:
            locked = bool(z.needs_password())
            entries = []
            for e in list(z.list())[:MAX_ENTRIES]:
                if getattr(e, "is_directory", False):
                    continue
                size = getattr(e, "uncompressed", 0)
                entries.append(Entry(
                    e.filename, size if isinstance(size, int) else 0, locked))
    except Exception as exc:
        if "password" in type(exc).__name__.lower():
            return [Finding(
                "ARCHIVE_ENCRYPTED", 40,
                "Архів зашифровано паролем, вміст перевірити неможливо")]
        return [Finding("ARCHIVE_UNREADABLE", 20,
                        "Архів пошкоджений або має нестандартну структуру")]
    return analyze_entries(entries, info.size)