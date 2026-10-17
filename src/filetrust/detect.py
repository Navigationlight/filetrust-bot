import hashlib
from pathlib import Path
import magic
from filetrust.models import FileInfo

# Правила зверху вниз: перший збіг за префіксом MIME виграє
MIME_RULES = [
    ("application/x-dosexec", "exe"),
    ("application/vnd.microsoft.portable-executable", "exe"),
    ("application/x-msdownload", "exe"),
    ("application/x-executable", "elf"),
    ("application/x-pie-executable", "elf"),
    ("application/pdf", "pdf"),
    ("application/vnd.openxmlformats-officedocument", "ooxml"),
    ("application/msword", "ole"),
    ("application/vnd.ms-", "ole"),
    ("application/x-ole-storage", "ole"),
    ("application/cdfv2", "ole"),
    ("application/zip", "zip"),
    ("application/vnd.rar", "rar"),
    ("application/x-rar", "rar"),
    ("application/x-7z-compressed", "7z"),
    ("application/gzip", "gz"),
    ("application/x-ms-shortcut", "lnk"),
    ("text/html", "html"),
    ("image/", "image"),
    ("text/", "text"),
]

def kind_from_mime(mime: str) -> str:
    m = mime.lower()
    for prefix, kind in MIME_RULES:
        if m.startswith(prefix):
            return kind
    return "unknown"

def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def inspect_file(path: Path, name: str) -> FileInfo:
    mime = magic.from_file(str(path), mime=True)
    return FileInfo(
        name=name, path=path, size=path.stat().st_size,
        sha256=sha256_of(path), mime=mime, kind=kind_from_mime(mime),
    )
