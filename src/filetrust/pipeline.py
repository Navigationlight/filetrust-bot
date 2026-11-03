from pathlib import Path
from typing import Callable

from filetrust.analyzers import common, archive, pdf, html_page, office
from filetrust.detect import inspect_file
from filetrust.models import FileInfo, Finding

Analyzer = Callable[[FileInfo], list[Finding]]

# вид файлу -> список перевірок. Нові кроки просто додають рядки сюди.
ANALYZERS: dict[str, list[Analyzer]] = {
    "zip": [archive.check_zip, office.check_ooxml],
    "ooxml": [archive.check_zip, office.check_ooxml],
    "7z": [archive.check_7z],
    "ole": [office.check_ole],
    "pdf": [pdf.check_pdf],
    "html": [html_page.check_html],
}


def analyze(path: Path, name: str) -> tuple[FileInfo, list[Finding]]:
    info = inspect_file(path, name)
    findings = common.check(info)
    for fn in ANALYZERS.get(info.kind, []):
        findings += fn(info)
    return info, findings