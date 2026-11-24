import logging
from pathlib import Path
from typing import Callable

from filetrust.analyzers import common, archive, pdf, html_page, office
from filetrust.detect import inspect_file
from filetrust.models import FileInfo, Finding

log = logging.getLogger("filetrust")
Analyzer = Callable[[FileInfo], list[Finding]]

# вид файлу і список перевірок. Нові кроки просто додають рядки сюди.
ANALYZERS: dict[str, list[Analyzer]] = {
    "zip": [archive.check_zip, office.check_ooxml],
    "ooxml": [archive.check_zip, office.check_ooxml],
    "7z": [archive.check_7z],
    "ole": [office.check_ole],
    "pdf": [pdf.check_pdf],
    "html": [html_page.check_html],
}


# Файл ніколи не запускається: лише читається байтами.
# Вид визначаємо за вмістом (libmagic), а не за розширенням
def analyze(path: Path, name: str) -> tuple[FileInfo, list[Finding]]:
    info = inspect_file(path, name)
    findings: list[Finding] = []
    # збій однієї перевірки не повинен губити результат інших
    for fn in [common.check] + ANALYZERS.get(info.kind, []):
        try:
            findings += fn(info)
        except Exception:
            log.exception("перевірка %s завершилась помилкою", fn.__name__)
            findings.append(Finding(
                "ANALYSIS_PARTIAL", 15,
                "Частину перевірок виконати не вдалося: файл пошкоджений або незвичний"))
    return info, findings
