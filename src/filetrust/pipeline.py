from pathlib import Path
from typing import Callable
from filetrust.detect import inspect_file
from filetrust.models import FileInfo, Finding
from filetrust.analyzers import common, archive, pdf, html_page

Analyzer = Callable[[FileInfo], list[Finding]]

# вид файла -> список проверок. Новые шаги просто добавляют строки сюда.
ANALYZERS: dict[str, list[Analyzer]] = {
    "zip": [archive.check_zip],
    "pdf": [pdf.check_pdf],
    "html": [html_page.check_html],
}


def analyze(path: Path, name: str) -> tuple[FileInfo, list[Finding]]:
    info = inspect_file(path, name)
    findings = common.check(info)
    for fn in ANALYZERS.get(info.kind, []):
        findings += fn(info)
    return info, findings
