import re
from filetrust.models import FileInfo, Finding

URL_RE = re.compile(r"https?://[^\s)»]+")

ADVICE = {
    "ВИСОКИЙ": "Що робити: не відкривайте файл, видаліть його, запитайте відправника іншим каналом.",
    "ПІДОЗРІЛО": "Що робити: відкривайте лише якщо впевнені у відправнику, бажано у пісочниці.",
    "НИЗЬКИЙ": "Що робити: явних ознак загрози немає, але обережність не зайва.",
}


def defang(text: str) -> str:

    def fix(m):
        return m.group(0).replace("http", "hxxp", 1).replace(".", "[.]")
    return URL_RE.sub(fix, text)


def format_report(info: FileInfo, total: int, verdict: str,
                  findings: list[Finding]) -> str:
    lines = [
        f"📄 {info.name}",
        f"Тип за вмістом: {info.kind} ({info.mime})",
        f"SHA256: {info.sha256[:12]}…{info.sha256[-6:]}",
        "",
        f"{verdict} ({total}/100)",
        "",
    ]
    if findings:
        lines.append("Знахідки:")
        for i, f in enumerate(findings, 1):
            lines.append(f"{i}. {defang(f.text)} (+{f.points})")
    else:
        lines.append("Підозрілих ознак не знайдено.")
        lines.append("Це не гарантія безпеки, а лише результат наших перевірок.")
    for key, text in ADVICE.items():
        if key in verdict:
            lines += ["", text]
            break
    return "\n".join(lines)
