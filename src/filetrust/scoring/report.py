import re
from filetrust.models import FileInfo, Finding
from filetrust.scoring.explain import ORDER, category_of

URL_RE = re.compile(r"https?://[^\s)»]+")

ADVICE = {
    "ВИСОКИЙ": "Що робити: не відкривайте файл, видаліть його.",
    "ПІДОЗРІЛО": "Що робити: відкривайте лише якщо впевнені у відправнику, бажано у пісочниці.",
    "НИЗЬКИЙ": "Що робити: явних ознак загрози немає, але обережність не зайва.",
}


def defang(text: str) -> str:

    def fix(m):
        return m.group(0).replace("http", "hxxp", 1).replace(".", "[.]")
    return URL_RE.sub(fix, text)


def format_report(info: FileInfo, total: int, verdict: str,
                  findings: list[Finding], story: str = "") -> str:
    lines = [
        f"📄 {info.name}",
        f"Тип за вмістом: {info.kind} ({info.mime})",
        f"SHA256: {info.sha256[:12]}…{info.sha256[-6:]}",
        "",
        f"{verdict} ({total}/100)",
    ]
    if story:
        lines.append(story)
    lines.append("")
    if findings:
        n = 0
        for cat in ORDER:
            group = [f for f in findings if category_of(f.id) == cat]
            if not group:
                continue
            lines.append(f"{cat}:")
            for f in group:
                n += 1
                lines.append(f"{n}. {defang(f.text)} (+{f.points})")
    else:
        lines.append("Підозрілих ознак не знайдено.")
        lines.append("Це не гарантія безпеки, а лише результат  перевірок.")
    for key, text in ADVICE.items():
        if key in verdict:
            lines += ["", text]
            break
    return "\n".join(lines)
