import re
from filetrust.models import FileInfo, Finding
from filetrust.scoring.explain import ORDER, category_of

URL_RE = re.compile(r"https?://[^\s)»]+")

ADVICE = {
    "ВИСОКИЙ": "Що робити: не відкривайте файл, видаліть його, запитайте відправника іншим каналом.",
    "ПІДОЗРІЛО": "Що робити: відкривайте лише якщо впевнені у відправнику, бажано у пісочниці.",
    "НИЗЬКИЙ": "Що робити: явних ознак загрози немає, але обережність не зайва.",
}


TG_LIMIT = 4000   # ліміт Telegram 4096 символів, лишаємо запас


def limit(text: str, size: int = TG_LIMIT) -> str:
    return text if len(text) <= size else text[:size - 1] + "…"


def no_ping(text: str) -> str:
    """@ у назві файлу не повинен позначати людей у групі."""
    return text.replace("@", "@\u200b")


def defang(text: str) -> str:
    """hxxp і [.] у посиланнях,щоб у чаті на них випадково не натиснули."""
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
    return limit("\n".join(lines))


def show_url(url: str, size: int = 70) -> str:
    """Посилання у безпечному вигляді: hxxp і [.]"""
    u = url.replace("http", "hxxp", 1) if url.lower().startswith("http") else url
    u = no_ping(u.replace(".", "[.]"))
    return u if len(u) <= size else u[:size - 1] + "…"


def format_short(name: str, a) -> str:
    """Короткий звіт для груп: вердикт, до 3 головних знахідок, порада."""
    top = sorted(a.findings, key=lambda f: -f.points)[:3]
    lines = [f"{a.verdict} ({a.total}/100)", f"📄 {no_ping(name)}"]
    lines += [f"• {defang(no_ping(f.text))}" for f in top]
    for key, text in ADVICE.items():
        if key in a.verdict:
            lines += ["", text]
            break
    return limit("\n".join(lines))


def format_links(results: list, short: bool = False) -> str:
    """ список (адреса, Assessment). У короткому режимі лише ризикові."""
    lines = [] if short else [f"🔗 Перевірка посилань: {len(results)}", ""]
    shown = 0
    for n, (url, a) in enumerate(results, 1):
        if short and a.total < 30:
            continue
        shown += 1
        lines += [f"{n}. {show_url(url)}", f"{a.verdict} ({a.total}/100)"]
        top = sorted(a.findings, key=lambda f: -f.points)[: 2 if short else 5]
        lines += [f"• {f.text} (+{f.points})" for f in top]
        if not top:
            lines.append("Явних ознак підміни в адресі немає.")
        lines.append("")
    if short and not shown:
        return ""
    lines.append("Сторінка не відкривалась, перевірено лише адресу. Це не гарантія безпеки."
                 if not short else "Не переходьте за такими посиланнями.")
    return limit("\n".join(lines))
