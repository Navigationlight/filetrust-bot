"""Формування відповідей бота у Telegram HTML.

Усі дані від користувача (назви файлів, тексти знахідок) екранується через esc().
Відповідь збирається з цілих блоків і обрізається по межах блоків,
щоб розмітка ніколи не ламалась на півтеґу.
"""
import html
import re

from filetrust.models import FileInfo, Finding
from filetrust.scoring.explain import ORDER, category_of

URL_RE = re.compile(r"https?://[^\s)»]+")

ADVICE = {
    "ВИСОКИЙ": "Що робити: не відкривайте файл, видаліть його, запитайте відправника іншим каналом.",
    "ПІДОЗРІЛО": "Що робити: відкривайте лише якщо впевнені у відправнику, бажано у пісочниці.",
    "НИЗЬКИЙ": "Що робити: явних ознак загрози немає, але обережність не зайва.",
}
ICONS = {"Маскування": "🎭", "Виконання коду": "⚙️", "Фішинг": "🎣",
         "Контейнер": "📦", "Інше": "▫️", "Комбінація": "🔗"}

TG_LIMIT = 4000       # ліміт Telegram 4096 символів, лишаємо запас
TECH_LINES = 20       # скільки рядків показуємо у блоці для технарів


def esc(text: str) -> str:
    return html.escape(str(text), quote=False)


def limit(text: str, size: int = TG_LIMIT) -> str:
    """Обрізка простого тексту. Для HTML використовуйте fit()."""
    return text if len(text) <= size else text[:size - 1] + "…"


def fit(blocks: list[str], size: int = TG_LIMIT) -> str:
    """З'єднує цілі HTML-блоки, не перевищуючи ліміт. Перший блок завжди лишається."""
    out, used = [], 0
    for i, b in enumerate(blocks):
        if used + len(b) + 1 > size and i > 0:
            break
        out.append(b)
        used += len(b) + 1
    return "\n".join(out)


def strip_tags(text: str) -> str:
    """Запасний варіант, якщо Telegram не прийняв розмітку."""
    return html.unescape(re.sub(r"<[^>]+>", "", text))


def no_ping(text: str) -> str:
    """@ у назві файлу не повинен позначати людей у групі."""
    return text.replace("@", "@\u200b")


def defang(text: str) -> str:
    """hxxp і [.] у посиланнях, щоб у чаті на них випадково не натиснули."""
    def fix(m):
        return m.group(0).replace("http", "hxxp", 1).replace(".", "[.]")
    return URL_RE.sub(fix, text)


def human_size(n: int) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024 or unit == "ГБ":
            return f"{n} Б" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} Б"


def bar(total: int, width: int = 10) -> str:
    filled = round(width * max(0, min(100, total)) / 100)
    return "▰" * filled + "▱" * (width - filled)


def _advice(verdict: str) -> str:
    for key, text in ADVICE.items():
        if key in verdict:
            return text
    return ""


def format_report(info: FileInfo, total: int, verdict: str,
                  findings: list[Finding], story: str = "") -> str:
    """Повний звіт для особистого чату: вердикт, характеристики, висновок, знахідки, техдеталі."""
    sha = info.sha256
    head = [
        f"<b>{esc(verdict)}</b>",
        f"<code>{bar(total)} {total}/100</code>",
        "",
        f"📄 <b>{esc(info.name)}</b>",
        "<pre>"
        f"Тип      {esc(info.kind)} ({esc(info.mime)})\n"
        f"Розмір   {human_size(info.size)}\n"
        f"Правил   {len(findings)} спрацювало"
        "</pre>",
        f"SHA256: <code>{sha}</code>",
        f'<a href="https://www.virustotal.com/gui/file/{sha}">Знайти за хешем у VirusTotal</a>',
    ]
    blocks = ["\n".join(head)]
    if story:
        blocks.append(f"<blockquote>{esc(story)}</blockquote>")

    if findings:
        n = 0
        for cat in ORDER:
            group = [f for f in findings if category_of(f.id) == cat]
            if not group:
                continue
            lines = [f"{ICONS.get(cat, '▫️')} <b>{esc(cat)}:</b>"]
            for f in group:
                n += 1
                lines.append(f"{n}. {esc(defang(f.text))} <i>(+{f.points})</i>")
            blocks.append("\n".join(lines))
        blocks.append(_tech_block(findings, total))
    else:
        blocks.append("Підозрілих ознак не знайдено.\n"
                      "<i>Це не гарантія безпеки, а лише результат наших перевірок.</i>")

    advice = _advice(verdict)
    if advice:
        blocks.append(f"<blockquote>{esc(advice)}</blockquote>")
    # технічний блок і порада важливіші за хвіст довгого списку: ставимо їх у кінець бюджету
    return fit_keep_tail(blocks)


def _tech_block(findings: list[Finding], total: int) -> str:
    """Для технарів: ідентифікатори правил, бали, категорії у блоці, що розгортається."""
    rows = []
    for f in sorted(findings, key=lambda x: -x.points)[:TECH_LINES]:
        rows.append(f"{f.id:<26} +{f.points:<3} {category_of(f.id)}")
    if len(findings) > TECH_LINES:
        rows.append(f"… ще {len(findings) - TECH_LINES}")
    raw = sum(f.points for f in findings)
    rows.append(f"Сума {raw}, стеля 100 → {total}")
    return "🔬 <b>Технічні деталі</b>\n<blockquote expandable>" + esc("\n".join(rows)) + "</blockquote>"


def fit_keep_tail(blocks: list[str], size: int = TG_LIMIT) -> str:
    """Як fit, але останні 2 блоки (техдеталі й порада) мають пріоритет над серединою."""
    if sum(len(b) + 1 for b in blocks) <= size:
        return "\n".join(blocks)
    tail, body = blocks[-2:], blocks[:-2]
    note = "<i>… частину знахідок приховано, дивіться технічні деталі</i>"
    room = size - sum(len(b) + 1 for b in tail) - len(note) - 2
    return "\n".join([fit(body, room), note] + tail)


def show_url(url: str, size: int = 70) -> str:
    """Посилання у безпечному вигляді: hxxp і [.]"""
    u = url.replace("http", "hxxp", 1) if url.lower().startswith("http") else url
    u = no_ping(u.replace(".", "[.]"))
    return u if len(u) <= size else u[:size - 1] + "…"


def format_short(name: str, a) -> str:
    """Короткий звіт для груп: вердикт, до 3 головних знахідок, порада."""
    top = sorted(a.findings, key=lambda f: -f.points)[:3]
    lines = [f"<b>{esc(a.verdict)}</b> · <code>{a.total}/100</code>",
             f"📄 {esc(no_ping(name))}"]
    lines += [f"• {esc(defang(no_ping(f.text)))}" for f in top]
    blocks = ["\n".join(lines)]
    advice = _advice(a.verdict)
    if advice:
        blocks.append(f"<blockquote>{esc(advice)}</blockquote>")
    return fit(blocks)


def format_links(results: list, short: bool = False) -> str:
    """results: список (адреса, Assessment). У короткому режимі лише ризикові."""
    blocks = [] if short else [f"🔗 <b>Перевірка посилань: {len(results)}</b>"]
    shown = 0
    for n, (url, a) in enumerate(results, 1):
        if short and a.total < 30:
            continue
        shown += 1
        top = sorted(a.findings, key=lambda f: -f.points)[: 2 if short else 5]
        lines = [f"<b>{n}.</b> <code>{esc(show_url(url))}</code>",
                 f"{esc(a.verdict)} · <code>{a.total}/100</code>"]
        lines += [f"• {esc(defang(f.text))} <i>(+{f.points})</i>" for f in top]
        if not top:
            lines.append("Явних ознак підміни в адресі немає.")
        blocks.append("\n".join(lines))
    if short and not shown:
        return ""
    blocks.append("<blockquote>Не переходьте за такими посиланнями.</blockquote>" if short else
                  "<i>Сторінка не відкривалась, перевірено лише адресу. Це не гарантія безпеки.</i>")
    return fit_keep_last(blocks)


def fit_keep_last(blocks: list[str], size: int = TG_LIMIT) -> str:
    """Обрізає середину списку посилань, але лишає підсумковий рядок."""
    if sum(len(b) + 1 for b in blocks) <= size:
        return "\n".join(blocks)
    last = blocks[-1]
    kept = fit(blocks[:-1], size - len(last) - 40)
    return "\n".join([kept, "<i>… решту посилань приховано</i>", last])
