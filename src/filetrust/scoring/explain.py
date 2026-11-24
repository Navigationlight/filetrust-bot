
from dataclasses import dataclass, field

from filetrust.models import Finding
from filetrust.scoring.engine import score

MASK = "Маскування"
CODE = "Виконання коду"
PHISH = "Фішинг"
CONT = "Контейнер"
CHAIN = "Комбінація"
OTHER = "Інше"
ORDER = [MASK, CODE, PHISH, CONT, OTHER, CHAIN]

_CATEGORY = {
    # файл вдає із себе щось інше
    "RTLO": MASK, "DOUBLE_EXT": MASK, "DISGUISED_EXEC": MASK,
    "TYPE_MISMATCH": MASK, "OFFICE_MACRO_HIDDEN_EXT": MASK,
    # код, який може виконатись
    "EXEC_FILE": CODE, "ARCHIVE_EXEC": CODE,
    "PDF_LAUNCH": CODE, "PDF_JAVASCRIPT": CODE, "PDF_AUTO_RUN": CODE,
    "PDF_OBFUSCATED": CODE, "PDF_EMBEDDED_EXEC": CODE,
    "OFFICE_MACRO": CODE, "OFFICE_MACRO_AUTOEXEC": CODE,
    "OFFICE_MACRO_SUSPICIOUS": CODE, "OFFICE_MACRO_IOC": CODE,
    "OFFICE_DDE": CODE, "OFFICE_EMBEDDED_EXEC": CODE,
    "HTML_SMUGGLING": CODE, "HTML_OBFUSCATED_JS": CODE,
    # крадіжка даних і підозрілі адреси
    "HTML_PASSWORD_FORM": PHISH, "HTML_FORM_EXTERNAL": PHISH,
    "HTML_REDIRECT": PHISH, "HTML_HIDDEN_IFRAME": PHISH,
    "HTML_SUSPICIOUS_LINK": PHISH, "PDF_SUSPICIOUS_LINK": PHISH,
    "OFFICE_SUSPICIOUS_LINK": PHISH, "OFFICE_REMOTE_CONTENT": PHISH,
    # структура контейнера
    "ARCHIVE_ENCRYPTED": CONT, "ARCHIVE_BOMB": CONT,
    "ARCHIVE_PATH_TRAVERSAL": CONT, "ARCHIVE_UNREADABLE": CONT,
    "PDF_EMBEDDED_FILE": CONT, "PDF_RICHMEDIA": CONT,
}

_STORY = {
    MASK: "файл маскується під інший тип",
    CODE: "містить код, який може виконатись",
    PHISH: "веде на підозрілі адреси або збирає дані",
    CONT: "має ризиковий вміст чи структуру контейнера",
}


def category_of(fid: str) -> str:
    if fid in _CATEGORY:
        return _CATEGORY[fid]
    if fid.startswith("CHAIN_"):
        return CHAIN
    if fid.startswith("ARCHIVE_"):          # знахідки назви всередині архіву
        return _CATEGORY.get(fid[len("ARCHIVE_"):], CONT)
    return OTHER


def _chains(findings: list[Finding]) -> list[Finding]:
    ids = {f.id for f in findings}
    cats = {category_of(i) for i in ids}
    out = []
    if MASK in cats and CODE in cats:
        out.append(Finding(
            "CHAIN_MASK_CODE", 15,
            "Файл маскується під інший тип і водночас містить код, що виконується"))
    if "ARCHIVE_ENCRYPTED" in ids and cats & {MASK, CODE}:
        out.append(Finding(
            "CHAIN_LOCKED_PAYLOAD", 15,
            "Архів під паролем разом із підозрілим вмістом: так обходять автоматичні перевірки"))
    if PHISH in cats and CODE in cats:
        out.append(Finding(
            "CHAIN_PHISH_CODE", 10,
            "Підозрілі адреси разом із кодом: схоже на доставку шкідливого вмісту"))
    return out


@dataclass
class Assessment:
    total: int
    verdict: str
    findings: list[Finding]                       # разом із комбінаціями
    categories: dict[str, int] = field(default_factory=dict)   
    story: str = ""


def assess(findings: list[Finding]) -> Assessment:
    all_f = list(findings) + _chains(findings)
    total, verdict = score(all_f)
    cats: dict[str, int] = {}
    for f in all_f:
        c = category_of(f.id)
        cats[c] = cats.get(c, 0) + f.points
    parts = [_STORY[c] for c in (MASK, CODE, PHISH, CONT) if c in cats]
    story = ("Висновок: " + "; ".join(parts) + ".") if parts else ""
    return Assessment(total, verdict, all_f, cats, story)
