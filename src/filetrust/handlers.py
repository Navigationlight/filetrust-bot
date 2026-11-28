import asyncio
import logging
import tempfile
import time
from pathlib import Path

from aiogram import Router, F, Bot
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramAPIError, TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.types import (CallbackQuery, InlineKeyboardButton,
                           InlineKeyboardMarkup, Message)

from filetrust.analyzers.urlcheck import check_url, extract_urls
from filetrust.config import DB_PATH, MAX_FILE_MB, SAFE_BROWSING_KEY, VT_API_KEY
from filetrust.vt import lookup as vt_lookup
from filetrust import sb
from filetrust.isolated import analyze_isolated
from filetrust.report import format_links, format_report, format_short, limit, no_ping, strip_tags
from filetrust.scoring.explain import assess
from filetrust.store import SettingsStore

log = logging.getLogger("filetrust")
router = Router()

COOLDOWN_SEC = 5               # пауза між файлами одного користувача
_cooldown: dict[tuple[int, int], float] = {}
_slots = asyncio.Semaphore(2)  # не більше 2 аналізів одночасно
_store: SettingsStore | None = None

HELP_PRIVATE = (
    "Надішліть мені файл або посилання, і я перевірю, чи можна їм довіряти.\n"
    "Файл не запускається, посилання не відкривається: аналізується лише вміст і адреса.\n\n"
    "Групи: додайте мене в чат, і я буду мовчки перевіряти файли та посилання, "
    "а писати лише коли знайду ризик. Налаштування: /settings у групі.")
HELP_GROUP = (
    "Я перевіряю файли та посилання і пишу лише коли бачу ризик.\n"
    "/settings: налаштування (для адміністраторів)\n"
    "/check: відповісти цією командою на файл чи посилання, щоб перевірити його вручну")


def store() -> SettingsStore:
    global _store
    if _store is None:
        _store = SettingsStore(DB_PATH)
    return _store


def is_group(message: Message) -> bool:
    return message.chat.type in ("group", "supergroup")


def cooldown_ok(chat_id: int, user_id: int) -> tuple[bool, int]:
    now = time.monotonic()
    if len(_cooldown) > 5000:                     # не даємо словнику рости без меж
        for k in [k for k, t in _cooldown.items() if now - t > COOLDOWN_SEC * 10]:
            del _cooldown[k]
    key = (chat_id, user_id)
    wait = COOLDOWN_SEC - (now - _cooldown.get(key, 0))
    if wait > 0:
        return False, int(wait) + 1
    _cooldown[key] = now
    return True, 0


async def reply(message: Message, text: str, group: bool) -> None:
    """У групах без сповіщення, як відповідь на повідомлення. Збій відправки не валить бота."""
    try:
        await message.reply(text, parse_mode=ParseMode.HTML, disable_notification=group)
    except TelegramBadRequest as exc:
        if "parse" not in str(exc).lower():
            log.warning("не вдалося надіслати відповідь: %s", exc)
            return
        try:                          # розмітку не прийнято: надсилаємо простим текстом
            await message.reply(strip_tags(text), parse_mode=None, disable_notification=group)
        except TelegramAPIError as exc2:
            log.warning("не вдалося надіслати відповідь: %s", exc2)
    except TelegramAPIError as exc:
        log.warning("не вдалося надіслати відповідь: %s", exc)


async def scan_document(bot: Bot, doc):
    """Повертає (info, оцінка) або рядок з причиною, чому не вдалося."""
    if doc.file_size and doc.file_size > MAX_FILE_MB * 1024 * 1024:
        return f"Файл завеликий (максимум {MAX_FILE_MB} МБ)."
    async with _slots:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = Path(tmp) / "sample.bin"       # фіксована назва, не від користувача
            try:
                await bot.download(doc, destination=path)
                info, findings = await analyze_isolated(path, doc.file_name or "unnamed")
            except asyncio.TimeoutError:
                log.warning("таймаут аналізу %s", doc.file_unique_id)
                return "Аналіз зайняв забагато часу, файл пропущено."
            except Exception:
                log.exception("помилка аналізу %s", doc.file_unique_id)
                return "Не вдалося проаналізувати файл."
    return info, assess(findings)


async def handle_document(bot: Bot, message: Message, doc, force: bool = False) -> None:
    group = is_group(message)
    s = store().get(message.chat.id) if group else None
    if group and not force and not s.files:
        return
    ok, wait = cooldown_ok(message.chat.id, message.from_user.id)
    if not ok:
        if not group or force:
            await reply(message, f"Занадто часто. Спробуйте через {wait} с.", group)
        return
    result = await scan_document(bot, doc)
    if isinstance(result, str):
        if not group or force:
            await reply(message, result, group)
        return
    info, a = result
    if not group:
        vt = await vt_lookup(info.sha256, VT_API_KEY)
        await reply(message, format_report(info, a.total, a.verdict, a.findings, a.story, vt), False)
    elif a.total >= 30 or force or not s.quiet:
        await reply(message, format_short(info.name, a), True)


async def handle_text(message: Message, text: str, entities, force: bool = False) -> None:
    group = is_group(message)
    s = store().get(message.chat.id) if group else None
    if group and not force and not s.links:
        return
    urls = extract_urls(text, entities)
    if not urls:
        if not group or force:
            await reply(message, "Не знайшов посилань. Надішліть посилання або файл.", group)
        return
    threats = await sb.lookup([u for u, _ in urls], SAFE_BROWSING_KEY) or {}
    results = [(u, assess(check_url(u, shown) + sb.findings_for(threats.get(u)))) for u, shown in urls]
    if not group:
        await reply(message, format_links(results), False)
        return
    short = format_links(results, short=True)
    if short:
        await reply(message, short, True)
    elif force or not s.quiet:
        await reply(message, "🟢 Явних ознак підміни в посиланні немає.", True)




@router.message(CommandStart())
@router.message(Command("help"))
async def start(message: Message):
    await reply(message, HELP_GROUP if is_group(message) else HELP_PRIVATE, is_group(message))


async def is_admin(bot: Bot, chat_id: int, user_id: int) -> bool:
    try:
        member = await bot.get_chat_member(chat_id, user_id)
    except TelegramAPIError:
        return False
    return member.status in ("creator", "administrator")


def settings_view(chat_id: int) -> tuple[str, InlineKeyboardMarkup]:
    s = store().get(chat_id)
    mark = lambda v: "✅" if v else "❌"
    text = (
        "⚙️ Налаштування filetrust для цієї групи\n\n"
        f"📄 Файли: {'перевіряю' if s.files else 'вимкнено'}\n"
        f"🔗 Посилання: {'перевіряю' if s.links else 'вимкнено'}\n"
        f"🔕 Тихий режим: {'пишу лише про ризик' if s.quiet else 'відповідаю на все'}\n\n"
        "Змінювати можуть лише адміністратори. Вручну перевірити файл чи посилання "
        "можна командою /check у відповіді на повідомлення.")
    kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=f"📄 Файли {mark(s.files)}", callback_data="cfg:files"),
        InlineKeyboardButton(text=f"🔗 Посилання {mark(s.links)}", callback_data="cfg:links"),
    ], [
        InlineKeyboardButton(text=f"🔕 Тихий режим {mark(s.quiet)}", callback_data="cfg:quiet"),
    ]])
    return text, kb


@router.message(Command("settings"))
async def settings(message: Message, bot: Bot):
    if not is_group(message):
        await reply(message, "Налаштування є лише в групах. Тут я перевіряю все, що ви надішлете.", False)
        return
    if not await is_admin(bot, message.chat.id, message.from_user.id):
        await reply(message, "Налаштування доступні лише адміністраторам.", True)
        return
    text, kb = settings_view(message.chat.id)
    try:
        await message.reply(text, reply_markup=kb, disable_notification=True)
    except TelegramAPIError as exc:
        log.warning("settings: %s", exc)


@router.callback_query(F.data.startswith("cfg:"))
async def toggle(cb: CallbackQuery, bot: Bot):
    msg = cb.message
    if msg is None or msg.chat.type not in ("group", "supergroup"):
        await cb.answer()
        return
    if not await is_admin(bot, msg.chat.id, cb.from_user.id):
        await cb.answer("Лише для адміністраторів", show_alert=True)
        return
    try:
        store().toggle(msg.chat.id, cb.data.split(":", 1)[1])
    except ValueError:
        await cb.answer()
        return
    text, kb = settings_view(msg.chat.id)
    try:
        await msg.edit_text(text, reply_markup=kb)
    except TelegramAPIError:
        pass                      
    await cb.answer("Збережено")


@router.message(Command("check"))
async def check(message: Message, bot: Bot):
    if message.from_user is None:
        return
    target = message.reply_to_message
    if target is None:
        await reply(message, "Відповідайте цією командою на повідомлення з файлом чи посиланням.",
                    is_group(message))
    elif target.document:
        await handle_document(bot, message, target.document, force=True)
    else:
        await handle_text(message, target.text or target.caption or "",
                          target.entities or target.caption_entities, force=True)



@router.message(F.document)
async def on_file(message: Message, bot: Bot):
    if message.from_user and not message.from_user.is_bot:
        await handle_document(bot, message, message.document)


@router.message(F.text & ~F.text.startswith("/"))
async def on_text(message: Message):
    if message.from_user and not message.from_user.is_bot:
        await handle_text(message, message.text, message.entities)
