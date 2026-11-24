import asyncio
import tempfile
import time
from pathlib import Path
from aiogram import Router, F, Bot
from aiogram.filters import CommandStart
from aiogram.types import Message
from filetrust.config import MAX_FILE_MB
from filetrust.pipeline import analyze
from filetrust.scoring.engine import score
from filetrust.report import format_report

router = Router()

COOLDOWN_SEC = 5         
TIMEOUT_SEC = 60          
_last_request: dict[int, float] = {}
_slots = asyncio.Semaphore(2)   


@router.message(CommandStart())
async def start(message: Message):
    await message.answer(
        "Надішліть мені файл, і я перевірю, чи він є тим за кого себе видає. "
        "Файл не запускається,а  лише аналізується.")


@router.message(F.document)
async def on_file(message: Message, bot: Bot):
    doc = message.document
    uid = message.from_user.id
    now = time.monotonic()
    wait = COOLDOWN_SEC - (now - _last_request.get(uid, 0))
    if wait > 0:
        await message.answer(f"Занадто часто. Спробуйте через {int(wait) + 1} с.")
        return
    _last_request[uid] = now

    if doc.file_size and doc.file_size > MAX_FILE_MB * 1024 * 1024:
        await message.answer(f"Файл завеликий (максимум {MAX_FILE_MB} МБ).")
        return

    async with _slots:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.bin"   # фіксоване імʼя, не від користувача
            await bot.download(doc, destination=path)
            try:
                info, findings = await asyncio.wait_for(
                    asyncio.to_thread(analyze, path, doc.file_name or "unnamed"),
                    timeout=TIMEOUT_SEC)
            except asyncio.TimeoutError:
                await message.answer("Аналіз зайняв забагато часу, файл пропущено.")
                return
            except Exception:
                await message.answer("Не вдалося проаналізувати файл.")
                return
    total, verdict = score(findings)
    await message.answer(format_report(info, total, verdict, findings))
