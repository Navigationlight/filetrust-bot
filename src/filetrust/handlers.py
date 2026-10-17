import tempfile
from pathlib import Path
from aiogram import Router, F, Bot
from aiogram.filters import CommandStart
from aiogram.types import Message
from filetrust.config import MAX_FILE_MB
from filetrust.pipeline import analyze
from filetrust.scoring.engine import score
from filetrust.report import format_report

router = Router()

@router.message(CommandStart())
async def start(message: Message):
    await message.answer(
        "Надішліть мені файл, і я перевірю, чи він є тим, за кого себе видає. "
        "Файл не запускається, лише аналізується.")

@router.message(F.document)
async def on_file(message: Message, bot: Bot):
    doc = message.document
    if doc.file_size and doc.file_size > MAX_FILE_MB * 1024 * 1024:
        await message.answer(f"Файл завеликий (максимум {MAX_FILE_MB} МБ).")
        return
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "sample.bin"   # фіксоване імʼя, не від користувача
        await bot.download(doc, destination=path)
        try:
            info, findings = analyze(path, doc.file_name or "unnamed")
        except Exception:
            await message.answer("Не вдалося проаналізувати файл.")
            return
    total, verdict = score(findings)
    await message.answer(format_report(info, total, verdict, findings))
