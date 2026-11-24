import asyncio
import logging

from aiogram import Bot, Dispatcher
from filetrust.config import BOT_TOKEN, LOG_LEVEL
from filetrust.handlers import router


async def run():
    if not BOT_TOKEN:
        raise SystemExit("Немає BOT_TOKEN у файлі .env")
    logging.basicConfig(
        level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    bot = Bot(BOT_TOKEN)
    dp = Dispatcher()
    dp.include_router(router)
    await dp.start_polling(bot, allowed_updates=["message", "callback_query"])

if __name__ == "__main__":
    asyncio.run(run())
