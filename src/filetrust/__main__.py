import asyncio
from aiogram import Bot, Dispatcher
from filetrust.config import BOT_TOKEN
from filetrust.handlers import router

async def run():
    if not BOT_TOKEN:
        raise SystemExit("Немає BOT_TOKEN у файлі .env")
    bot = Bot(BOT_TOKEN)
    dp = Dispatcher()
    dp.include_router(router)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(run())
