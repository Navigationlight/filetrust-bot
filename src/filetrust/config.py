import os
from dotenv import load_dotenv

load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
DB_PATH = os.getenv("DB_PATH", "filetrust.db")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
MAX_FILE_MB = 20
TIMEOUT_SEC = 60      # максимум на аналіз одного файлу
