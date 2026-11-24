import sqlite3
import threading
from dataclasses import dataclass

FIELDS = ("files", "links", "quiet")


@dataclass
class ChatSettings:
    files: bool = True    # перевіряти файли
    links: bool = True    # перевіряти посилання
    quiet: bool = True    # відповідати лише на ризикові


class SettingsStore:
    """Налаштування груп у SQLite. Нічого, крім цих трьох прапорців, не зберігається."""

    def __init__(self, path: str):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS chat_settings ("
            "chat_id INTEGER PRIMARY KEY, files INTEGER, links INTEGER, quiet INTEGER)")
        self._db.commit()

    def get(self, chat_id: int) -> ChatSettings:
        with self._lock:
            row = self._db.execute(
                "SELECT files, links, quiet FROM chat_settings WHERE chat_id=?",
                (chat_id,)).fetchone()
        return ChatSettings(*map(bool, row)) if row else ChatSettings()

    def toggle(self, chat_id: int, field: str) -> ChatSettings:
        if field not in FIELDS:
            raise ValueError(field)
        s = self.get(chat_id)
        setattr(s, field, not getattr(s, field))
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO chat_settings VALUES (?,?,?,?)",
                (chat_id, s.files, s.links, s.quiet))
            self._db.commit()
        return s
