# Розгортання та експлуатація filetrust

## 1. Налаштування конфігурації (`src/filetrust/config.py`)

Бот зчитує конфігурацію зі змінних середовища або файлу `.env` у корені проєкту:

| Змінна | Значення за замовчуванням | Опис |
|---|---|---|
| `BOT_TOKEN` | *(обов'язково)* | Токен бота, отриманий у `@BotFather` |
| `DB_PATH` | `filetrust.db` | Шлях до локальної бази SQLite (`store.py`) для збереження налаштувань групових чатів |
| `LOG_LEVEL` | `INFO` | Рівень журналювання (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

Константи безпеки у `config.py`:
- `MAX_FILE_MB = 20` — верхній поріг розміру вхідного файлу (узгоджений із лімітом стандартного Telegram Bot API);
- `TIMEOUT_SEC = 60` — таймаут виконання одного файлу в ізольованому процесі `worker.py`.

---

## 2. Продакшен-розгортання на Ubuntu через `systemd`

У репозиторії підготовлено готовий шаблон сервісу [`deploy/filetrust-bot.service.example`](../deploy/filetrust-bot.service.example) із застосуванням механізмів ізоляції ядра Linux:

```bash
# 1. Створення виділеного системного облікового запису без права інтерактивного входу
sudo useradd --system --create-home --home-dir /opt/filetrust --shell /usr/sbin/nologin filetrust

# 2. Клонування проєкту та встановлення залежностей у віртуальне середовище
sudo -u filetrust git clone [https://github.com/Navigationlight/filetrust-bot.git](https://github.com/Navigationlight/filetrust-bot.git) /opt/filetrust/filetrust-bot
cd /opt/filetrust/filetrust-bot
sudo -u filetrust python3 -m venv .venv
sudo -u filetrust .venv/bin/pip install -r requirements.txt

# 3. Створення робочого .env та реєстрація systemd-юніта
sudo -u filetrust cp .env.example .env
# Додайте BOT_TOKEN у /opt/filetrust/filetrust-bot/.env

sudo cp deploy/filetrust-bot.service.example /etc/systemd/system/filetrust-bot.service
sudo systemctl daemon-reload
sudo systemctl enable --now filetrust-bot
sudo systemctl status filetrust-bot
