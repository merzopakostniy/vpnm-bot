# VPN Telegram Bot

Бот продает доступ к VLESS Reality через 3x-ui:

- создает платеж YooKassa;
- проверяет оплату;
- добавляет отдельного клиента в inbound `XUI_INBOUND_ID`;
- ставит лимит `2` устройства;
- сохраняет покупку в SQLite;
- выдает пользователю персональную `vless://` ссылку.

## Настройка

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
```

Заполни `.env`:

```text
BOT_TOKEN=...
YOOKASSA_SHOP_ID=...
YOOKASSA_SECRET_KEY=...
XUI_USERNAME=...
XUI_PASSWORD=...
```

Локальный запуск:

```bash
.venv/bin/python bot.py
```

## Продакшен на VPS

Скопируй проект на сервер, например в `/root/vpnbot`, затем:

```bash
cd /root/vpnbot
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp vpnbot.service /etc/systemd/system/vpnbot.service
systemctl daemon-reload
systemctl enable --now vpnbot
```

Логи:

```bash
journalctl -u vpnbot -f
```

Перезапуск:

```bash
systemctl restart vpnbot
```

## Важно

После того как доступ от 3x-ui был отправлен в чат, пароль панели лучше сменить и обновить `XUI_PASSWORD` в `.env`.
