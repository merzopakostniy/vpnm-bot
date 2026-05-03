import asyncio
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html import escape
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, quote, urlsplit

import requests
import httpx
from aiohttp import web
from aiogram import Bot, Dispatcher, F, Router, types
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.types import BotCommand, BufferedInputFile, InlineKeyboardButton, InlineKeyboardMarkup
from dotenv import load_dotenv
from yookassa import Configuration, Payment


load_dotenv(override=True)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
YOOKASSA_SHOP_ID = os.getenv("YOOKASSA_SHOP_ID", "").strip()
YOOKASSA_SECRET_KEY = os.getenv("YOOKASSA_SECRET_KEY", "").strip()
PAYMENT_RETURN_URL = os.getenv("PAYMENT_RETURN_URL", "https://t.me/").strip()

XUI_BASE_URL = os.getenv("XUI_BASE_URL", "").strip().rstrip("/")
XUI_USERNAME = os.getenv("XUI_USERNAME", "").strip()
XUI_PASSWORD = os.getenv("XUI_PASSWORD", "").strip()
XUI_INBOUND_ID = int(os.getenv("XUI_INBOUND_ID", "1") or "1")
XUI_HOST = os.getenv("XUI_HOST", "").strip()
XUI_PORT = int(os.getenv("XUI_PORT", "443") or "443")
XUI_VERIFY_SSL = os.getenv("XUI_VERIFY_SSL", "false").lower() in {"1", "true", "yes", "on"}

SERVICE_NAME = os.getenv("SERVICE_NAME", "VPN").strip() or "VPN"
SUPPORT_USERNAME = os.getenv("SUPPORT_USERNAME", "").strip().lstrip("@")
DEVICE_LIMIT = int(os.getenv("DEVICE_LIMIT", "2") or "2")
DNS_FILTER_ENABLED = os.getenv("DNS_FILTER_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
DNS_FILTER_SERVERS = [
    value.strip()
    for value in os.getenv("DNS_FILTER_SERVERS", "94.140.14.14,94.140.15.15").split(",")
    if value.strip()
]
HAPP_FULL_DIRECT_LIST = os.getenv("HAPP_FULL_DIRECT_LIST", "false").lower() in {
    "1",
    "true",
    "yes",
    "on",
}
def parse_telegram_ids(raw_value: str) -> set:
    return {
        int(value)
        for value in raw_value.replace(" ", "").split(",")
        if value.isdigit()
    }


ADMIN_TELEGRAM_IDS = parse_telegram_ids(os.getenv("ADMIN_TELEGRAM_IDS", ""))
SUPPORT_TELEGRAM_IDS = parse_telegram_ids(os.getenv("SUPPORT_TELEGRAM_IDS", "")) or ADMIN_TELEGRAM_IDS
ADMIN_TEST_DAYS = int(os.getenv("ADMIN_TEST_DAYS", "30") or "30")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
TGDASH_ENABLED = os.getenv("TGDASH_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
TGDASH_URL = os.getenv("TGDASH_URL", "").strip()
TGDASH_KEY = os.getenv("TGDASH_KEY", "").strip()
PROFILE_PUBLIC_BASE_URL = os.getenv("PROFILE_PUBLIC_BASE_URL", "").strip().rstrip("/")
PROFILE_LISTEN_HOST = os.getenv("PROFILE_LISTEN_HOST", "127.0.0.1").strip() or "127.0.0.1"
PROFILE_LISTEN_PORT = int(os.getenv("PROFILE_LISTEN_PORT", "8091") or "8091")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "payments.db")
HAPP_DIRECT_DOMAINS_PATH = os.path.join(BASE_DIR, "assets", "happ_direct_domains.txt")

TARIFFS = {
    "month": {"title": "1 месяц", "price": 200, "days": 30},
    "three_months": {"title": "3 месяца", "price": 549, "days": 90},
    "year": {"title": "12 месяцев", "price": 1990, "days": 365},
}

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("vpn-bot")

Configuration.account_id = YOOKASSA_SHOP_ID
Configuration.secret_key = YOOKASSA_SECRET_KEY

router = Router()
PAID_STATUSES = {"paid", "admin_issued"}
ISSUING_STATUSES = {"issuing", "admin_creating"}
FAILED_STATUSES = {"paid_issue_failed", "admin_issue_failed"}
admin_reply_state: Dict[int, int] = {}


async def track_event(event: str, user_id: int, **kwargs: Any) -> None:
    if not TGDASH_ENABLED or not TGDASH_URL or not TGDASH_KEY:
        return
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            response = await client.post(
                TGDASH_URL,
                headers={"X-API-Key": TGDASH_KEY},
                json={"event": event, "user_id": user_id, **kwargs},
            )
        logger.info(
            "TgDash event=%s user_id=%s status=%s body=%s",
            event,
            user_id,
            response.status_code,
            response.text[:200],
        )
    except Exception:
        logger.warning("TgDash track failed: event=%s user_id=%s", event, user_id, exc_info=True)


def user_payload(user: types.User) -> Dict[str, Any]:
    return {
        "username": user.username,
        "first_name": user.first_name,
        "last_name": user.last_name,
    }


@dataclass
class XuiClient:
    email: str
    uuid: str
    sub_id: str
    expires_at: datetime
    vless_link: str


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ms_from_dt(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def dedupe_keep_order(values: List[str]) -> List[str]:
    result = []
    seen = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def load_happ_direct_domains() -> List[str]:
    built_in = [
        "geosite:category-ru",
        "geosite:apple",
        "geosite:microsoft",
        "geosite:android",
        "domain:yandex.ru",
        "domain:ya.ru",
        "domain:vk.com",
        "domain:vk.ru",
        "domain:ok.ru",
        "domain:mail.ru",
        "domain:rutube.ru",
        "domain:gosuslugi.ru",
        "domain:mos.ru",
        "domain:sberbank.ru",
        "domain:sber.ru",
        "domain:tbank.ru",
        "domain:tinkoff.ru",
        "domain:alfabank.ru",
        "domain:vtb.ru",
        "domain:ozon.ru",
        "domain:wildberries.ru",
        "domain:avito.ru",
        "domain:2gis.ru",
    ]
    domains = list(built_in)
    if not HAPP_FULL_DIRECT_LIST:
        return dedupe_keep_order(domains)
    if os.path.exists(HAPP_DIRECT_DOMAINS_PATH):
        with open(HAPP_DIRECT_DOMAINS_PATH, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if not line.startswith(("domain:", "geosite:", "regexp:", "full:")):
                    line = f"domain:{line}"
                domains.append(line)
    return dedupe_keep_order(domains)


HAPP_DIRECT_DOMAINS = load_happ_direct_domains()


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                tg_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tg_id INTEGER NOT NULL,
                tariff_key TEXT NOT NULL,
                amount_rub INTEGER NOT NULL,
                days INTEGER NOT NULL,
                status TEXT NOT NULL,
                payment_id TEXT UNIQUE,
                xui_inbound_id INTEGER,
                xui_email TEXT,
                xui_uuid TEXT,
                xui_sub_id TEXT,
                vless_link TEXT,
                paid_at TEXT,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS support_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                closed_at TEXT
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS support_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                sender_role TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        db.commit()


def upsert_user(user: types.User) -> None:
    now = utc_now().isoformat()
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """
            INSERT INTO users (tg_id, username, first_name, last_name, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(tg_id) DO UPDATE SET
                username = excluded.username,
                first_name = excluded.first_name,
                last_name = excluded.last_name,
                updated_at = excluded.updated_at
            """,
            (user.id, user.username, user.first_name, user.last_name, now, now),
        )
        db.commit()


def support_keyboard(ticket_id: int, *, for_admin: bool) -> InlineKeyboardMarkup:
    if for_admin:
        rows = [
            [
                InlineKeyboardButton(text="✍️ Ответить", callback_data=f"ticket_reply:{ticket_id}"),
                InlineKeyboardButton(text="✅ Закрыть", callback_data=f"ticket_close:{ticket_id}"),
            ],
        ]
    else:
        rows = [[InlineKeyboardButton(text="✅ Закрыть обращение", callback_data=f"ticket_user_close:{ticket_id}")]]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def support_entry_keyboard(active_ticket_id: Optional[int] = None) -> InlineKeyboardMarkup:
    rows = []
    if active_ticket_id:
        rows.append([InlineKeyboardButton(text="✍️ Написать в обращение", callback_data=f"ticket_continue:{active_ticket_id}")])
        rows.append([InlineKeyboardButton(text="✅ Закрыть обращение", callback_data=f"ticket_user_close:{active_ticket_id}")])
    else:
        rows.append([InlineKeyboardButton(text="🆕 Создать обращение", callback_data="ticket_new")])
    rows.append([InlineKeyboardButton(text="← Назад", callback_data="back")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def support_user_label(row: Dict[str, Any]) -> str:
    username = row.get("username")
    name = " ".join(value for value in [row.get("first_name"), row.get("last_name")] if value)
    parts = []
    if name:
        parts.append(escape(name))
    if username:
        parts.append(f"@{escape(username)}")
    parts.append(f"<code>{row['user_id']}</code>")
    return " / ".join(parts)


def get_open_support_ticket(user_id: int) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            """
            SELECT * FROM support_tickets
            WHERE user_id = ? AND status = 'open'
            ORDER BY id DESC
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()
    return dict(row) if row else None


def get_support_ticket(ticket_id: int) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            """
            SELECT t.*, u.username, u.first_name, u.last_name
            FROM support_tickets t
            LEFT JOIN users u ON u.tg_id = t.user_id
            WHERE t.id = ?
            """,
            (ticket_id,),
        ).fetchone()
    return dict(row) if row else None


def create_support_ticket(user: types.User) -> int:
    upsert_user(user)
    now = utc_now().isoformat()
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.execute(
            """
            INSERT INTO support_tickets (user_id, status, created_at, updated_at)
            VALUES (?, 'open', ?, ?)
            """,
            (user.id, now, now),
        )
        db.commit()
        return int(cursor.lastrowid)


def add_support_message(ticket_id: int, sender_id: int, sender_role: str, text: str) -> None:
    now = utc_now().isoformat()
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """
            INSERT INTO support_messages (ticket_id, sender_id, sender_role, text, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (ticket_id, sender_id, sender_role, text, now),
        )
        db.execute(
            "UPDATE support_tickets SET updated_at = ? WHERE id = ?",
            (now, ticket_id),
        )
        db.commit()


def close_support_ticket(ticket_id: int) -> None:
    now = utc_now().isoformat()
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """
            UPDATE support_tickets
            SET status = 'closed', closed_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (now, now, ticket_id),
        )
        db.commit()


def support_message_body(message: types.Message) -> str:
    if message.text:
        return message.text
    if message.caption:
        return f"[{message.content_type}] {message.caption}"
    return f"[{message.content_type}]"


def main_keyboard(user_id: Optional[int] = None) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text="🚀 Купить VPN-доступ", callback_data="buy")],
        [InlineKeyboardButton(text="🔑 Мои ключи", callback_data="my_keys")],
        [InlineKeyboardButton(text="💬 Помощь и поддержка", callback_data="support")],
    ]
    if user_id in ADMIN_TELEGRAM_IDS:
        rows.append([InlineKeyboardButton(text="🧪 Выдать тестовый ключ", callback_data="admin_test_key")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def start_text() -> str:
    return (
        f"🚀 <b>{escape(SERVICE_NAME)}</b>\n"
        "Персональный VPN-доступ без ручной возни с настройками.\n\n"
        "Внутри:\n"
        f"🔑 <b>1 ключ на {DEVICE_LIMIT} устройства</b>\n"
        "⚡ VLESS Reality для стабильного подключения\n"
        "🧹 DNS-фильтр рекламы и трекеров\n"
        "📲 Отдельный JSON-профиль для Happ + ссылка для других клиентов\n"
        "🕒 Автоматический срок действия после оплаты\n\n"
        "Выберите действие:"
    )


def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_TELEGRAM_IDS


def is_support(user_id: int) -> bool:
    return user_id in SUPPORT_TELEGRAM_IDS


def format_date(value: str) -> str:
    return datetime.fromisoformat(value).strftime("%d.%m.%Y")


def order_tariff_title(row: Dict[str, Any]) -> str:
    tariff = TARIFFS.get(row["tariff_key"])
    if tariff:
        return f"{tariff['title']} ({row['days']} дней)"
    if row["tariff_key"] == "admin_test":
        return f"Тестовый доступ ({row['days']} дней)"
    return f"{row['days']} дней"


def key_text(title: str, client: XuiClient, tariff: Optional[Dict[str, Any]] = None) -> str:
    expires_text = client.expires_at.strftime("%d.%m.%Y")
    tariff_text = ""
    if tariff:
        tariff_text = f"Тариф: <b>{escape(tariff['title'])}</b> / <b>{tariff['days']} дней</b>\n"
    return (
        f"✅ <b>{escape(title)}</b>\n\n"
        f"{tariff_text}"
        f"Доступ активен до <b>{expires_text}</b>\n"
        f"Можно использовать на <b>{DEVICE_LIMIT} устройствах</b>.\n\n"
        "Ниже я отправлю профиль для Happ. Его нужно открыть в приложении и нажать подключение.\n\n"
        "Для других VPN-клиентов используйте кнопку с ручной ссылкой."
    )


def stored_key_text(row: Dict[str, Any]) -> str:
    return (
        f"Тариф: <b>{escape(order_tariff_title(row))}</b>\n"
        f"До <b>{format_date(row['expires_at'])}</b>\n"
        f"Устройства: <b>{DEVICE_LIMIT}</b>\n"
        f"<code>{escape(row['vless_link'])}</code>"
    )


def vless_user_id(parsed) -> str:
    if parsed.username:
        return parsed.username
    if "@" in parsed.netloc:
        return parsed.netloc.rsplit("@", 1)[0]
    return ""


def vless_port(parsed, default: int = 443) -> int:
    try:
        return parsed.port or default
    except ValueError:
        return default


def vless_link_to_outbound(tag: str, link: str) -> Optional[Dict[str, Any]]:
    if not link or not link.startswith("vless://"):
        return None

    parsed = urlsplit(link)
    user_id = vless_user_id(parsed)
    address = parsed.hostname or ""
    if not user_id or not address:
        return None

    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    network = query.get("type") or "tcp"
    security = query.get("security") or "none"

    user = {
        "id": user_id,
        "encryption": query.get("encryption") or "none",
    }
    if query.get("flow"):
        user["flow"] = query["flow"]

    outbound = {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": vless_port(parsed),
                    "users": [user],
                }
            ],
        },
        "streamSettings": {
            "network": network,
            "security": security,
        },
    }
    stream = outbound["streamSettings"]

    if security == "reality":
        reality = {
            "fingerprint": query.get("fp") or "chrome",
            "serverName": query.get("sni") or address,
            "publicKey": query.get("pbk") or "",
            "shortId": query.get("sid") or "",
            "spiderX": query.get("spx") or "/",
        }
        stream["realitySettings"] = {key: value for key, value in reality.items() if value}
    elif security == "tls":
        tls = {
            "serverName": query.get("sni") or query.get("host") or address,
            "fingerprint": query.get("fp") or "chrome",
        }
        if query.get("alpn"):
            tls["alpn"] = [item.strip() for item in query["alpn"].split(",") if item.strip()]
        stream["tlsSettings"] = tls

    if network == "tcp":
        stream["tcpSettings"] = {"header": {"type": "none"}}
    elif network == "grpc":
        grpc = {}
        if query.get("serviceName"):
            grpc["serviceName"] = query["serviceName"]
        if query.get("authority"):
            grpc["authority"] = query["authority"]
        stream["grpcSettings"] = grpc
    elif network == "ws":
        ws = {"path": query.get("path") or "/"}
        host_header = query.get("host") or query.get("authority")
        if host_header:
            ws["headers"] = {"Host": host_header}
        stream["wsSettings"] = ws

    return outbound


def build_happ_json_profile(vless_link: str, remarks: str) -> Optional[Dict[str, Any]]:
    proxy = vless_link_to_outbound("proxy", vless_link)
    if not proxy:
        return None

    sniff = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False}
    rules = [
        {
            "type": "field",
            "protocol": ["bittorrent"],
            "outboundTag": "block",
        },
        {
            "type": "field",
            "domain": [
                "domain:mtalk.google.com",
                "domain:push.apple.com",
                "domain:api.push.apple.com",
                "domain:push-apple.com.akadns.net",
                "regexp:.*-courier\\.push\\.apple\\.com$",
            ],
            "outboundTag": "direct",
        },
        {
            "type": "field",
            "ip": [
                "geoip:private",
                "10.0.0.0/8",
                "100.64.0.0/10",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "224.0.0.0/4",
                "255.255.255.255",
            ],
            "outboundTag": "direct",
        },
    ]
    if HAPP_DIRECT_DOMAINS:
        rules.append(
            {
                "type": "field",
                "domain": HAPP_DIRECT_DOMAINS,
                "outboundTag": "direct",
            }
        )
    rules.append(
        {
            "type": "field",
            "network": "tcp,udp",
            "outboundTag": "proxy",
        }
    )

    dns_servers = DNS_FILTER_SERVERS if DNS_FILTER_ENABLED and DNS_FILTER_SERVERS else [
        "1.1.1.1",
        "1.0.0.1",
    ]

    return {
        "remarks": remarks,
        "log": {"loglevel": "warning", "dnsLog": False},
        "dns": {
            "queryStrategy": "UseIP",
            "servers": dns_servers,
        },
        "inbounds": [
            {
                "tag": "socks",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": sniff,
            },
            {
                "tag": "http",
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {"allowTransparent": False},
                "sniffing": sniff,
            },
        ],
        "outbounds": [
            proxy,
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {
            "domainMatcher": "hybrid",
            "domainStrategy": "IPIfNonMatch",
            "rules": rules,
        },
        "meta": {
            "serverDescription": "VLESS Reality | Happ JSON | RU direct routing | DNS filter",
        },
    }


def happ_json_file(vless_link: str, name: str) -> Optional[BufferedInputFile]:
    profile = build_happ_json_profile(vless_link, f"{SERVICE_NAME} | Happ")
    if not profile:
        return None
    payload = json.dumps(profile, ensure_ascii=False, indent=2).encode("utf-8")
    safe_name = "".join(char if char.isalnum() or char in {"_", "-"} else "_" for char in name)
    filename = f"{safe_name[:40] or 'vpn'}_happ.json"
    return BufferedInputFile(payload, filename=filename)


def profile_secret() -> str:
    return "|".join([BOT_TOKEN, YOOKASSA_SECRET_KEY, XUI_PASSWORD])


def happ_profile_token(order_id: int, tg_id: int, xui_uuid: str) -> str:
    payload = f"happ:{order_id}:{tg_id}:{xui_uuid}".encode("utf-8")
    return hmac.new(profile_secret().encode("utf-8"), payload, hashlib.sha256).hexdigest()[:32]


def happ_profile_url(order_id: int, tg_id: int, xui_uuid: str) -> str:
    if not PROFILE_PUBLIC_BASE_URL:
        return ""
    token = happ_profile_token(order_id, tg_id, xui_uuid)
    return f"{PROFILE_PUBLIC_BASE_URL}/happ/{order_id}/{token}.json"


def tariffs_keyboard() -> InlineKeyboardMarkup:
    rows = []
    for key, tariff in TARIFFS.items():
        per_month = max(1, round(tariff["price"] / max(1, tariff["days"] / 30)))
        rows.append(
            [
                InlineKeyboardButton(
                    text=f"💳 {tariff['title']} — {tariff['price']} ₽ (~{per_month} ₽/мес)",
                    callback_data=f"tariff:{key}",
                )
            ]
        )
    rows.append([InlineKeyboardButton(text="← Назад", callback_data="back")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def payment_keyboard(payment_url: str, order_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="💳 Перейти к оплате", url=payment_url)],
            [InlineKeyboardButton(text="✅ Проверить оплату и выдать ключ", callback_data=f"check:{order_id}")],
            [InlineKeyboardButton(text="← Назад к тарифам", callback_data="buy")],
        ]
    )


def issued_key_keyboard(order_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Показать ручную ссылку", callback_data=f"show_vless:{order_id}")],
            [InlineKeyboardButton(text="🔑 Мои ключи", callback_data="my_keys")],
        ]
    )


def save_order(tg_id: int, tariff_key: str, payment_id: str) -> int:
    tariff = TARIFFS[tariff_key]
    now = utc_now().isoformat()
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.execute(
            """
            INSERT INTO orders (
                tg_id, tariff_key, amount_rub, days, status, payment_id,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)
            """,
            (tg_id, tariff_key, tariff["price"], tariff["days"], payment_id, now, now),
        )
        db.commit()
        return int(cursor.lastrowid)


def save_admin_order(tg_id: int, days: int) -> int:
    now = utc_now().isoformat()
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.execute(
            """
            INSERT INTO orders (
                tg_id, tariff_key, amount_rub, days, status, payment_id,
                created_at, updated_at
            )
            VALUES (?, 'admin_test', 0, ?, 'admin_creating', ?, ?, ?)
            """,
            (tg_id, days, f"admin-{tg_id}-{uuid.uuid4().hex}", now, now),
        )
        db.commit()
        return int(cursor.lastrowid)


def get_order(order_id: int) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        return dict(row) if row else None


def get_order_for_happ_profile(order_id: int) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            """
            SELECT * FROM orders
            WHERE id = ?
              AND status IN ('paid', 'admin_issued')
              AND expires_at > ?
              AND vless_link IS NOT NULL
            """,
            (order_id, utc_now().isoformat()),
        ).fetchone()
        return dict(row) if row else None


def get_active_orders(tg_id: int) -> List[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """
            SELECT * FROM orders
            WHERE tg_id = ? AND status IN ('paid', 'admin_issued') AND expires_at > ?
            ORDER BY expires_at DESC
            """,
            (tg_id, utc_now().isoformat()),
        ).fetchall()
        return [dict(row) for row in rows]


def order_stats() -> Dict[str, int]:
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            "SELECT status, COUNT(*) AS count FROM orders GROUP BY status"
        ).fetchall()
        stats = {row["status"]: int(row["count"]) for row in rows}
        stats["users"] = int(db.execute("SELECT COUNT(*) FROM users").fetchone()[0])
        stats["active"] = int(
            db.execute(
                """
                SELECT COUNT(*) FROM orders
                WHERE status IN ('paid', 'admin_issued') AND expires_at > ?
                """,
                (utc_now().isoformat(),),
            ).fetchone()[0]
        )
        return stats


def mark_paid(order_id: int, client: XuiClient) -> None:
    mark_order_issued(order_id, client, "paid")


def mark_order_issued(order_id: int, client: XuiClient, status: str) -> None:
    now = utc_now().isoformat()
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """
            UPDATE orders
            SET status = ?,
                xui_inbound_id = ?,
                xui_email = ?,
                xui_uuid = ?,
                xui_sub_id = ?,
                vless_link = ?,
                paid_at = ?,
                expires_at = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                status,
                XUI_INBOUND_ID,
                client.email,
                client.uuid,
                client.sub_id,
                client.vless_link,
                now,
                client.expires_at.isoformat(),
                now,
                order_id,
            ),
        )
        db.commit()


def set_order_status(order_id: int, status: str) -> None:
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            "UPDATE orders SET status = ?, updated_at = ? WHERE id = ?",
            (status, utc_now().isoformat(), order_id),
        )
        db.commit()


def try_set_order_status(order_id: int, from_statuses: set, to_status: str) -> bool:
    placeholders = ",".join("?" for _ in from_statuses)
    params = [to_status, utc_now().isoformat(), order_id, *from_statuses]
    with sqlite3.connect(DB_PATH) as db:
        cursor = db.execute(
            f"""
            UPDATE orders
            SET status = ?, updated_at = ?
            WHERE id = ? AND status IN ({placeholders})
            """,
            params,
        )
        db.commit()
        return cursor.rowcount == 1


async def create_payment(tariff_key: str, user: types.User) -> Payment:
    tariff = TARIFFS[tariff_key]
    description = f"{SERVICE_NAME}: {tariff['title']} для Telegram ID {user.id}"
    return await asyncio.to_thread(
        Payment.create,
        {
            "amount": {"value": f"{tariff['price']}.00", "currency": "RUB"},
            "confirmation": {"type": "redirect", "return_url": PAYMENT_RETURN_URL},
            "capture": True,
            "description": description[:128],
            "metadata": {
                "tg_id": str(user.id),
                "username": user.username or "",
                "tariff": tariff_key,
            },
        },
        str(uuid.uuid4()),
    )


async def get_payment(payment_id: str) -> Payment:
    return await asyncio.to_thread(Payment.find_one, payment_id)


async def send_happ_profile(
    message: types.Message,
    vless_link: str,
    name: str,
    order_id: Optional[int] = None,
    tg_id: Optional[int] = None,
    xui_uuid: str = "",
) -> None:
    if order_id and tg_id and xui_uuid:
        url = happ_profile_url(order_id, tg_id, xui_uuid)
        if url:
            await message.answer(
                "<b>Профиль Happ</b>\n\n"
                "Откройте эту ссылку в Happ или вставьте ее в импорт по URL:\n"
                f"<code>{escape(url)}</code>\n\n"
                "Профиль уже содержит маршрутизацию и DNS-фильтр.",
                parse_mode="HTML",
            )
            return

    document = happ_json_file(vless_link, name)
    if not document:
        return
    await message.answer_document(
        document,
        caption=(
            "<b>Профиль Happ</b>\n\n"
            "Откройте файл в Happ и подключите профиль.\n\n"
            "Внутри уже настроены маршрутизация российских сервисов напрямую "
            "и DNS-фильтр рекламы/трекеров."
        ),
        parse_mode="HTML",
    )


class XuiApi:
    def __init__(self) -> None:
        self.session = requests.Session()
        self.logged_in = False

    async def close(self) -> None:
        self.session.close()

    async def login(self) -> None:
        data = await asyncio.to_thread(self._login_sync)
        if not data.get("success"):
            raise RuntimeError(f"3x-ui login failed: {data}")
        self.logged_in = True

    def _login_sync(self) -> Dict[str, Any]:
        response = self.session.post(
            f"{XUI_BASE_URL}/login",
            data={"username": XUI_USERNAME, "password": XUI_PASSWORD},
            verify=XUI_VERIFY_SSL,
            timeout=20,
        )
        text = response.text
        try:
            return response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"3x-ui login returned non-JSON: status={response.status_code}, body={text[:300]}"
            ) from exc

    async def request(self, method: str, path: str, **kwargs: Any) -> Dict[str, Any]:
        if not self.logged_in:
            await self.login()

        data = await asyncio.to_thread(self._request_once_sync, method, path, kwargs)
        if not isinstance(data, dict) or (
            data.get("success") is False and "login" in str(data).lower()
        ):
            self.logged_in = False
            await self.login()
            data = await asyncio.to_thread(self._request_once_sync, method, path, kwargs)
        if not isinstance(data, dict):
            raise RuntimeError(f"3x-ui returned unexpected response for {path}: {data!r}")
        return data

    def _request_once_sync(self, method: str, path: str, kwargs: Dict[str, Any]) -> Any:
        response = self.session.request(
            method,
            f"{XUI_BASE_URL}{path}",
            verify=XUI_VERIFY_SSL,
            timeout=20,
            **kwargs,
        )
        text = response.text
        if not text.strip():
            raise RuntimeError(
                f"3x-ui returned empty response for {path}: status={response.status_code}"
            )
        try:
            return response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"3x-ui returned non-JSON for {path}: status={response.status_code}, body={text[:300]}"
            ) from exc

    async def get_inbound(self, inbound_id: int) -> Dict[str, Any]:
        data = await self.request("GET", f"/panel/api/inbounds/get/{inbound_id}")
        if not data.get("success"):
            raise RuntimeError(f"Cannot get inbound {inbound_id}: {data}")
        return data["obj"]

    async def add_client(self, user: types.User, days: int) -> XuiClient:
        inbound = await self.get_inbound(XUI_INBOUND_ID)
        stream = json.loads(inbound["streamSettings"])
        reality = stream["realitySettings"]
        public_key = reality["settings"]["publicKey"]
        fingerprint = reality["settings"].get("fingerprint", "chrome")
        spider_x = reality["settings"].get("spiderX", "/")
        server_names = reality.get("serverNames") or ["www.nvidia.com"]
        sni = server_names[0]
        short_ids = reality.get("shortIds") or [""]
        short_id = short_ids[0]

        client_uuid = str(uuid.uuid4())
        sub_id = uuid.uuid4().hex[:16]
        safe_username = "".join(
            char if char.isalnum() or char in {"_", "-"} else "_"
            for char in (user.username or "nouser").replace("@", "")
        )[:24]
        email = f"tg_{user.id}_{safe_username}_{uuid.uuid4().hex[:6]}"
        expires_at = utc_now() + timedelta(days=days)

        client = {
            "id": client_uuid,
            "flow": "xtls-rprx-vision",
            "email": email,
            "limitIp": DEVICE_LIMIT,
            "totalGB": 0,
            "expiryTime": ms_from_dt(expires_at),
            "enable": True,
            "tgId": str(user.id),
            "subId": sub_id,
            "comment": user.username or user.full_name,
            "reset": 0,
        }
        payload = {
            "id": XUI_INBOUND_ID,
            "settings": json.dumps({"clients": [client]}, ensure_ascii=False),
        }
        data = await self.request(
            "POST",
            "/panel/api/inbounds/addClient",
            json=payload,
        )
        if not data.get("success"):
            raise RuntimeError(f"Cannot add 3x-ui client: {data}")

        host = XUI_HOST or XUI_BASE_URL.split("://", 1)[-1].split(":", 1)[0].split("/", 1)[0]
        params = {
            "type": "tcp",
            "encryption": "none",
            "security": "reality",
            "pbk": public_key,
            "fp": fingerprint,
            "sni": sni,
            "sid": short_id,
            "spx": spider_x,
            "flow": "xtls-rprx-vision",
        }
        query = "&".join(f"{key}={quote(str(value), safe='')}" for key, value in params.items())
        vless_link = f"vless://{client_uuid}@{host}:{XUI_PORT}?{query}#{quote(email)}"
        return XuiClient(
            email=email,
            uuid=client_uuid,
            sub_id=sub_id,
            expires_at=expires_at,
            vless_link=vless_link,
        )


xui: Optional[XuiApi] = None


@router.message(CommandStart())
async def start(message: types.Message) -> None:
    upsert_user(message.from_user)
    await track_event("start", message.from_user.id, **user_payload(message.from_user))
    await track_event(
        "command",
        message.from_user.id,
        data={"command": "start"},
        **user_payload(message.from_user),
    )
    await message.answer(
        start_text(),
        reply_markup=main_keyboard(message.from_user.id),
        parse_mode="HTML",
    )


@router.message(Command("id"))
async def show_id(message: types.Message) -> None:
    await message.answer(f"Ваш Telegram ID: <code>{message.from_user.id}</code>", parse_mode="HTML")


@router.message(Command("buy"))
async def buy_command(message: types.Message) -> None:
    upsert_user(message.from_user)
    await track_event("buy_opened", message.from_user.id, **user_payload(message.from_user))
    await message.answer(
        "💳 <b>Выберите тариф</b>\n\n"
        f"Каждый тариф включает 1 VPN-ключ на <b>{DEVICE_LIMIT} устройства</b>. "
        "Ключ создается автоматически после оплаты.",
        reply_markup=tariffs_keyboard(),
        parse_mode="HTML",
    )


@router.message(Command("keys"))
async def keys_command(message: types.Message) -> None:
    await track_event("my_keys_opened", message.from_user.id, **user_payload(message.from_user))
    rows = get_active_orders(message.from_user.id)
    if not rows:
        await message.answer(
            "🔑 <b>Активных ключей пока нет</b>\n\n"
            "Купите доступ или, если вы админ, выдайте тестовый ключ.",
            reply_markup=main_keyboard(message.from_user.id),
            parse_mode="HTML",
        )
        return

    text_parts = ["🔑 <b>Ваши активные ключи</b>"]
    for row in rows:
        text_parts.append("\n" + stored_key_text(row))
    await message.answer("\n".join(text_parts), parse_mode="HTML")
    for row in rows:
        await send_happ_profile(
            message,
            row["vless_link"],
            row.get("xui_email") or "vpn",
            order_id=row["id"],
            tg_id=row["tg_id"],
            xui_uuid=row.get("xui_uuid") or "",
        )


@router.message(Command("support"))
async def support_command(message: types.Message) -> None:
    await track_event("support_opened", message.from_user.id, **user_payload(message.from_user))
    active_ticket = get_open_support_ticket(message.from_user.id)
    await message.answer(
        "💬 <b>Поддержка</b>\n\n"
        "Создайте обращение и напишите вопрос прямо сюда. Администратор ответит вам в этом чате.\n\n"
        f"Ваш Telegram ID: <code>{message.from_user.id}</code>",
        reply_markup=support_entry_keyboard(active_ticket["id"] if active_ticket else None),
        parse_mode="HTML",
    )


@router.message(Command("help"))
async def help_command(message: types.Message) -> None:
    support = f"@{SUPPORT_USERNAME}" if SUPPORT_USERNAME else "через администратора сервиса"
    await message.answer(
        "Команды:\n"
        "/start - главное меню\n"
        "/buy - купить доступ\n"
        "/keys - мои ключи\n"
        "/support - поддержка\n"
        "/id - ваш Telegram ID\n"
        "/help - помощь\n\n"
        f"Поддержка: {support}"
    )


@router.message(Command("admin"))
async def admin_command(message: types.Message) -> None:
    if not is_admin(message.from_user.id):
        await message.answer("Команда недоступна.")
        return

    stats = order_stats()
    lines = [
        f"<b>{escape(SERVICE_NAME)} admin</b>",
        f"Пользователей: <b>{stats.get('users', 0)}</b>",
        f"Активных ключей: <b>{stats.get('active', 0)}</b>",
        "",
        "Заказы по статусам:",
    ]
    for status, count in sorted(stats.items()):
        if status in {"users", "active"}:
            continue
        lines.append(f"{escape(status)}: <b>{count}</b>")
    await message.answer("\n".join(lines), parse_mode="HTML")


@router.callback_query(F.data == "back")
async def back(callback: types.CallbackQuery) -> None:
    await callback.message.edit_text(
        start_text(),
        reply_markup=main_keyboard(callback.from_user.id),
        parse_mode="HTML",
    )
    await callback.answer()


@router.callback_query(F.data == "buy")
async def buy(callback: types.CallbackQuery) -> None:
    upsert_user(callback.from_user)
    await track_event("buy_opened", callback.from_user.id, **user_payload(callback.from_user))
    await callback.message.edit_text(
        "💳 <b>Выберите тариф</b>\n\n"
        f"Каждый тариф включает 1 VPN-ключ на <b>{DEVICE_LIMIT} устройства</b>. "
        "Ключ создается автоматически после оплаты.",
        reply_markup=tariffs_keyboard(),
        parse_mode="HTML",
    )
    await callback.answer()


@router.callback_query(F.data.startswith("tariff:"))
async def choose_tariff(callback: types.CallbackQuery) -> None:
    tariff_key = callback.data.split(":", 1)[1]
    if tariff_key not in TARIFFS:
        await callback.answer("Тариф не найден", show_alert=True)
        return

    await track_event(
        "tariff_selected",
        callback.from_user.id,
        tariff=tariff_key,
        **user_payload(callback.from_user),
    )
    try:
        payment = await create_payment(tariff_key, callback.from_user)
    except Exception:
        logger.exception("Cannot create payment for user %s tariff %s", callback.from_user.id, tariff_key)
        await callback.answer("Не удалось создать платеж. Попробуйте позже.", show_alert=True)
        return

    order_id = save_order(callback.from_user.id, tariff_key, payment.id)
    await track_event(
        "payment_created",
        callback.from_user.id,
        order_id=order_id,
        payment_id=payment.id,
        tariff=tariff_key,
        amount=TARIFFS[tariff_key]["price"],
    )
    payment_url = payment.confirmation.confirmation_url
    tariff = TARIFFS[tariff_key]
    await callback.message.edit_text(
        f"💳 <b>{escape(tariff['title'])}</b>\n\n"
        f"Стоимость: <b>{tariff['price']} ₽</b>\n"
        f"Срок: <b>{tariff['days']} дней</b>\n"
        f"Устройства: <b>{DEVICE_LIMIT}</b>\n\n"
        "Нажмите «Перейти к оплате». После оплаты вернитесь сюда и нажмите "
        "«Проверить оплату и выдать ключ».",
        reply_markup=payment_keyboard(payment_url, order_id),
        parse_mode="HTML",
    )
    await callback.answer()


@router.callback_query(F.data.startswith("check:"))
async def check_payment(callback: types.CallbackQuery) -> None:
    global xui

    order_id = int(callback.data.split(":", 1)[1])
    order = get_order(order_id)
    if not order or order["tg_id"] != callback.from_user.id:
        await callback.answer("Заказ не найден", show_alert=True)
        return
    if order["status"] in PAID_STATUSES:
        await callback.message.answer(
            "✅ Этот заказ уже оплачен.\n\n"
            f"{stored_key_text(order)}",
            parse_mode="HTML",
        )
        await send_happ_profile(
            callback.message,
            order["vless_link"],
            order.get("xui_email") or "vpn",
            order_id=order["id"],
            tg_id=order["tg_id"],
            xui_uuid=order.get("xui_uuid") or "",
        )
        await callback.answer()
        return
    if order["status"] in ISSUING_STATUSES:
        await callback.answer("Ключ уже создается. Нажмите еще раз через пару секунд.", show_alert=True)
        return

    try:
        payment = await get_payment(order["payment_id"])
    except Exception:
        logger.exception("Cannot check payment for order %s", order_id)
        await callback.answer("Не удалось проверить оплату. Попробуйте позже.", show_alert=True)
        return

    if payment.status != "succeeded":
        if payment.status in {"canceled", "expired"}:
            set_order_status(order_id, payment.status)
        await callback.answer("Оплата пока не прошла", show_alert=True)
        return

    tariff = TARIFFS[order["tariff_key"]]
    await track_event(
        "payment_succeeded",
        callback.from_user.id,
        order_id=order_id,
        payment_id=order["payment_id"],
        tariff=order["tariff_key"],
        tariff_title=tariff["title"],
        days=tariff["days"],
        amount=order["amount_rub"],
    )
    await track_event(
        "purchase",
        callback.from_user.id,
        amount=order["amount_rub"],
        data={
            "currency": "RUB",
            "provider": "yookassa",
            "payment_id": order["payment_id"],
            "order_id": order_id,
            "tariff": order["tariff_key"],
            "tariff_title": tariff["title"],
            "days": tariff["days"],
        },
    )
    if not try_set_order_status(order_id, {"pending", *FAILED_STATUSES}, "issuing"):
        await callback.answer("Заказ уже обрабатывается. Проверьте «Мои ключи».", show_alert=True)
        return

    try:
        if xui is None:
            xui = XuiApi()
        client = await xui.add_client(callback.from_user, tariff["days"])
    except Exception:
        logger.exception("Failed to issue key for order %s", order_id)
        set_order_status(order_id, "paid_issue_failed")
        await callback.message.answer(
            "⚠️ Оплата прошла, но ключ не удалось создать автоматически.\n\n"
            "Заказ сохранен, напишите в поддержку — выдадим ключ вручную."
        )
        await callback.answer()
        return

    mark_paid(order_id, client)
    await track_event(
        "key_issued",
        callback.from_user.id,
        order_id=order_id,
        tariff=order["tariff_key"],
        xui_email=client.email,
        expires_at=client.expires_at.isoformat(),
    )
    await callback.message.answer(
        key_text("Оплата прошла, ключ готов", client, tariff),
        reply_markup=issued_key_keyboard(order_id),
        parse_mode="HTML",
    )
    await send_happ_profile(
        callback.message,
        client.vless_link,
        client.email,
        order_id=order_id,
        tg_id=callback.from_user.id,
        xui_uuid=client.uuid,
    )
    await notify_admins(
        callback.bot,
        f"Новая покупка: tg_id={callback.from_user.id}, tariff={order['tariff_key']}, order={order_id}",
    )
    await callback.answer()


@router.callback_query(F.data == "my_keys")
async def my_keys(callback: types.CallbackQuery) -> None:
    await track_event("my_keys_opened", callback.from_user.id, **user_payload(callback.from_user))
    rows = get_active_orders(callback.from_user.id)
    if not rows:
        await callback.answer()
        await callback.message.answer(
            "🔑 <b>Активных ключей пока нет</b>\n\n"
            "Купите доступ или, если вы админ, выдайте тестовый ключ.",
            reply_markup=main_keyboard(callback.from_user.id),
            parse_mode="HTML",
        )
        return

    text_parts = ["🔑 <b>Ваши активные ключи</b>"]
    for row in rows:
        text_parts.append("\n" + stored_key_text(row))
    await callback.message.answer("\n".join(text_parts), parse_mode="HTML")
    for row in rows:
        await send_happ_profile(
            callback.message,
            row["vless_link"],
            row.get("xui_email") or "vpn",
            order_id=row["id"],
            tg_id=row["tg_id"],
            xui_uuid=row.get("xui_uuid") or "",
        )
    await callback.answer()


@router.callback_query(F.data.startswith("show_vless:"))
async def show_vless(callback: types.CallbackQuery) -> None:
    order_id = int(callback.data.split(":", 1)[1])
    order = get_order(order_id)
    if not order or order["tg_id"] != callback.from_user.id or order["status"] not in PAID_STATUSES:
        await callback.answer("Ключ не найден", show_alert=True)
        return
    await callback.message.answer(
        "<b>Ручная ссылка</b>\n\n"
        "Для Streisand, v2rayN, Nekoray и других клиентов:\n"
        f"<code>{escape(order['vless_link'])}</code>",
        parse_mode="HTML",
    )
    await callback.answer()


@router.callback_query(F.data == "support")
async def support(callback: types.CallbackQuery) -> None:
    await track_event("support_opened", callback.from_user.id, **user_payload(callback.from_user))
    active_ticket = get_open_support_ticket(callback.from_user.id)
    await callback.message.answer(
        "💬 <b>Поддержка</b>\n\n"
        "Создайте обращение и напишите вопрос прямо сюда. Администратор ответит вам в этом чате.\n\n"
        f"Ваш Telegram ID: <code>{callback.from_user.id}</code>",
        reply_markup=support_entry_keyboard(active_ticket["id"] if active_ticket else None),
        parse_mode="HTML",
    )
    await callback.answer()


@router.callback_query(F.data == "ticket_new")
async def ticket_new(callback: types.CallbackQuery) -> None:
    active_ticket = get_open_support_ticket(callback.from_user.id)
    if active_ticket:
        await callback.message.answer(
            f"💬 У вас уже есть открытое обращение <b>#{active_ticket['id']}</b>.\n\n"
            "Напишите сообщение сюда, и я передам его администратору.",
            reply_markup=support_keyboard(active_ticket["id"], for_admin=False),
            parse_mode="HTML",
        )
        await callback.answer()
        return

    ticket_id = create_support_ticket(callback.from_user)
    ticket = get_support_ticket(ticket_id)
    await track_event("support_ticket_created", callback.from_user.id, ticket_id=ticket_id, **user_payload(callback.from_user))
    await callback.message.answer(
        f"💬 <b>Обращение #{ticket_id} создано</b>\n\n"
        "Опишите проблему одним сообщением: что не работает, какой клиент используете и на каком устройстве.",
        reply_markup=support_keyboard(ticket_id, for_admin=False),
        parse_mode="HTML",
    )
    if ticket:
        await notify_ticket_admins(
            callback.bot,
            ticket,
            f"🆕 <b>Новое обращение #{ticket_id}</b>\n\n"
            f"Пользователь: {support_user_label(ticket)}\n\n"
            "Пока без сообщения. Ждем текст от пользователя.",
        )
    await callback.answer("Обращение создано")


@router.callback_query(F.data.startswith("ticket_continue:"))
async def ticket_continue(callback: types.CallbackQuery) -> None:
    ticket_id = int(callback.data.split(":", 1)[1])
    ticket = get_support_ticket(ticket_id)
    if not ticket or ticket["user_id"] != callback.from_user.id or ticket["status"] != "open":
        await callback.answer("Обращение не найдено или уже закрыто", show_alert=True)
        return
    await callback.message.answer(
        f"💬 <b>Обращение #{ticket_id}</b>\n\n"
        "Напишите сообщение сюда, я передам его администратору.",
        reply_markup=support_keyboard(ticket_id, for_admin=False),
        parse_mode="HTML",
    )
    await callback.answer()


@router.callback_query(F.data.startswith("ticket_user_close:"))
async def ticket_user_close(callback: types.CallbackQuery) -> None:
    ticket_id = int(callback.data.split(":", 1)[1])
    ticket = get_support_ticket(ticket_id)
    if not ticket or ticket["user_id"] != callback.from_user.id:
        await callback.answer("Обращение не найдено", show_alert=True)
        return
    if ticket["status"] != "closed":
        close_support_ticket(ticket_id)
        await notify_ticket_admins(
            callback.bot,
            ticket,
            f"✅ <b>Обращение #{ticket_id} закрыто пользователем</b>\n\n"
            f"Пользователь: {support_user_label(ticket)}",
        )
    await track_event("support_ticket_closed_by_user", callback.from_user.id, ticket_id=ticket_id)
    await callback.message.answer(f"✅ Обращение <b>#{ticket_id}</b> закрыто.", parse_mode="HTML")
    await callback.answer()


@router.callback_query(F.data.startswith("ticket_reply:"))
async def ticket_reply(callback: types.CallbackQuery) -> None:
    if not is_support(callback.from_user.id):
        await callback.answer("Недоступно", show_alert=True)
        return

    ticket_id = int(callback.data.split(":", 1)[1])
    ticket = get_support_ticket(ticket_id)
    if not ticket or ticket["status"] != "open":
        await callback.answer("Обращение не найдено или закрыто", show_alert=True)
        return

    admin_reply_state[callback.from_user.id] = ticket_id
    await callback.message.answer(
        f"✍️ Ответ на обращение <b>#{ticket_id}</b>\n\n"
        "Напишите следующим сообщением текст ответа. Я отправлю его пользователю.",
        parse_mode="HTML",
    )
    await callback.answer()


@router.callback_query(F.data.startswith("ticket_close:"))
async def ticket_close(callback: types.CallbackQuery) -> None:
    if not is_support(callback.from_user.id):
        await callback.answer("Недоступно", show_alert=True)
        return

    ticket_id = int(callback.data.split(":", 1)[1])
    ticket = get_support_ticket(ticket_id)
    if not ticket:
        await callback.answer("Обращение не найдено", show_alert=True)
        return
    if ticket["status"] != "closed":
        close_support_ticket(ticket_id)
        admin_reply_state.pop(callback.from_user.id, None)
        await callback.bot.send_message(
            ticket["user_id"],
            f"✅ Обращение <b>#{ticket_id}</b> закрыто администратором.\n\n"
            "Если вопрос вернется, создайте новое обращение в поддержке.",
            parse_mode="HTML",
        )
    await track_event("support_ticket_closed_by_admin", callback.from_user.id, ticket_id=ticket_id)
    await callback.message.answer(f"✅ Обращение <b>#{ticket_id}</b> закрыто.", parse_mode="HTML")
    await callback.answer()


@router.callback_query(F.data == "admin_test_key")
async def admin_test_key(callback: types.CallbackQuery) -> None:
    global xui

    if not is_admin(callback.from_user.id):
        await callback.answer("Недоступно", show_alert=True)
        return

    await track_event("admin_test_key_requested", callback.from_user.id, **user_payload(callback.from_user))
    order_id = save_admin_order(callback.from_user.id, ADMIN_TEST_DAYS)
    try:
        if xui is None:
            xui = XuiApi()
        client = await xui.add_client(callback.from_user, ADMIN_TEST_DAYS)
    except Exception:
        logger.exception("Failed to issue admin test key for order %s", order_id)
        set_order_status(order_id, "admin_issue_failed")
        await callback.message.answer("Не удалось создать тестовый ключ. Проверьте логи бота.")
        await callback.answer()
        return

    mark_order_issued(order_id, client, "admin_issued")
    await track_event(
        "admin_test_key_issued",
        callback.from_user.id,
        order_id=order_id,
        xui_email=client.email,
        expires_at=client.expires_at.isoformat(),
    )
    await callback.message.answer(
        key_text("Тестовый ключ готов", client),
        reply_markup=issued_key_keyboard(order_id),
        parse_mode="HTML",
    )
    await send_happ_profile(
        callback.message,
        client.vless_link,
        client.email,
        order_id=order_id,
        tg_id=callback.from_user.id,
        xui_uuid=client.uuid,
    )
    await callback.answer()


@router.message(F.text)
async def support_message_router(message: types.Message) -> None:
    if not message.from_user or not message.text or message.text.startswith("/"):
        return

    if is_support(message.from_user.id) and message.from_user.id in admin_reply_state:
        ticket_id = admin_reply_state.pop(message.from_user.id)
        ticket = get_support_ticket(ticket_id)
        if not ticket or ticket["status"] != "open":
            await message.answer("Обращение не найдено или уже закрыто.")
            return

        add_support_message(ticket_id, message.from_user.id, "admin", message.text)
        await track_event("support_admin_reply", message.from_user.id, ticket_id=ticket_id)
        await message.bot.send_message(
            ticket["user_id"],
            f"💬 <b>Ответ поддержки по обращению #{ticket_id}</b>\n\n"
            f"{escape(message.text)}",
            reply_markup=support_keyboard(ticket_id, for_admin=False),
            parse_mode="HTML",
        )
        await message.answer(
            f"✅ Ответ отправлен пользователю по обращению <b>#{ticket_id}</b>.",
            reply_markup=support_keyboard(ticket_id, for_admin=True),
            parse_mode="HTML",
        )
        return

    ticket = get_open_support_ticket(message.from_user.id)
    if not ticket:
        return

    add_support_message(ticket["id"], message.from_user.id, "user", message.text)
    full_ticket = get_support_ticket(ticket["id"]) or ticket
    await track_event("support_user_message", message.from_user.id, ticket_id=ticket["id"], **user_payload(message.from_user))
    await notify_ticket_admins(
        message.bot,
        full_ticket,
        f"💬 <b>Сообщение по обращению #{ticket['id']}</b>\n\n"
        f"Пользователь: {support_user_label(full_ticket)}\n\n"
        f"{escape(message.text)}",
    )
    await message.answer(
        f"✅ Сообщение отправлено в поддержку по обращению <b>#{ticket['id']}</b>.\n\n"
        "Ответ придет сюда.",
        reply_markup=support_keyboard(ticket["id"], for_admin=False),
        parse_mode="HTML",
    )


@router.message(F.photo | F.document | F.video | F.animation | F.voice | F.audio | F.video_note)
async def support_media_router(message: types.Message) -> None:
    if not message.from_user:
        return

    if is_support(message.from_user.id) and message.from_user.id in admin_reply_state:
        ticket_id = admin_reply_state.pop(message.from_user.id)
        ticket = get_support_ticket(ticket_id)
        if not ticket or ticket["status"] != "open":
            await message.answer("Обращение не найдено или уже закрыто.")
            return

        add_support_message(ticket_id, message.from_user.id, "admin", support_message_body(message))
        await track_event("support_admin_reply_media", message.from_user.id, ticket_id=ticket_id, media_type=message.content_type)
        await message.bot.send_message(
            ticket["user_id"],
            f"💬 <b>Ответ поддержки по обращению #{ticket_id}</b>",
            reply_markup=support_keyboard(ticket_id, for_admin=False),
            parse_mode="HTML",
        )
        await message.copy_to(ticket["user_id"])
        await message.answer(
            f"✅ Медиа-ответ отправлен пользователю по обращению <b>#{ticket_id}</b>.",
            reply_markup=support_keyboard(ticket_id, for_admin=True),
            parse_mode="HTML",
        )
        return

    ticket = get_open_support_ticket(message.from_user.id)
    if not ticket:
        await message.answer(
            "Чтобы отправить файл или скрин в поддержку, сначала создайте обращение.",
            reply_markup=support_entry_keyboard(),
        )
        return

    add_support_message(ticket["id"], message.from_user.id, "user", support_message_body(message))
    full_ticket = get_support_ticket(ticket["id"]) or ticket
    await track_event(
        "support_user_media",
        message.from_user.id,
        ticket_id=ticket["id"],
        media_type=message.content_type,
        **user_payload(message.from_user),
    )

    for admin_id in SUPPORT_TELEGRAM_IDS:
        try:
            await message.bot.send_message(
                admin_id,
                f"📎 <b>Вложение по обращению #{ticket['id']}</b>\n\n"
                f"Пользователь: {support_user_label(full_ticket)}",
                reply_markup=support_keyboard(ticket["id"], for_admin=True),
                parse_mode="HTML",
            )
            await message.copy_to(admin_id)
        except TelegramBadRequest as exc:
            logger.warning("Cannot send ticket media to admin %s: %s", admin_id, exc.message)
        except Exception:
            logger.exception("Cannot send ticket media to admin %s", admin_id)

    await message.answer(
        f"✅ Вложение отправлено в поддержку по обращению <b>#{ticket['id']}</b>.\n\n"
        "Ответ придет сюда.",
        reply_markup=support_keyboard(ticket["id"], for_admin=False),
        parse_mode="HTML",
    )


async def notify_admins(bot: Bot, text: str) -> None:
    for admin_id in ADMIN_TELEGRAM_IDS:
        try:
            await bot.send_message(admin_id, text)
        except TelegramBadRequest as exc:
            logger.warning("Cannot notify admin %s: %s", admin_id, exc.message)
        except Exception:
            logger.exception("Cannot notify admin %s", admin_id)


async def notify_ticket_admins(bot: Bot, ticket: Dict[str, Any], text: str) -> None:
    for admin_id in SUPPORT_TELEGRAM_IDS:
        try:
            await bot.send_message(
                admin_id,
                text,
                reply_markup=support_keyboard(ticket["id"], for_admin=True),
                parse_mode="HTML",
            )
        except TelegramBadRequest as exc:
            logger.warning("Cannot notify admin %s about ticket %s: %s", admin_id, ticket["id"], exc.message)
        except Exception:
            logger.exception("Cannot notify admin %s about ticket %s", admin_id, ticket["id"])


async def handle_happ_profile_request(request: web.Request) -> web.Response:
    try:
        order_id = int(request.match_info["order_id"])
    except (KeyError, ValueError):
        raise web.HTTPBadRequest(text="bad order id")

    token = request.match_info.get("token", "").replace(".json", "")
    order = get_order_for_happ_profile(order_id)
    if not order:
        raise web.HTTPNotFound(text="profile not found")

    expected = happ_profile_token(order["id"], order["tg_id"], order.get("xui_uuid") or "")
    if not hmac.compare_digest(token, expected):
        raise web.HTTPForbidden(text="bad token")

    profile = build_happ_json_profile(order["vless_link"], f"{SERVICE_NAME} | Happ")
    if not profile:
        raise web.HTTPBadGateway(text="cannot build profile")

    payload = json.dumps(profile, ensure_ascii=False, indent=2).encode("utf-8")
    filename = f"{order.get('xui_email') or 'vpn'}_happ.json"
    return web.Response(
        body=payload,
        content_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


async def profile_web_server_loop() -> None:
    app = web.Application()
    app.router.add_get("/happ/{order_id}/{token}.json", handle_happ_profile_request)
    app.router.add_get("/happ/{order_id}/{token}", handle_happ_profile_request)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, PROFILE_LISTEN_HOST, PROFILE_LISTEN_PORT)
    await site.start()
    logger.info("Profile endpoint listening on http://%s:%s", PROFILE_LISTEN_HOST, PROFILE_LISTEN_PORT)
    await asyncio.Event().wait()


async def setup_bot_commands(bot: Bot) -> None:
    await bot.set_my_commands(
        [
            BotCommand(command="start", description="Главное меню"),
            BotCommand(command="buy", description="Купить VPN-доступ"),
            BotCommand(command="keys", description="Мои ключи"),
            BotCommand(command="support", description="Помощь и поддержка"),
            BotCommand(command="id", description="Мой Telegram ID"),
            BotCommand(command="help", description="Все команды"),
        ]
    )


def validate_env() -> None:
    required = {
        "BOT_TOKEN": BOT_TOKEN,
        "YOOKASSA_SHOP_ID": YOOKASSA_SHOP_ID,
        "YOOKASSA_SECRET_KEY": YOOKASSA_SECRET_KEY,
        "XUI_BASE_URL": XUI_BASE_URL,
        "XUI_USERNAME": XUI_USERNAME,
        "XUI_PASSWORD": XUI_PASSWORD,
    }
    missing = [key for key, value in required.items() if not value]
    if missing:
        raise RuntimeError(f"Missing env values: {', '.join(missing)}")


async def main() -> None:
    global xui

    validate_env()
    init_db()

    bot = Bot(BOT_TOKEN)
    dp = Dispatcher()
    dp.include_router(router)
    xui = XuiApi()

    me = await bot.get_me()
    await setup_bot_commands(bot)
    logger.info("Bot started as @%s", me.username)
    await notify_admins(bot, f"{SERVICE_NAME}: бот запущен (@{me.username})")

    profile_task = asyncio.create_task(profile_web_server_loop())
    try:
        await dp.start_polling(bot)
    finally:
        profile_task.cancel()
        if xui is not None:
            await xui.close()
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
