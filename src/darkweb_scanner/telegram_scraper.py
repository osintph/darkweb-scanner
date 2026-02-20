"""
Telegram channel scraper — monitors public channels for keyword hits.
Uses Telethon to read messages without joining channels.
Requires a Telegram API ID and Hash from https://my.telegram.org
"""

import asyncio
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TelegramConfig:
    api_id: int
    api_hash: str
    session_path: str
    channels: list[str]
    limit_per_channel: int = 200

    @classmethod
    def from_env(cls) -> Optional["TelegramConfig"]:
        api_id = os.getenv("TELEGRAM_API_ID")
        api_hash = os.getenv("TELEGRAM_API_HASH")
        channels_raw = os.getenv("TELEGRAM_CHANNELS", "")
        if not api_id or not api_hash:
            return None
        channels = [c.strip().lstrip("@") for c in channels_raw.split(",") if c.strip()]
        return cls(
            api_id=int(api_id),
            api_hash=api_hash,
            session_path=os.getenv("TELEGRAM_SESSION_PATH", "/app/data/telegram.session"),
            channels=channels,
            limit_per_channel=int(os.getenv("TELEGRAM_LIMIT_PER_CHANNEL", "200")),
        )


async def scrape_channels(
    config: TelegramConfig,
    scanner,
    storage,
    alerter,
    session_id: Optional[int] = None,
) -> dict:
    """
    Scrape Telegram channels for keyword hits.
    Returns summary dict with pages_scraped and hits_found.
    """
    try:
        from telethon import TelegramClient
        from telethon.errors import (
            ChannelPrivateError,
            FloodWaitError,
            UsernameInvalidError,
            UsernameNotOccupiedError,
        )
    except ImportError:
        logger.error("telethon not installed. Run: pip install telethon")
        return {"pages_scraped": 0, "hits_found": 0}

    if not config.channels:
        logger.warning("No Telegram channels configured. Set TELEGRAM_CHANNELS in .env")
        return {"pages_scraped": 0, "hits_found": 0}

    session_file = Path(config.session_path)
    if not session_file.exists():
        logger.error(
            f"Telegram session not found at {config.session_path}. "
            "Run: make telegram-auth to authenticate first."
        )
        return {"pages_scraped": 0, "hits_found": 0}

    client = TelegramClient(
        str(session_file.with_suffix("")),
        config.api_id,
        config.api_hash,
    )

    pages_scraped = 0
    hits_found = 0

    try:
        await client.connect()
        if not await client.is_user_authorized():
            logger.error("Telegram session expired. Run: make telegram-auth to re-authenticate.")
            return {"pages_scraped": 0, "hits_found": 0}

        for channel in config.channels:
            logger.info(f"Scraping Telegram channel: @{channel} (limit={config.limit_per_channel})")
            channel_total = 0
            channel_text = 0
            channel_hits = 0

            try:
                entity = await client.get_entity(channel)
                async for message in client.iter_messages(
                    entity, limit=config.limit_per_channel
                ):
                    channel_total += 1
                    # Capture text messages and media captions
                    text = message.text or message.message or ""
                    if not text.strip():
                        continue

                    channel_text += 1
                    pages_scraped += 1
                    url = f"https://t.me/{channel}/{message.id}"

                    hits = scanner.scan(url=url, text=text, depth=0)
                    for hit in hits:
                        hit_id = storage.save_hit(
                            url=hit.url,
                            keyword=hit.keyword,
                            category=hit.category,
                            context=hit.context,
                            position=hit.position,
                            depth=0,
                            session_id=session_id,
                        )
                        hits_found += 1
                        channel_hits += 1
                        if alerter.alert(hit):
                            storage.mark_alerted(hit_id)

                    await asyncio.sleep(0.05)

                logger.info(
                    f"@{channel}: {channel_total} total messages, "
                    f"{channel_text} with text, {channel_hits} keyword hits"
                )

            except (UsernameNotOccupiedError, UsernameInvalidError):
                logger.warning(f"Channel not found or invalid: @{channel}")
            except ChannelPrivateError:
                logger.warning(f"Channel is private, cannot access: @{channel}")
            except FloodWaitError as e:
                logger.warning(f"Flood wait {e.seconds}s for @{channel} — skipping")
                await asyncio.sleep(e.seconds)
            except Exception as e:
                logger.error(f"Error scraping @{channel}: {e}", exc_info=True)

    finally:
        await client.disconnect()

    logger.info(f"Telegram scan complete. Messages with text: {pages_scraped} | Hits: {hits_found}")
    return {"pages_scraped": pages_scraped, "hits_found": hits_found}


async def interactive_auth(config: TelegramConfig):
    """
    Run interactive first-time authentication.
    Called by: make telegram-auth
    """
    try:
        from telethon import TelegramClient
    except ImportError:
        print("ERROR: telethon not installed. Run: pip install telethon")
        return

    session_file = Path(config.session_path)
    session_file.parent.mkdir(parents=True, exist_ok=True)

    print(f"\n{'=' * 55}")
    print("  Telegram Authentication")
    print(f"{'=' * 55}")
    print(f"  Session will be saved to: {config.session_path}")
    print(f"  API ID: {config.api_id}")
    print()

    client = TelegramClient(
        str(session_file.with_suffix("")),
        config.api_id,
        config.api_hash,
    )

    await client.start()
    me = await client.get_me()
    print(f"\n✅ Authenticated as: {me.first_name} (@{me.username})")
    print(f"   Session saved to: {config.session_path}")
    print("\nYou can now run Telegram scans with: make telegram-scan")
    await client.disconnect()
