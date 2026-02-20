# Telegram Channel Scraping

The Telegram scraper monitors public channels for keyword hits using the same keyword engine as the dark web crawler.

## Prerequisites

1. **Get API credentials** at [https://my.telegram.org/apps](https://my.telegram.org/apps)
   - Log in with your phone number
   - Create a new application (name/description can be anything)
   - Copy your **API ID** and **API Hash**

2. **Add credentials to `.env`**:
   ```
   TELEGRAM_API_ID=12345678
   TELEGRAM_API_HASH=abcdef1234567890abcdef1234567890
   TELEGRAM_CHANNELS=channel1,channel2,channel3
   ```

3. **Authenticate once** (interactive — requires phone + OTP):
   ```bash
   make telegram-auth
   ```
   This saves a session file to `/app/data/telegram.session`. You only need to do this once — the session persists across restarts.

## Running a Scan

```bash
# Scan all channels configured in TELEGRAM_CHANNELS
make telegram-scan

# Scan specific channels (override .env)
docker compose exec dashboard python -m darkweb_scanner.main telegram-scan --channels chan1,chan2
```

## How It Works

- Reads the last `TELEGRAM_LIMIT_PER_CHANNEL` messages (default: 200) from each channel
- Runs every message through the same keyword scanner used for .onion crawling
- Hits are stored in the same database and appear in the dashboard
- Source URLs are formatted as `https://t.me/channelname/message_id` for easy lookup

## Notes

- Only **public** channels work — private channels require membership and are not supported
- Telethon uses your personal Telegram account — use a dedicated account for scanning
- Flood limits: Telegram rate-limits heavy usage; the scraper includes polite delays
- The session file contains your auth token — keep `/app/data/` secure and do not commit it

## Finding Relevant Channels

Useful starting points for threat intelligence:
- Search Telegram for keywords relevant to your monitoring targets
- Check [IntelX](https://intelx.io/) and [Cybersixgill](https://cybersixgill.com/) for known threat actor channels
- Forums like RaidForums and BreachForums have active Telegram communities
