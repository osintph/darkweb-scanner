# Paste Site Monitor

The Paste Monitor polls public paste sites in near-real-time and scans new pastes for Philippine-specific patterns — mobile numbers, bank names, government domains, ID number formats, and card BINs. Because pastes are ephemeral and often disappear within hours, fast detection matters.

## How It Works

Every 3–10 minutes (depending on source), the monitor fetches each site's recent/archive page, extracts new paste URLs, checks them against a `seen_pastes` database table to avoid re-scanning, fetches unseen pastes, and runs them through the PH pattern library. Hits are stored in `paste_hits` and appear in the Paste Monitor tab in the dashboard.

## PH Pattern Library

| Pattern | Description | Example |
|---------|-------------|---------|
| `ph_mobile` | Philippine mobile numbers | `+639171234567`, `09171234567` |
| `ph_domain` | Any `.ph` domain mention | `bdo.com.ph`, `dlsu.edu.ph` |
| `ph_gov_domain` | Government domains | `bsp.gov.ph`, `dict.gov.ph` |
| `ph_bank` | Philippine bank names | BDO, BPI, Metrobank, UnionBank, RCBC, Landbank, PNB, Security Bank, EastWest, PSBank, Chinabank |
| `ph_sss` | SSS number format | `33-1234567-8` |
| `ph_tin` | Tax Identification Number | `123-456-789`, `123-456-789-000` |
| `ph_philhealth` | PhilHealth number | `01-234567890-1` |
| `ph_card_bin` | PH-issued card BINs | First 6 digits matching known PH-issued Visa/Mastercard ranges |
| `ph_postal` | Philippines/Pilipinas mentions | `Philippines`, `Pilipinas` |

## Sources Monitored

| Source | Poll Interval | Notes |
|--------|---------------|-------|
| Pastebin | 3 minutes | Archive page — most active paste site |
| Rentry | 5 minutes | No rate limiting, recent page |
| Pastes.io | 5 minutes | Public feed |
| ControlC | 10 minutes | Recent pastes page |

## Dashboard

Navigate to the **📋 Paste Monitor** tab to view results.

**Filters:**
- Filter by source (Pastebin, Rentry, Pastes.io, ControlC)
- Filter by pattern type

**Stats row** shows total hits, total pastes scanned, pastes with hits, and per-source breakdown.

**Scan Now button** (admin only) — triggers an immediate one-shot scan of all sources without waiting for the cron schedule.

## Setup

### Automated Scanning (cron)

The monitor runs automatically via cron every 5 minutes. This is configured during deployment. To verify or add manually:

```bash
crontab -e
```

Add:
```
*/5 * * * * cd /root/darkweb-scanner && docker compose exec -T dashboard python3 -c "import sys; sys.path.insert(0,'/app/src'); from darkweb_scanner.storage import Storage; from darkweb_scanner.paste_monitor import run_paste_monitor; run_paste_monitor(Storage(), single_run=True)" >> /var/log/paste_monitor.log 2>&1
```

### Manual Scan

Run a one-shot scan from the command line:

```bash
docker compose exec dashboard python3 -c "
import sys
sys.path.insert(0, '/app/src')
from darkweb_scanner.storage import Storage
from darkweb_scanner.paste_monitor import run_paste_monitor
result = run_paste_monitor(Storage(), single_run=True)
print(result)
"
```

### Check Logs

```bash
tail -f /var/log/paste_monitor.log
```

## Database Tables

**`seen_pastes`** — every paste URL processed, with a `had_hits` flag so you can query which pastes were interesting:
```sql
SELECT * FROM seen_pastes WHERE had_hits = 1 ORDER BY fetched_at DESC LIMIT 20;
```

**`paste_hits`** — all pattern matches with context:
```sql
SELECT source, matched_pattern, count(*) FROM paste_hits GROUP BY source, matched_pattern;
```

## Extending the Pattern Library

Edit `src/darkweb_scanner/paste_monitor.py` and add to the `PH_PATTERNS` dict:

```python
PH_PATTERNS = {
    ...
    "your_pattern": re.compile(r'your_regex_here', re.IGNORECASE),
}
```

Pattern names appear as labels in the dashboard automatically. Rebuild the image after editing:

```bash
docker compose build --no-cache dashboard && docker compose up -d dashboard
```

## Adding New Sources

Add a new `PasteSource` entry in `paste_monitor.py`:

```python
SOURCES = [
    ...
    PasteSource("mysource", "https://example.com/recent", "https://example.com", 300),
]
```

Then implement a scraper function and register it in `SOURCE_SCRAPERS`:

```python
def _get_mysource_urls() -> list[tuple[str, str]]:
    r = _safe_get("https://example.com/recent")
    if not r:
        return []
    soup = BeautifulSoup(r.text, "lxml")
    results = []
    # extract (paste_id, raw_url) tuples
    return results

SOURCE_SCRAPERS = {
    ...
    "mysource": _get_mysource_urls,
}
```

## Notes

- Pastes larger than 500KB are skipped to avoid processing massive data dumps that would slow the monitor
- Within a single paste, the same pattern+value combination is only recorded once to avoid flooding the hits table with duplicates
- 0.5 second delay between fetches to avoid rate limiting
- The `seen_pastes` table grows over time — it is safe to prune entries older than 30 days periodically
