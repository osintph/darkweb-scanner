"""
Main entry point — orchestrates crawling, scanning, storage, and alerting.
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

import click

from .alerting import Alerter
from .crawler import CrawlConfig, Crawler
from .scanner import KeywordConfig, Scanner
from .storage import Storage
from .tor_client import create_tor_client

# ── Logging setup ──────────────────────────────────────────────────────────────

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/app/data/scanner.log")
        if os.path.exists("/app/data")
        else logging.NullHandler(),
    ],
)
logger = logging.getLogger(__name__)


# ── Core orchestration ─────────────────────────────────────────────────────────


async def run_scan(
    seeds: list[str],
    keyword_config: KeywordConfig,
    crawl_config: CrawlConfig,
    storage: Storage,
    alerter: Alerter,
    check_tor: bool = True,
):
    tor = create_tor_client()
    crawler = Crawler(tor, crawl_config)
    scanner = Scanner(keyword_config)

    logger.info(
        f"Starting scan with {len(seeds)} seed URL(s) and {scanner.keyword_count} keyword(s)"
    )

    if check_tor:
        logger.info("Checking Tor connectivity...")
        if not await tor.check_connectivity():
            logger.error("Tor connectivity check failed. Is the Tor daemon running?")
            sys.exit(1)
        logger.info("Tor connectivity confirmed.")

    session_id = storage.create_crawl_session(seeds)
    pages_crawled = 0
    hits_found = 0

    try:
        async for page in crawler.crawl(seeds):
            pages_crawled += 1

            storage.save_page(
                url=page.url,
                status_code=page.status_code,
                depth=page.depth,
                session_id=session_id,
                error=page.error,
            )

            if page.error or not page.text:
                continue

            hits = scanner.scan(url=page.url, text=page.text, depth=page.depth)

            for hit in hits:
                hit_id = storage.save_hit(
                    url=hit.url,
                    keyword=hit.keyword,
                    category=hit.category,
                    context=hit.context,
                    position=hit.position,
                    depth=hit.depth,
                    session_id=session_id,
                )
                hits_found += 1

                # alert and mark
                if alerter.alert(hit):
                    storage.mark_alerted(hit_id)

            if pages_crawled % 10 == 0:
                logger.info(f"Progress: {pages_crawled} pages crawled, {hits_found} hits found")

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Scan error: {e}", exc_info=True)
        storage.update_crawl_session(session_id, pages_crawled, hits_found, status="failed")
        raise
    finally:
        storage.update_crawl_session(session_id, pages_crawled, hits_found, status="completed")
        await tor.close()

    logger.info(f"Scan complete. Pages: {pages_crawled} | Hits: {hits_found}")
    return {"pages_crawled": pages_crawled, "hits_found": hits_found}


# ── CLI ────────────────────────────────────────────────────────────────────────


@click.group()
def cli():
    """Dark Web Scanner — keyword monitoring tool for .onion sites."""
    pass


@cli.command()
@click.option("--seeds", "-s", default="config/seeds.txt", help="Path to seed URLs file")
@click.option("--keywords", "-k", default="config/keywords.yaml", help="Path to keywords YAML file")
@click.option("--depth", "-d", default=None, type=int, help="Max crawl depth (overrides env)")
@click.option("--no-tor-check", is_flag=True, default=False, help="Skip Tor connectivity check")
def scan(seeds: str, keywords: str, depth: int, no_tor_check: bool):
    """Run a crawl and keyword scan."""
    seeds_path = Path(seeds)
    keywords_path = Path(keywords)

    if not seeds_path.exists():
        click.echo(f"Seeds file not found: {seeds_path}", err=True)
        sys.exit(1)
    if not keywords_path.exists():
        click.echo(f"Keywords file not found: {keywords_path}", err=True)
        sys.exit(1)

    seed_urls = [
        line.strip()
        for line in seeds_path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not seed_urls:
        click.echo("No seed URLs found.", err=True)
        sys.exit(1)

    keyword_config = KeywordConfig.from_yaml(str(keywords_path))
    crawl_config = CrawlConfig()
    if depth is not None:
        crawl_config.max_depth = depth

    storage = Storage()
    alerter = Alerter()

    asyncio.run(
        run_scan(
            seeds=seed_urls,
            keyword_config=keyword_config,
            crawl_config=crawl_config,
            storage=storage,
            alerter=alerter,
            check_tor=not no_tor_check,
        )
    )


@cli.command()
def stats():
    """Print database statistics."""
    storage = Storage()
    s = storage.get_stats()
    click.echo(f"\n{'=' * 40}")
    click.echo("  Dark Web Scanner — Statistics")
    click.echo(f"{'=' * 40}")
    click.echo(f"  Sessions:    {s['total_sessions']}")
    click.echo(f"  Pages crawled: {s['total_pages']}")
    click.echo(f"  Keyword hits:  {s['total_hits']}")
    if s["top_keywords"]:
        click.echo("\n  Top keywords:")
        for item in s["top_keywords"]:
            click.echo(f"    {item['keyword']:<40} {item['count']} hits")
    click.echo(f"{'=' * 40}\n")


@cli.command()
@click.option("--limit", "-n", default=20, help="Number of recent hits to show")
def hits(limit: int):
    """Show recent keyword hits."""
    storage = Storage()
    records = storage.get_recent_hits(limit=limit)
    if not records:
        click.echo("No hits found yet.")
        return
    for r in records:
        click.echo(f"\n[{r.found_at}] {r.keyword!r} ({r.category})")
        click.echo(f"  URL: {r.url}")
        click.echo(f"  Context: {r.context[:200]}...")


@cli.command()
def check_tor():
    """Verify Tor is reachable."""

    async def _check():
        tor = create_tor_client()
        ok = await tor.check_connectivity()
        await tor.close()
        return ok

    ok = asyncio.run(_check())
    if ok:
        click.echo("✅ Tor is connected and routing correctly.")
    else:
        click.echo("❌ Tor connectivity check failed.", err=True)
        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
