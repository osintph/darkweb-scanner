"""Unit tests for the crawler — link extraction and URL filtering."""

import pytest
from unittest.mock import MagicMock, AsyncMock
from darkweb_scanner.crawler import Crawler, CrawlConfig


@pytest.fixture
def crawler():
    tor_mock = MagicMock()
    config = CrawlConfig(max_depth=2, max_concurrent=2, delay_min=0, delay_max=0)
    return Crawler(tor_mock, config)


def test_normalize_url(crawler):
    assert crawler._normalize_url("http://abc.onion/page#section") == "http://abc.onion/page"
    assert crawler._normalize_url("http://abc.onion/") == "http://abc.onion"


def test_get_domain(crawler):
    assert crawler._get_domain("http://abc123.onion/page") == "abc123.onion"


def test_extract_links(crawler):
    html = """
    <html><body>
      <a href="http://other.onion/page1">Link 1</a>
      <a href="/relative">Relative</a>
      <a href="https://clearnet.com">Clearnet</a>
      <a href="mailto:test@test.com">Email</a>
      <a href="http://valid.onion/page2">Link 2</a>
    </body></html>
    """
    links = crawler._extract_links(html, "http://base.onion")
    assert "http://other.onion/page1" in links
    assert "http://base.onion/relative" in links
    assert "http://valid.onion/page2" in links
    # clearnet and mailto should be excluded
    assert not any("clearnet.com" in l for l in links)
    assert not any("mailto" in l for l in links)


def test_should_crawl_already_visited(crawler):
    crawler._visited.add("http://abc.onion/page")
    assert not crawler._should_crawl("http://abc.onion/page", "abc.onion")


def test_should_crawl_non_onion(crawler):
    assert not crawler._should_crawl("http://clearnet.com/page", "clearnet.com")


def test_should_crawl_domain_limit(crawler):
    crawler.config.max_pages_per_domain = 2
    crawler._domain_counts["abc.onion"] = 2
    assert not crawler._should_crawl("http://abc.onion/new-page", "abc.onion")


def test_should_crawl_stay_on_domain(crawler):
    crawler.config.stay_on_domain = True
    assert not crawler._should_crawl("http://other.onion/page", "origin.onion")
    assert crawler._should_crawl("http://origin.onion/page", "origin.onion")


def test_reset(crawler):
    crawler._visited.add("http://abc.onion")
    crawler._pages_crawled = 10
    crawler.reset()
    assert len(crawler._visited) == 0
    assert crawler._pages_crawled == 0
