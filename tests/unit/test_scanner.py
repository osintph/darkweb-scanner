"""Unit tests for the keyword scanner."""

import pytest
from darkweb_scanner.scanner import KeywordConfig, Scanner


@pytest.fixture
def config():
    return KeywordConfig(
        categories={
            "brand": ["acme corp", "acme.com"],
            "threat": ["credential dump", "database leak"],
        },
        case_sensitive=False,
        context_window=50,
        alert_on_first_hit_only=True,
    )


@pytest.fixture
def scanner(config):
    return Scanner(config)


def test_basic_hit(scanner):
    text = "We found a credential dump on the dark web involving your users."
    hits = scanner.scan("http://test.onion", text)
    assert len(hits) == 1
    assert hits[0].keyword == "credential dump"
    assert hits[0].category == "threat"


def test_case_insensitive(scanner):
    text = "ACME CORP was mentioned in this post."
    hits = scanner.scan("http://test.onion", text)
    assert len(hits) == 1
    assert hits[0].keyword == "acme corp"


def test_no_hits(scanner):
    text = "This page talks about completely unrelated things."
    hits = scanner.scan("http://test.onion", text)
    assert hits == []


def test_multiple_keywords(scanner):
    text = "acme corp had a database leak and credential dump posted here."
    hits = scanner.scan("http://test.onion", text)
    keywords_found = {h.keyword for h in hits}
    assert "acme corp" in keywords_found
    assert "database leak" in keywords_found
    assert "credential dump" in keywords_found


def test_context_window(scanner):
    text = "before " * 20 + "acme corp" + " after " * 20
    hits = scanner.scan("http://test.onion", text)
    assert len(hits) == 1
    # context should be shorter than full text
    assert len(hits[0].context) < len(text)
    assert "acme corp" in hits[0].context.lower()


def test_empty_text(scanner):
    hits = scanner.scan("http://test.onion", "")
    assert hits == []


def test_url_recorded(scanner):
    url = "http://somesite.onion/page"
    hits = scanner.scan(url, "acme corp mentioned here")
    assert hits[0].url == url


def test_add_keyword(scanner):
    scanner.add_keyword("new threat", "custom")
    hits = scanner.scan("http://test.onion", "there is a new threat actor")
    assert any(h.keyword == "new threat" for h in hits)


def test_remove_keyword(scanner):
    scanner.remove_keyword("acme corp")
    hits = scanner.scan("http://test.onion", "acme corp was here")
    assert not any(h.keyword == "acme corp" for h in hits)


def test_keyword_count(scanner):
    initial = scanner.keyword_count
    scanner.add_keyword("extra keyword", "test")
    assert scanner.keyword_count == initial + 1


def test_from_list():
    scanner = Scanner(KeywordConfig.from_list(["alpha", "beta", "gamma"]))
    hits = scanner.scan("http://test.onion", "alpha and beta are here")
    assert len(hits) == 2
