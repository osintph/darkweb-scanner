"""
Integration test — verifies Tor connectivity.
Requires a running Tor daemon (skipped in CI unless TOR_INTEGRATION=1).
"""

import os
import pytest
import asyncio
from darkweb_scanner.tor_client import create_tor_client


@pytest.mark.skipif(
    os.getenv("TOR_INTEGRATION") != "1",
    reason="Skipped unless TOR_INTEGRATION=1 env var is set"
)
@pytest.mark.asyncio
async def test_tor_connectivity():
    """Verify that Tor is routing traffic correctly."""
    tor = create_tor_client()
    result = await tor.check_connectivity()
    await tor.close()
    assert result, "Tor connectivity check failed"


@pytest.mark.skipif(
    os.getenv("TOR_INTEGRATION") != "1",
    reason="Skipped unless TOR_INTEGRATION=1 env var is set"
)
@pytest.mark.asyncio
async def test_onion_fetch():
    """Verify that we can actually reach an .onion site."""
    tor = create_tor_client()
    session = await tor.get_session()
    # DuckDuckGo's .onion site — a stable, legitimate test target
    try:
        async with session.get("https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", ssl=False) as resp:
            assert resp.status == 200
    finally:
        await tor.close()
