"""Shared Playwright fixtures for browser tests.

The official sync pytest-playwright plugin starts its own event loop and can
conflict with pytest-asyncio tests in the same suite. Browser tests therefore
use a small local fixture instead, while the project-level pytest config
disables the external plugin.
"""

from collections.abc import Generator

import pytest
from playwright.sync_api import Browser, Page, Playwright, sync_playwright


@pytest.fixture(scope="session")
def playwright_instance() -> Generator[Playwright, None, None]:
    with sync_playwright() as playwright:
        yield playwright


@pytest.fixture(scope="session")
def browser(playwright_instance: Playwright) -> Generator[Browser, None, None]:
    browser = playwright_instance.chromium.launch(headless=True)
    try:
        yield browser
    finally:
        browser.close()


@pytest.fixture
def page(browser: Browser) -> Generator[Page, None, None]:
    page = browser.new_page()
    try:
        yield page
    finally:
        page.close()
