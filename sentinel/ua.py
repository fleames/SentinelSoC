# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/ua.py -- UA tag classification (crawler vs generic bot / automation).
"""

_CRAWLER_MARKERS = (
    "googlebot",
    "bingbot",
    "duckduckbot",
    "baiduspider",
    "yandexbot",
    "yandex.com/bots",
    "slurp",
    "semrushbot",
    "ahrefsbot",
    "mj12bot",
    "dotbot",
    "petalbot",
    "bytespider",
    "facebookexternalhit",
    "linkedinbot",
    "twitterbot",
    "slackbot",
    "discordbot",
    "telegrambot",
    "applebot",
    "ia_archiver",
    "amazonbot",
    "pinterestbot",
    "tiktokspider",
    "crawler",
    "google-inspectiontool",
    "gptbot",
    "claudebot",
    "anthropic-ai",
    "perplexitybot",
)
_BOT_TOOL_MARKERS = (
    "curl/",
    "wget/",
    "python-requests",
    "python-urllib",
    "aiohttp",
    "httpx/",
    "go-http-client",
    "okhttp",
    "java/",
    "httpclient",
    "libwww",
    "scrapy",
    "headless",
    "phantomjs",
    "puppeteer",
    "playwright",
    "selenium",
    "zgrab",
    "masscan",
    "nmap",
    "nikto",
    "sqlmap",
)


def _ua_tags(ua):
    """
    Classify User-Agent for UI tags. crawler = search/index/social fetchers;
    bot = broader automation (includes crawlers, HTTP libraries, empty UA).
    """
    ul = (ua or "").strip().lower()
    tags = []
    if any(m in ul for m in _CRAWLER_MARKERS):
        tags.append("crawler")
    is_bot = bool(tags) or not ul
    if not is_bot:
        if any(m in ul for m in _BOT_TOOL_MARKERS):
            is_bot = True
        elif "bot" in ul or "spider" in ul:
            is_bot = True
    if is_bot:
        tags.append("bot")
    out = []
    seen = set()
    for t in tags:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out
