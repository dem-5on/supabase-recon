import asyncio
import base64
import json
import re
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from .models import TargetResult
from .patterns import (

    CREATE_CLIENT_RE,
    INLINE_CONFIG_RE,
    JWT_RE,
    POSTGREST_VALUES,
    SUPABASE_HEADERS,
    SUPABASE_URL_RE,
)


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def snippet(text: str, match: re.Match, window: int = 80) -> str:
    start = max(0, match.start() - window)
    end = min(len(text), match.end() + window)
    return text[start:end].replace("\n", " ").strip()


def decode_jwt_role(token: str) -> str:
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get("role", "unknown")
    except Exception:
        return "unknown"


class SupabaseScanner:
    def __init__(self, timeout: int = 15, max_js: int = 30):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_js = max_js

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    async def _fetch(
        self, session: aiohttp.ClientSession, url: str
    ) -> tuple[str | None, dict]:
        try:
            async with session.get(url, allow_redirects=True) as resp:
                text = await resp.text(errors="replace")
                return text, dict(resp.headers)
        except Exception:
            return None, {}

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def _check_headers(self, headers: dict, source: str, result: TargetResult) -> None:
        for key, value in headers.items():
            if key.lower() in SUPABASE_HEADERS:
                if any(sv in value.lower() for sv in POSTGREST_VALUES):
                    result.add_finding("header", f"{key}: {value}", source)

    def _scan_text(self, text: str, source: str, result: TargetResult) -> None:
        seen_jwts: set[str] = set()

        for m in SUPABASE_URL_RE.finditer(text):
            result.add_finding("supabase_url", m.group(0), source, snippet(text, m))

        for m in JWT_RE.finditer(text):
            token = m.group(0)
            if token not in seen_jwts:
                seen_jwts.add(token)
                role = decode_jwt_role(token)
                result.add_finding(
                    "jwt_key",
                    f"{token[:40]}...  [role={role}]",
                    source,
                    snippet(text, m),
                )

        for m in CREATE_CLIENT_RE.finditer(text):
            result.add_finding(
                "create_client", "createClient() call detected", source, snippet(text, m)
            )

        for m in INLINE_CONFIG_RE.finditer(text):
            result.add_finding("inline_config", m.group(0), source, snippet(text, m))

    # ------------------------------------------------------------------
    # Main scan
    # ------------------------------------------------------------------

    async def scan(
        self,
        session: aiohttp.ClientSession,
        target: str,
        deep: bool = False,
        output_dir: str = "output",
    ) -> TargetResult:
        target = normalize_url(target)
        result = TargetResult(target=target)

        html, headers = await self._fetch(session, target)
        if html is None:
            result.errors.append("Failed to fetch target URL")
            return result

        result.reachable = True
        self._check_headers(headers, source=target, result=result)
        self._scan_text(html, source=target, result=result)

        # Collect JS URLs from <script src="...">
        soup = BeautifulSoup(html, "html.parser")
        base = f"{urlparse(target).scheme}://{urlparse(target).netloc}"

        js_urls: list[str] = []
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            js_urls.append(urljoin(base, src) if not src.startswith("http") else src)

        js_urls = list(dict.fromkeys(js_urls))[: self.max_js]

        js_fetches = await asyncio.gather(*[self._fetch(session, u) for u in js_urls])
        js_texts: list[str] = []

        for js_url, (js_text, _) in zip(js_urls, js_fetches):
            if js_text:
                result.js_files_scanned.append(js_url)
                self._scan_text(js_text, source=js_url, result=result)
                js_texts.append(js_text)

        if deep and result.supabase_detected:
            await self.scan_deep_phase(session, result, html, js_texts, output_dir)

        return result

    async def scan_deep_phase(  # noqa: E303
        self,
        session: aiohttp.ClientSession,
        result: TargetResult,
        raw_html: str,
        js_texts: list[str],
        output_dir: str,
    ) -> None:
        """Called after passive scan when deep mode is active."""
        from .deep_scanner import run_deep_scan
        import re as _re

        JWT_FULL = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

        sb_url = next(
            (f.value for f in result.findings if f.type == "supabase_url"), None
        )
        if not sb_url:
            return

        raw_jwt = None
        for text in [raw_html] + js_texts:
            if not text:
                continue
            m = JWT_FULL.search(text)
            if m:
                raw_jwt = m.group(0)
                break

        if not raw_jwt:
            return

        deep_result = await run_deep_scan(session, sb_url, raw_jwt, output_dir)
        result.deep_scan = deep_result.to_dict()