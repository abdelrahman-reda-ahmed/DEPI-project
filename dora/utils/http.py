from __future__ import annotations

import asyncio
from typing import Optional

import httpx
from httpx import AsyncClient, Response

from dora.config import DORAConfig


class AsyncHTTPClient:
    def __init__(self, config: DORAConfig):
        self.config = config
        self._client: Optional[AsyncClient] = None

    async def __aenter__(self):
        self._client = AsyncClient(
            timeout=httpx.Timeout(self.config.scan_timeout),
            headers={"User-Agent": self.config.user_agent},
            follow_redirects=True,
            verify=False,
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    async def get(self, url: str, **kwargs) -> Response:
        if self._client is None:
            raise RuntimeError("client not initialized")
        for attempt in range(self.config.scan_retries + 1):
            try:
                return await self._client.get(url, **kwargs)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError):
                if attempt < self.config.scan_retries:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
                raise

    async def head(self, url: str, **kwargs) -> Response:
        if self._client is None:
            raise RuntimeError("client not initialized")
        try:
            return await self._client.head(url, **kwargs)
        except httpx.ConnectError:
            raise

    async def fetch_text(self, url: str, **kwargs) -> str:
        resp = await self.get(url, **kwargs)
        return resp.text

    async def fetch_json(self, url: str, **kwargs) -> dict:
        resp = await self.get(url, **kwargs)
        return resp.json()

    async def probe(self, url: str) -> tuple[str, int, dict[str, str]]:
        try:
            resp = await self.head(url)
            return url, resp.status_code, dict(resp.headers)
        except Exception:
            try:
                resp = await self.get(url)
                return url, resp.status_code, dict(resp.headers)
            except Exception:
                return url, 0, {}
