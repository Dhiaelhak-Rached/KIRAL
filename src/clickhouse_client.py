"""ClickHouse HTTP client.

Lightweight async client using httpx for JSONEachRow ingestion.
"""

from __future__ import annotations

import json
import logging

import httpx

from src.config import settings

logger = logging.getLogger(__name__)


class ClickHouseClient:
    """Async ClickHouse client over HTTP interface."""

    def __init__(
        self,
        url: str = settings.ch_url,
        database: str = settings.ch_database,
        username: str = settings.ch_user,
        password: str | None = settings.ch_password,
    ):
        self.url = url
        self.database = database
        self.auth = (username, password) if password else None
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=10.0),
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
        )
        self._inserted = 0

    @staticmethod
    def _raise_ch_error(resp: httpx.Response):
        """Surface ClickHouse error text instead of generic HTTP codes."""
        if resp.is_error:
            body = resp.text.strip()[:800]
            raise RuntimeError(
                f"ClickHouse HTTP {resp.status_code}: {body}"
            )

    async def execute(
        self,
        query: str,
        database: str | None = None,
        query_params: dict | None = None,
    ) -> str:
        """Execute an arbitrary SQL query.

        Args:
            query: SQL statement. Use ClickHouse parameter syntax
                   ``{name:Type}`` for values that come from user input.
            database: Database to run the query in (passed as HTTP ``database`` param).
            query_params: Dict of user-supplied values. Each key is prefixed
                          with ``param_`` and sent as an HTTP query parameter.
        """
        params = {}
        if database:
            params["database"] = database
        if query_params:
            for key, value in query_params.items():
                params[f"param_{key}"] = str(value)
        resp = await self._client.post(
            self.url,
            params=params,
            content=query,
            headers={"Content-Type": "text/plain; charset=UTF-8"},
            auth=self.auth,
        )
        self._raise_ch_error(resp)
        return resp.text

    async def insert_json_each_row(self, table: str, rows: list[dict]) -> str:
        """Batch insert rows via JSONEachRow format.

        Args:
            table: Target table name (qualified if needed).
            rows: List of row dictionaries.
        """
        if not rows:
            return ""

        body = "\n".join(
            json.dumps(r, separators=(",", ":"), default=str) for r in rows
        )
        params = {
            "database": self.database,
            "query": f"INSERT INTO {table} FORMAT JSONEachRow",
            "input_format_allow_errors_num": max(1, len(rows) // 100),
            "input_format_allow_errors_ratio": 0.05,
        }
        resp = await self._client.post(
            self.url, params=params, content=body, auth=self.auth
        )
        self._raise_ch_error(resp)
        self._inserted += len(rows)
        return resp.text

    @property
    def inserted_count(self) -> int:
        return self._inserted

    async def close(self):
        await self._client.aclose()
