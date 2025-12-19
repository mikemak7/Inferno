"""
Caido integration tool for Inferno.

This module provides integration with Caido, a modern web security testing proxy.
It allows the agent to:
- Route requests through Caido for inspection
- Retrieve captured requests/responses
- Replay requests with modifications
- Search through captured traffic using HTTPQL

Caido API: https://docs.caido.io/concepts/internals/graphql.html
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from inferno.tools.base import CoreTool, ToolCategory, ToolExample, ToolResult

logger = structlog.get_logger(__name__)

# Check if httpx is available for async HTTP
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


@dataclass
class CaidoConfig:
    """Configuration for Caido connection."""

    host: str = "localhost"
    port: int = 8080
    graphql_port: int = 8080  # GraphQL API port (same as proxy by default)
    auth_token: str | None = None
    use_https: bool = False

    @property
    def proxy_url(self) -> str:
        """Get the proxy URL for routing requests."""
        scheme = "https" if self.use_https else "http"
        return f"{scheme}://{self.host}:{self.port}"

    @property
    def graphql_url(self) -> str:
        """Get the GraphQL API URL."""
        scheme = "https" if self.use_https else "http"
        return f"{scheme}://{self.host}:{self.graphql_port}/graphql"

    @classmethod
    def from_env(cls) -> CaidoConfig:
        """Create config from environment variables."""
        return cls(
            host=os.getenv("CAIDO_HOST", "localhost"),
            port=int(os.getenv("CAIDO_PORT", "8080")),
            graphql_port=int(os.getenv("CAIDO_GRAPHQL_PORT", "8080")),
            auth_token=os.getenv("CAIDO_AUTH_TOKEN"),
            use_https=os.getenv("CAIDO_USE_HTTPS", "false").lower() == "true",
        )


@dataclass
class CaidoRequest:
    """Represents a request captured by Caido."""

    id: str
    method: str
    url: str
    host: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    timestamp: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "headers": self.headers,
            "body": self.body,
            "timestamp": self.timestamp,
        }


@dataclass
class CaidoResponse:
    """Represents a response captured by Caido."""

    id: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    length: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body,
            "length": self.length,
        }


class CaidoClient:
    """
    Client for interacting with Caido's GraphQL API.

    This client provides methods to:
    - Query captured requests/responses
    - Replay requests
    - Search traffic using HTTPQL
    """

    def __init__(self, config: CaidoConfig | None = None):
        """Initialize the Caido client."""
        self.config = config or CaidoConfig.from_env()
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            headers = {"Content-Type": "application/json"}
            if self.config.auth_token:
                headers["Authorization"] = f"Bearer {self.config.auth_token}"

            self._client = httpx.AsyncClient(
                headers=headers,
                timeout=30.0,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _execute_query(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a GraphQL query."""
        client = await self._get_client()

        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        try:
            response = await client.post(self.config.graphql_url, json=payload)
            response.raise_for_status()
            result = response.json()

            if "errors" in result:
                raise Exception(f"GraphQL errors: {result['errors']}")

            return result.get("data", {})

        except httpx.ConnectError:
            raise ConnectionError(
                f"Cannot connect to Caido at {self.config.graphql_url}. "
                "Make sure Caido is running."
            )

    async def check_connection(self) -> bool:
        """Check if Caido is accessible."""
        try:
            query = """
            query Viewer {
                viewer {
                    id
                }
            }
            """
            await self._execute_query(query)
            return True
        except Exception as e:
            logger.warning("caido_connection_failed", error=str(e))
            return False

    async def get_requests(
        self,
        limit: int = 50,
        filter_host: str | None = None,
        httpql: str | None = None,
    ) -> list[CaidoRequest]:
        """
        Get captured requests from Caido.

        Args:
            limit: Maximum number of requests to return
            filter_host: Filter by host
            httpql: HTTPQL query for filtering (e.g., "req.method.eq:POST")

        Returns:
            List of captured requests
        """
        # Build the HTTPQL filter
        filter_parts = []
        if filter_host:
            filter_parts.append(f'req.host.cont:"{filter_host}"')
        if httpql:
            filter_parts.append(httpql)

        filter_query = " AND ".join(filter_parts) if filter_parts else None

        query = """
        query GetRequests($first: Int, $filter: HTTPQL) {
            requests(first: $first, filter: $filter) {
                edges {
                    node {
                        id
                        method
                        host
                        path
                        query
                        raw
                        createdAt
                    }
                }
            }
        }
        """

        variables = {"first": limit}
        if filter_query:
            variables["filter"] = filter_query

        try:
            data = await self._execute_query(query, variables)
            requests = []

            edges = data.get("requests", {}).get("edges", [])
            for edge in edges:
                node = edge.get("node", {})
                req = CaidoRequest(
                    id=node.get("id", ""),
                    method=node.get("method", ""),
                    url=f"{node.get('host', '')}{node.get('path', '')}",
                    host=node.get("host", ""),
                    path=node.get("path", ""),
                    body=node.get("raw"),
                    timestamp=node.get("createdAt"),
                )
                requests.append(req)

            return requests

        except Exception as e:
            logger.error("caido_get_requests_failed", error=str(e))
            return []

    async def get_request_response(
        self,
        request_id: str,
    ) -> tuple[CaidoRequest | None, CaidoResponse | None]:
        """
        Get a specific request and its response by ID.

        Args:
            request_id: The request ID from Caido

        Returns:
            Tuple of (request, response) or (None, None) if not found
        """
        query = """
        query GetRequestResponse($id: ID!) {
            request(id: $id) {
                id
                method
                host
                path
                raw
                response {
                    id
                    statusCode
                    raw
                    length
                }
            }
        }
        """

        try:
            data = await self._execute_query(query, {"id": request_id})
            node = data.get("request")

            if not node:
                return None, None

            request = CaidoRequest(
                id=node.get("id", ""),
                method=node.get("method", ""),
                url=f"{node.get('host', '')}{node.get('path', '')}",
                host=node.get("host", ""),
                path=node.get("path", ""),
                body=node.get("raw"),
            )

            response = None
            if node.get("response"):
                resp_node = node["response"]
                response = CaidoResponse(
                    id=resp_node.get("id", ""),
                    status_code=resp_node.get("statusCode", 0),
                    body=resp_node.get("raw"),
                    length=resp_node.get("length", 0),
                )

            return request, response

        except Exception as e:
            logger.error("caido_get_request_response_failed", error=str(e))
            return None, None

    async def replay_request(
        self,
        request_id: str,
        modifications: dict[str, Any] | None = None,
    ) -> tuple[CaidoRequest | None, CaidoResponse | None]:
        """
        Replay a request, optionally with modifications.

        Args:
            request_id: The request ID to replay
            modifications: Optional modifications (headers, body, etc.)

        Returns:
            Tuple of (new_request, response)
        """
        # First, get the original request
        original_request, _ = await self.get_request_response(request_id)
        if not original_request:
            return None, None

        # Build the replay mutation
        mutation = """
        mutation ReplayRequest($requestId: ID!, $input: ReplayRequestInput) {
            replayRequest(requestId: $requestId, input: $input) {
                request {
                    id
                    method
                    host
                    path
                    raw
                    response {
                        id
                        statusCode
                        raw
                        length
                    }
                }
            }
        }
        """

        variables = {"requestId": request_id}
        if modifications:
            variables["input"] = modifications

        try:
            data = await self._execute_query(mutation, variables)
            result = data.get("replayRequest", {}).get("request")

            if not result:
                return None, None

            new_request = CaidoRequest(
                id=result.get("id", ""),
                method=result.get("method", ""),
                url=f"{result.get('host', '')}{result.get('path', '')}",
                host=result.get("host", ""),
                path=result.get("path", ""),
                body=result.get("raw"),
            )

            response = None
            if result.get("response"):
                resp = result["response"]
                response = CaidoResponse(
                    id=resp.get("id", ""),
                    status_code=resp.get("statusCode", 0),
                    body=resp.get("raw"),
                    length=resp.get("length", 0),
                )

            return new_request, response

        except Exception as e:
            logger.error("caido_replay_failed", error=str(e))
            return None, None

    async def search_traffic(
        self,
        httpql: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Search captured traffic using HTTPQL.

        HTTPQL examples:
        - req.method.eq:POST
        - req.path.cont:/api/
        - resp.status.eq:200
        - req.body.cont:password
        - resp.body.cont:error

        Args:
            httpql: HTTPQL query string
            limit: Maximum results

        Returns:
            List of matching request/response pairs
        """
        requests = await self.get_requests(limit=limit, httpql=httpql)

        results = []
        for req in requests:
            _, resp = await self.get_request_response(req.id)
            results.append({
                "request": req.to_dict(),
                "response": resp.to_dict() if resp else None,
            })

        return results


class CaidoTool(CoreTool):
    """
    Tool for interacting with Caido web security proxy.

    This tool allows the agent to:
    1. Check if Caido is running and accessible
    2. Get captured requests from the proxy
    3. Get specific request/response pairs
    4. Replay requests with modifications
    5. Search traffic using HTTPQL queries

    The agent should use Caido when:
    - Manual inspection of traffic is needed
    - Request/response analysis is required
    - Replaying modified requests for testing
    - Complex traffic pattern analysis
    """

    name = "caido"
    description = (
        "Interact with Caido web security proxy. Use this to inspect captured traffic, "
        "replay requests with modifications, and search through HTTP history using HTTPQL. "
        "Caido must be running locally for this tool to work."
    )
    category = ToolCategory.RECONNAISSANCE

    input_schema = {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["status", "get_requests", "get_request", "replay", "search"],
                "description": "Operation to perform",
            },
            "request_id": {
                "type": "string",
                "description": "Request ID for get_request and replay operations",
            },
            "host_filter": {
                "type": "string",
                "description": "Filter requests by host",
            },
            "httpql": {
                "type": "string",
                "description": (
                    "HTTPQL query for filtering. Examples: "
                    "'req.method.eq:POST', 'req.path.cont:/api/', "
                    "'resp.status.eq:200', 'req.body.cont:password'"
                ),
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of results (default: 20)",
                "default": 20,
            },
            "modifications": {
                "type": "object",
                "description": "Modifications for replay (headers, body, etc.)",
            },
        },
        "required": ["operation"],
    }

    examples = [
        ToolExample(
            description="Check if Caido is running",
            input={"operation": "status"},
        ),
        ToolExample(
            description="Get recent requests for a specific host",
            input={
                "operation": "get_requests",
                "host_filter": "target.com",
                "limit": 10,
            },
        ),
        ToolExample(
            description="Search for POST requests containing 'password'",
            input={
                "operation": "search",
                "httpql": "req.method.eq:POST AND req.body.cont:password",
            },
        ),
        ToolExample(
            description="Replay a request with modified headers",
            input={
                "operation": "replay",
                "request_id": "abc123",
                "modifications": {
                    "headers": {"X-Custom": "test"},
                },
            },
        ),
    ]

    def __init__(self, config: CaidoConfig | None = None):
        """Initialize the Caido tool."""
        super().__init__()
        self.client = CaidoClient(config)

    async def execute(
        self,
        operation: str,
        request_id: str | None = None,
        host_filter: str | None = None,
        httpql: str | None = None,
        limit: int = 20,
        modifications: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute a Caido operation."""

        if not HTTPX_AVAILABLE:
            return ToolResult(
                success=False,
                output="",
                error="httpx library not available. Install with: pip install httpx",
            )

        try:
            if operation == "status":
                return await self._check_status()

            elif operation == "get_requests":
                return await self._get_requests(
                    limit=limit,
                    host_filter=host_filter,
                    httpql=httpql,
                )

            elif operation == "get_request":
                if not request_id:
                    return ToolResult(
                        success=False,
                        output="",
                        error="request_id is required for get_request operation",
                    )
                return await self._get_request(request_id)

            elif operation == "replay":
                if not request_id:
                    return ToolResult(
                        success=False,
                        output="",
                        error="request_id is required for replay operation",
                    )
                return await self._replay_request(request_id, modifications)

            elif operation == "search":
                if not httpql:
                    return ToolResult(
                        success=False,
                        output="",
                        error="httpql query is required for search operation",
                    )
                return await self._search_traffic(httpql, limit)

            else:
                return ToolResult(
                    success=False,
                    output="",
                    error=f"Unknown operation: {operation}",
                )

        except ConnectionError as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e),
            )
        except Exception as e:
            logger.error("caido_operation_failed", operation=operation, error=str(e))
            return ToolResult(
                success=False,
                output="",
                error=f"Caido operation failed: {e}",
            )

    async def _check_status(self) -> ToolResult:
        """Check Caido connection status."""
        is_connected = await self.client.check_connection()

        if is_connected:
            output = (
                f"Caido Status: CONNECTED\n"
                f"Proxy URL: {self.client.config.proxy_url}\n"
                f"GraphQL API: {self.client.config.graphql_url}\n\n"
                f"You can route requests through Caido by setting proxy parameter in HTTP tool:\n"
                f'  http_request(url="...", proxy="{self.client.config.proxy_url}")'
            )
            return ToolResult(success=True, output=output)
        else:
            return ToolResult(
                success=False,
                output="",
                error=(
                    f"Cannot connect to Caido at {self.client.config.graphql_url}\n"
                    "Make sure Caido is running and accessible.\n"
                    "Set CAIDO_AUTH_TOKEN environment variable if authentication is required."
                ),
            )

    async def _get_requests(
        self,
        limit: int,
        host_filter: str | None,
        httpql: str | None,
    ) -> ToolResult:
        """Get captured requests."""
        requests = await self.client.get_requests(
            limit=limit,
            filter_host=host_filter,
            httpql=httpql,
        )

        if not requests:
            return ToolResult(
                success=True,
                output="No requests found matching the criteria.",
            )

        lines = [f"Found {len(requests)} requests:\n"]
        for i, req in enumerate(requests, 1):
            lines.append(f"{i}. [{req.method}] {req.url}")
            lines.append(f"   ID: {req.id}")
            if req.timestamp:
                lines.append(f"   Time: {req.timestamp}")
            lines.append("")

        return ToolResult(
            success=True,
            output="\n".join(lines),
            metadata={"requests": [r.to_dict() for r in requests]},
        )

    async def _get_request(self, request_id: str) -> ToolResult:
        """Get a specific request and response."""
        request, response = await self.client.get_request_response(request_id)

        if not request:
            return ToolResult(
                success=False,
                output="",
                error=f"Request not found: {request_id}",
            )

        lines = [
            "=== REQUEST ===",
            f"ID: {request.id}",
            f"Method: {request.method}",
            f"URL: {request.url}",
            "",
        ]

        if request.body:
            lines.append("Body:")
            lines.append(request.body[:2000])
            if len(request.body) > 2000:
                lines.append(f"... (truncated, {len(request.body)} total bytes)")

        if response:
            lines.extend([
                "",
                "=== RESPONSE ===",
                f"Status: {response.status_code}",
                f"Length: {response.length} bytes",
                "",
            ])
            if response.body:
                lines.append("Body:")
                lines.append(response.body[:2000])
                if len(response.body) > 2000:
                    lines.append(f"... (truncated, {len(response.body)} total bytes)")

        return ToolResult(
            success=True,
            output="\n".join(lines),
            metadata={
                "request": request.to_dict(),
                "response": response.to_dict() if response else None,
            },
        )

    async def _replay_request(
        self,
        request_id: str,
        modifications: dict[str, Any] | None,
    ) -> ToolResult:
        """Replay a request with optional modifications."""
        new_request, response = await self.client.replay_request(
            request_id, modifications
        )

        if not new_request:
            return ToolResult(
                success=False,
                output="",
                error=f"Failed to replay request: {request_id}",
            )

        lines = [
            "=== REPLAYED REQUEST ===",
            f"New ID: {new_request.id}",
            f"Method: {new_request.method}",
            f"URL: {new_request.url}",
        ]

        if modifications:
            lines.append(f"Modifications applied: {list(modifications.keys())}")

        if response:
            lines.extend([
                "",
                "=== RESPONSE ===",
                f"Status: {response.status_code}",
                f"Length: {response.length} bytes",
                "",
            ])
            if response.body:
                lines.append("Body (first 1000 chars):")
                lines.append(response.body[:1000])

        return ToolResult(
            success=True,
            output="\n".join(lines),
            metadata={
                "request": new_request.to_dict(),
                "response": response.to_dict() if response else None,
            },
        )

    async def _search_traffic(self, httpql: str, limit: int) -> ToolResult:
        """Search traffic using HTTPQL."""
        results = await self.client.search_traffic(httpql, limit)

        if not results:
            return ToolResult(
                success=True,
                output=f"No results found for query: {httpql}",
            )

        lines = [
            f"Found {len(results)} matches for: {httpql}\n",
        ]

        for i, item in enumerate(results, 1):
            req = item["request"]
            resp = item["response"]

            lines.append(f"{i}. [{req['method']}] {req['url']}")
            lines.append(f"   Request ID: {req['id']}")
            if resp:
                lines.append(f"   Response: {resp['status_code']} ({resp['length']} bytes)")
            lines.append("")

        return ToolResult(
            success=True,
            output="\n".join(lines),
            metadata={"results": results},
        )


# Singleton instance
_caido_tool: CaidoTool | None = None


def get_caido_tool() -> CaidoTool:
    """Get or create the Caido tool singleton."""
    global _caido_tool
    if _caido_tool is None:
        _caido_tool = CaidoTool()
    return _caido_tool
