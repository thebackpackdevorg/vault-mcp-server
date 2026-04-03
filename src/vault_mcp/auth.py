"""Simple in-memory OAuth 2.1 provider for single-user MCP server."""

import logging
import secrets
import time
import urllib.parse
import uuid

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Approval page HTML
# ---------------------------------------------------------------------------

_APPROVE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vault MCP — Authorize</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 420px; margin: 60px auto; padding: 0 20px; background: #0d1117; color: #c9d1d9; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 32px; text-align: center; }}
  h1 {{ font-size: 1.3rem; margin: 0 0 8px; color: #f0f6fc; }}
  .client {{ color: #58a6ff; font-weight: 600; }}
  p {{ color: #8b949e; font-size: 0.9rem; line-height: 1.5; }}
  .pin-field {{ width: 120px; padding: 8px 12px; border: 1px solid #30363d; border-radius: 6px; background: #0d1117; color: #f0f6fc; font-size: 1.1rem; text-align: center; letter-spacing: 4px; margin: 12px auto; display: block; }}
  .pin-field:focus {{ outline: none; border-color: #58a6ff; }}
  .pin-label {{ color: #8b949e; font-size: 0.8rem; margin-bottom: 4px; }}
  .btn {{ display: inline-block; padding: 10px 32px; border: none; border-radius: 6px; font-size: 1rem; cursor: pointer; margin: 8px; font-weight: 500; }}
  .approve {{ background: #238636; color: #fff; }}
  .approve:hover {{ background: #2ea043; }}
  .deny {{ background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }}
  .deny:hover {{ background: #30363d; }}
  .error {{ color: #f85149; font-size: 0.85rem; margin-top: 8px; }}
</style>
</head>
<body>
<div class="card">
  <h1>Authorize access</h1>
  <p>
    <span class="client">{client_id}</span><br>
    wants to access your <strong>Vault MCP Server</strong>
  </p>
  <form method="POST">
    <input type="hidden" name="request_id" value="{request_id}">
    {pin_field}
    <button class="btn approve" type="submit" name="action" value="approve">Approve</button>
    <button class="btn deny" type="submit" name="action" value="deny">Deny</button>
  </form>
  {error_msg}
</div>
</body>
</html>"""

_ERROR_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vault MCP — Error</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 420px; margin: 60px auto; padding: 0 20px; background: #0d1117; color: #c9d1d9; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 32px; text-align: center; }}
  h1 {{ font-size: 1.3rem; color: #f85149; }}
  p {{ color: #8b949e; }}
</style>
</head>
<body>
<div class="card">
  <h1>Error</h1>
  <p>{message}</p>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# OAuth Provider
# ---------------------------------------------------------------------------

class SimpleOAuthProvider:
    """In-memory OAuth 2.1 provider for a personal, single-user MCP server.

    Stores clients, authorization codes, and tokens in memory.
    Tokens survive until server restart (acceptable for personal use).
    """

    def __init__(self, issuer_url: str, pin: str = ""):
        self.issuer_url = issuer_url.rstrip("/")
        self.pin = pin  # empty = no PIN required
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._auth_codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}
        self._pending: dict[str, dict] = {}

        # Permanent token for Cloudflare Access bypass
        self._cf_token = secrets.token_hex(32)
        self._access_tokens[self._cf_token] = AccessToken(
            token=self._cf_token,
            client_id="cloudflare-access",
            scopes=[],
            expires_at=None,
        )
        logger.info("OAuth provider initialized (in-memory, single-user)")

    @property
    def cf_bypass_token(self) -> str:
        return self._cf_token

    # -- Client management --------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info
        logger.info("Registered OAuth client: %s", client_info.client_id)

    # -- Authorization flow -------------------------------------------------

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        request_id = str(uuid.uuid4())
        self._pending[request_id] = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "state": params.state,
            "scopes": params.scopes or [],
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "resource": params.resource,
        }
        logger.info("Authorization request %s for client %s", request_id, client.client_id)
        return f"{self.issuer_url}/oauth/approve?request_id={request_id}"

    # -- Authorization code -------------------------------------------------

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        code = self._auth_codes.get(authorization_code)
        if not code:
            return None
        if code.client_id != client.client_id:
            return None
        if code.expires_at < time.time():
            self._auth_codes.pop(authorization_code, None)
            return None
        return code

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        self._auth_codes.pop(authorization_code.code, None)

        access_token = secrets.token_hex(32)
        refresh_token = secrets.token_hex(32)
        expires_in = 3600 * 24 * 30  # 30 days

        self._access_tokens[access_token] = AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + expires_in,
            resource=authorization_code.resource,
        )
        self._refresh_tokens[refresh_token] = RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
        )

        logger.info("Issued tokens for client %s (expires in %dd)", client.client_id, expires_in // 86400)
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=refresh_token,
        )

    # -- Refresh token ------------------------------------------------------

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        token = self._refresh_tokens.get(refresh_token)
        if token and token.client_id == client.client_id:
            return token
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        self._refresh_tokens.pop(refresh_token.token, None)

        access_token = secrets.token_hex(32)
        new_refresh = secrets.token_hex(32)
        expires_in = 3600 * 24 * 30
        use_scopes = scopes or refresh_token.scopes

        self._access_tokens[access_token] = AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=use_scopes,
            expires_at=int(time.time()) + expires_in,
        )
        self._refresh_tokens[new_refresh] = RefreshToken(
            token=new_refresh,
            client_id=client.client_id,
            scopes=use_scopes,
        )

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=new_refresh,
        )

    # -- Access token verification ------------------------------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        access_token = self._access_tokens.get(token)
        if not access_token:
            return None
        if access_token.expires_at and access_token.expires_at < int(time.time()):
            self._access_tokens.pop(token, None)
            return None
        return access_token

    # -- Revocation ---------------------------------------------------------

    async def revoke_token(
        self,
        token: AccessToken | RefreshToken,
    ) -> None:
        self._access_tokens.pop(token.token, None)
        self._refresh_tokens.pop(token.token, None)

    # -- Approval page helpers ----------------------------------------------

    def approve_request(self, request_id: str) -> str | None:
        """Approve a pending authorization. Returns redirect URL or None."""
        pending = self._pending.pop(request_id, None)
        if not pending:
            return None

        code = secrets.token_hex(32)
        self._auth_codes[code] = AuthorizationCode(
            code=code,
            client_id=pending["client_id"],
            redirect_uri=pending["redirect_uri"],
            code_challenge=pending["code_challenge"],
            state=pending["state"],
            scopes=pending["scopes"],
            expires_at=time.time() + 300,
            redirect_uri_provided_explicitly=pending["redirect_uri_provided_explicitly"],
            resource=pending.get("resource"),
        )

        redirect_uri = pending["redirect_uri"]
        params = {"code": code}
        if pending["state"]:
            params["state"] = pending["state"]

        separator = "&" if "?" in redirect_uri else "?"
        return redirect_uri + separator + urllib.parse.urlencode(params)

    def deny_request(self, request_id: str) -> str | None:
        """Deny a pending authorization. Returns redirect URL or None."""
        pending = self._pending.pop(request_id, None)
        if not pending:
            return None

        redirect_uri = pending["redirect_uri"]
        params = {"error": "access_denied", "error_description": "User denied the request"}
        if pending["state"]:
            params["state"] = pending["state"]

        separator = "&" if "?" in redirect_uri else "?"
        return redirect_uri + separator + urllib.parse.urlencode(params)


# ---------------------------------------------------------------------------
# Starlette routes for the approval page
# ---------------------------------------------------------------------------

def _render_approve_page(
    client_id: str, request_id: str, provider: SimpleOAuthProvider, error: str = "",
) -> str:
    pin_field = ""
    if provider.pin:
        pin_field = (
            '<label class="pin-label">PIN</label>'
            '<input class="pin-field" type="password" name="pin" '
            'maxlength="10" autocomplete="off" required>'
        )
    error_msg = f'<p class="error">{error}</p>' if error else ""
    return _APPROVE_HTML.format(
        client_id=client_id,
        request_id=request_id,
        pin_field=pin_field,
        error_msg=error_msg,
    )


def create_approve_routes(provider: SimpleOAuthProvider) -> list:
    """Create Starlette routes for the OAuth approval page."""

    async def approve_get(request: Request) -> HTMLResponse:
        request_id = request.query_params.get("request_id", "")
        pending = provider._pending.get(request_id)
        if not pending:
            return HTMLResponse(
                _ERROR_HTML.format(message="Invalid or expired authorization request."),
                status_code=400,
            )
        return HTMLResponse(
            _render_approve_page(pending["client_id"], request_id, provider)
        )

    async def approve_post(request: Request) -> HTMLResponse | RedirectResponse:
        form = await request.form()
        request_id = str(form.get("request_id", ""))
        action = str(form.get("action", ""))

        # PIN validation
        if action == "approve" and provider.pin:
            submitted_pin = str(form.get("pin", ""))
            if submitted_pin != provider.pin:
                pending = provider._pending.get(request_id)
                if not pending:
                    return HTMLResponse(
                        _ERROR_HTML.format(message="Invalid or expired authorization request."),
                        status_code=400,
                    )
                return HTMLResponse(
                    _render_approve_page(
                        pending["client_id"], request_id, provider, error="Wrong PIN"
                    )
                )

        if action == "approve":
            redirect_url = provider.approve_request(request_id)
        else:
            redirect_url = provider.deny_request(request_id)

        if not redirect_url:
            return HTMLResponse(
                _ERROR_HTML.format(message="Invalid or expired authorization request."),
                status_code=400,
            )

        return RedirectResponse(url=redirect_url, status_code=302)

    from starlette.routing import Route

    return [
        Route("/oauth/approve", approve_get, methods=["GET"]),
        Route("/oauth/approve", approve_post, methods=["POST"]),
    ]


# ---------------------------------------------------------------------------
# Cloudflare Access bypass middleware
# ---------------------------------------------------------------------------

class CfAccessBypassMiddleware:
    """Inject a Bearer token for requests already authenticated by Cloudflare Access.

    When a request arrives through the CF Access-protected domain, Cloudflare
    injects a Cf-Access-Jwt-Assertion header. This middleware detects it and
    injects a permanent Bearer token so the OAuth middleware accepts the request.
    """

    def __init__(self, app, bypass_token: str):
        self.app = app
        self.bypass_token = bypass_token

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            cf_jwt = headers.get(b"cf-access-jwt-assertion")
            if cf_jwt:
                # Request already authenticated by Cloudflare Access — inject Bearer token
                new_headers = [
                    (k, v) for k, v in scope["headers"]
                    if k.lower() != b"authorization"
                ]
                new_headers.append(
                    (b"authorization", f"Bearer {self.bypass_token}".encode())
                )
                scope = dict(scope, headers=new_headers)

        await self.app(scope, receive, send)
