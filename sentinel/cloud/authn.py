"""Authentication for the control plane.

Production: OIDC via the customer's identity provider - we validate JWTs
against the issuer's JWKS and NEVER own passwords or MFA.
Skeleton/offline: HS256 dev tokens signed with a locally configured secret.

Tenant identity comes ONLY from verified claims (``org_id``). Anything a
client sends in a request body cannot change tenancy.

Deployment mapping note: real IdPs carry org membership in custom claims
(e.g. ``org_id``, WorkOS organization). Map claim -> Sentinel org_id in
configuration, not in code paths.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import jwt


class AuthError(Exception):
    def __init__(self, msg: str, status: int = 401):
        super().__init__(msg)
        self.status = status


@dataclass
class TokenValidator:
    """Validates either OIDC RS256 tokens (issuer + JWKS) or dev HS256."""

    issuer: str = "https://sentinel.local"
    audience: str = "sentinel-cloud"
    hs_secret: Optional[str] = None
    jwks_url: Optional[str] = None
    leeway_s: int = 5
    _jwks_cache: dict = field(default_factory=dict, init=False)
    _jwks_ts: float = field(default=0.0, init=False)

    # ---------------------------------------------------------------- keys
    def _jwks(self) -> dict:
        if not self.jwks_url:
            raise AuthError("no JWKS configured")
        now = time.time()
        if not self._jwks_cache or now - self._jwks_ts > 300:
            import urllib.request

            with urllib.request.urlopen(self.jwks_url, timeout=10) as r:
                self._jwks_cache = json.loads(r.read().decode())
            self._jwks_ts = now
        return self._jwks_cache

    # ------------------------------------------------------------ validate
    def validate(self, token: str) -> Dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as e:
            raise AuthError(f"malformed token: {e}")

        alg = header.get("alg")
        kwargs: Dict[str, Any] = {
            "algorithms": [alg],
            "audience": self.audience,
            "issuer": self.issuer,
            "leeway": self.leeway_s,
        }
        try:
            if alg == "HS256":
                if not self.hs_secret:
                    raise AuthError("dev-token auth disabled on this deployment")
                claims = jwt.decode(token, self.hs_secret, **kwargs)
            elif alg == "RS256":
                kid = header.get("kid")
                key = jwt.PyJWK.from_dict(
                    self._find_jwk(kid)).key
                claims = jwt.decode(token, key, **kwargs)
            else:
                raise AuthError(f"unsupported alg {alg!r}")
        except jwt.ExpiredSignatureError as e:
            raise AuthError("token expired") from e
        except jwt.InvalidTokenError as e:
            raise AuthError(f"invalid token: {e}") from e

        org_id = claims.get("org_id")
        role = claims.get("role")
        sub = claims.get("sub")
        if not org_id or not sub or not role:
            raise AuthError("token missing required claims: sub/org_id/role")
        return {"sub": str(sub), "org_id": str(org_id),
                "role": str(role), "exp": claims.get("exp")}

    def _find_jwk(self, kid: Optional[str]) -> dict:
        keys = self._jwks().get("keys", [])
        for k in keys:
            if k.get("kid") == kid:
                return k
        raise AuthError(f"unknown signing key kid={kid!r}")


# ------------------------------------------------------------- dev tokens
def create_dev_token(secret: str, *, org_id: str, sub: str, role: str,
                     ttl_s: int = 3600, issuer: str = "https://sentinel.local",
                     audience: str = "sentinel-cloud",
                     now: Optional[float] = None) -> str:
    payload = {
        "iss": issuer, "aud": audience,
        "iat": int(now if now is not None else time.time()),
        "exp": int((now if now is not None else time.time()) + ttl_s),
        "sub": sub, "org_id": org_id, "role": role,
    }
    return jwt.encode(payload, secret, algorithm="HS256")
