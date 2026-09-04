"""FastAPI application for the Sentinel control-plane skeleton."""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response

from .authn import AuthError, TokenValidator
from .rbac import Forbidden, require
from .store import CloudStore

STARTED = time.time()


class Counters:
    def __init__(self):
        self.lock = __import__("threading").Lock()
        self.values: Dict[str, int] = {}

    def inc(self, name: str, n: int = 1) -> None:
        with self.lock:
            self.values[name] = self.values.get(name, 0) + n

    def render(self) -> str:
        with self.lock:
            items = sorted(self.values.items())
        lines = ["# HELP sentinel_cloud_total Control-plane counters.",
                 "# TYPE sentinel_cloud_total counter"]
        for name, val in items:
            lines.append(f"sentinel_cloud_total{{kind=\"{name}\"}} {val}")
        lines.append(f"sentinel_cloud_uptime_seconds {int(time.time() - STARTED)}")
        return "\n".join(lines) + "\n"


def build_app(validator: TokenValidator, store: CloudStore,
              counters: Optional[Counters] = None,
              hs_secret: Optional[str] = None) -> FastAPI:
    app = FastAPI(title="Sentinel Cloud", version="0.4.0-skeleton")
    counters = counters or Counters()

    # ------------------------------------------------------------- authn
    def authenticate(authorization: str = Header(default="")) -> dict:
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing bearer token")
        try:
            claims = validator.validate(authorization[7:])
        except AuthError as e:
            raise HTTPException(e.status, str(e))
        store.ensure_tenant(claims["org_id"])
        return claims

    def guard(capability: str):
        def dep(claims: dict = Depends(authenticate)) -> dict:
            try:
                require(capability, claims)
            except Forbidden as e:
                raise HTTPException(403, str(e))
            return claims
        return dep

    # ------------------------------------------------------------ routes
    @app.post("/v1/workflows/{workflow}/bundles")
    def upload_bundle(workflow: str, request: Request,
                      claims: dict = Depends(guard("bundles.upload"))):
        import json as _json

        from ..bundle.bundle import BundleError, PolicyBundle
        try:
            raw = _json.loads(request.scope.get("_body") or b"{}")
        except Exception:
            raw = None
        if not isinstance(raw, dict) or "manifest" not in raw:
            raise HTTPException(
                422, "body must be a signed bundle JSON object")
        try:
            PolicyBundle.from_dict(raw)  # structural check; anchor trust is client-side
        except BundleError as e:
            raise HTTPException(422, f"invalid bundle structure: {e}")
        out = store.put_bundle(claims["org_id"], workflow, raw)
        counters.inc("bundles_uploaded")
        return out

    @app.get("/v1/workflows/{workflow}/bundle")
    def get_bundle(workflow: str, claims: dict = Depends(guard("bundles.read"))):
        b = store.latest_bundle(claims["org_id"], workflow)
        if not b:
            raise HTTPException(404, f"no bundle for workflow {workflow!r} "
                                     f"in org {claims['org_id']}")
        counters.inc("bundles_served")
        return b

    @app.post("/v1/receipts:batch")
    def receipts_batch(request: Request,
                       claims: dict = Depends(guard("receipts.upload"))):
        import json as _json

        try:
            body = _json.loads(request.scope.get("_body") or b"{}")
        except Exception:
            raise HTTPException(400, "unreadable batch")
        receipts = body.get("receipts") if isinstance(body, dict) else None
        if not isinstance(receipts, list):
            raise HTTPException(422, "expected {\"receipts\": [...]}")
        out = store.put_receipts(claims["org_id"], receipts)
        counters.inc("receipts_accepted", out["accepted"])
        counters.inc("receipts_duplicates", out["duplicates"])
        return out

    @app.post("/v1/webhooks")
    def add_webhook(request: Request,
                    claims: dict = Depends(guard("webhooks.write"))):
        import json as _json

        try:
            body = _json.loads(request.scope.get("_body") or b"{}")
        except Exception:
            raise HTTPException(400, "unreadable body")
        url, secret = body.get("url"), body.get("secret")
        if not url or not secret:
            raise HTTPException(422, "url and secret required")
        return store.add_webhook(claims["org_id"], str(url), str(secret))

    @app.get("/v1/webhooks")
    def list_webhooks(claims: dict = Depends(guard("webhooks.read"))):
        return store.list_webhooks(claims["org_id"])

    @app.get("/v1/admin/receipts")
    def admin_receipts(limit: int = 100,
                       claims: dict = Depends(guard("receipts.read"))):
        return store.list_receipts(claims["org_id"], limit=min(limit, 1000))

    @app.get("/v1/admin/overview")
    def admin_overview(claims: dict = Depends(guard("admin.overview"))):
        return {"org_id": claims["org_id"], **store.overview(claims["org_id"])}

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    # ----------------------------------------------------------- metrics
    @app.get("/metrics")
    def metrics():
        return Response(counters.render(), media_type="text/plain")

    # ------------------------------------------------- body capture hack
    @app.middleware("http")
    async def _capture_body(request: Request, call_next):
        if request.method in ("POST", "PUT"):
            request.scope["_body"] = await request.body()
        return await call_next(request)

    return app
