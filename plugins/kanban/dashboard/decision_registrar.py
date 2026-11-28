"""Core #2 decision-receipt registrar — HTTP routes (mount-only consumer).

Three routes under the kanban plugin namespace:
    POST /decision-registrations
    POST /decision-registrations/{receipt_id}/revocations
    GET  /decision-registrations/{receipt_id}   (Cache-Control: no-store)

No DELETE and no list/collection endpoint. Request bodies carry ONLY the explicit scope
(tenant/profile/board/card/case-action/revision) plus an opaque original-decision reference;
they NEVER carry author, role, principal, decision issuer/id/actor, validity or evidence —
those come exclusively from the trusted verifier. Admission (interactive OAuth provenance,
CSRF, current raw-identity entitlement) happens server-side in the service.

The default service is DISABLED with deny adapters and no production storage, so importing
and mounting this router grants nothing and changes no behavior. Enabling it requires the
separately-approved release prerequisites (trusted adapters + protected storage/reader).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel

from gateway.decision_receipts import (
    DecisionReceiptService, RegistrarDeny, Scope, disabled_service,
)


class _ScopeBody(BaseModel):
    tenant: str
    profile: str
    board: str
    card_id: str
    case_action: str
    card_revision: str


class RegisterBody(_ScopeBody):
    reference: str  # opaque original-decision reference resolved by the trusted verifier


class RevokeBody(_ScopeBody):
    reference: str  # opaque revocation-decision reference


def _scope(body: _ScopeBody) -> Scope:
    return Scope(body.tenant, body.profile, body.board, body.card_id,
                 body.case_action, body.card_revision)


class _NoStoreRoute(APIRoute):
    """Attach Cache-Control: no-store to EVERY registrar response — success, dependency
    denial (404), validation error (422) and uncaught error (500). The endpoint function is
    never reached for the disabled-dependency 404 or a validation 422, so a per-response
    header inside the handler would miss them; this route wrapper covers all outcomes so a
    shared cache can never pin a denial or existence signal."""

    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request: Request):
            try:
                response = await original(request)
            except HTTPException as exc:
                exc.headers = {**(exc.headers or {}), "Cache-Control": "no-store"}
                raise
            except RequestValidationError as exc:
                return JSONResponse(status_code=422,
                                    content={"detail": jsonable_encoder(exc.errors())},
                                    headers={"Cache-Control": "no-store"})
            except Exception:
                return JSONResponse(status_code=500, content={"detail": "internal_error"},
                                    headers={"Cache-Control": "no-store"})
            response.headers["Cache-Control"] = "no-store"
            return response

        return handler


def create_router(service: DecisionReceiptService | None = None) -> APIRouter:
    # Default is DISABLED with deny adapters and no production storage (grants nothing).
    service = service if service is not None else disabled_service()
    router = APIRouter(route_class=_NoStoreRoute)

    def _enabled():
        # Runs as a dependency BEFORE FastAPI validates the body/query, so a disabled
        # registrar returns a uniform 404 even for a malformed request (no 422 existence leak).
        try:
            service._require_enabled()
        except RegistrarDeny as exc:
            raise HTTPException(status_code=exc.status, detail=exc.code)

    def _guard(fn):
        try:
            return fn()
        except RegistrarDeny as exc:
            raise HTTPException(status_code=exc.status, detail=exc.code)

    @router.post("/decision-registrations", dependencies=[Depends(_enabled)])
    def register(body: RegisterBody, request: Request):
        scope = _scope(body)
        return _guard(lambda: service.register(request.state, reference=body.reference, scope=scope))

    @router.post("/decision-registrations/{receipt_id}/revocations", dependencies=[Depends(_enabled)])
    def revoke(receipt_id: str, body: RevokeBody, request: Request):
        scope = _scope(body)
        return _guard(lambda: service.revoke(request.state, receipt_id=receipt_id,
                                             reference=body.reference, expected=scope))

    @router.get("/decision-registrations/{receipt_id}", dependencies=[Depends(_enabled)])
    def read(receipt_id: str, request: Request,
             tenant: str, profile: str, board: str, card_id: str,
             case_action: str, card_revision: str):
        # Query params carry only the expected scope; the reader principal is proven and
        # entitlement-checked server-side. Mismatch/missing returns a uniform 404. no-store
        # on every outcome (incl. errors) is applied by _NoStoreRoute.
        scope = Scope(tenant, profile, board, card_id, case_action, card_revision)
        return _guard(lambda: service.read(request.state, receipt_id=receipt_id, expected=scope))

    return router