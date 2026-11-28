"""Core #2 decision-receipt registrar — HTTP route tests (synthetic, offline).

Mounts the router on a bare FastAPI app with an injected enabled service and synthetic
adapters. A middleware stamps a synthetic verified principal onto request.state, standing in
for the trusted interactive-provenance adapter (which denies in production until approved).
No production storage, board DB, or business action is touched.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.decision_receipts import (
    DecisionReceiptService, ReceiptRepository, Scope, RawPrincipal, VerifiedDecision,
)
from plugins.kanban.dashboard.decision_registrar import create_router

TENANT, PROFILE, BOARD, CARD = "t1", "p1", "default", "card-1"
ACTION, REV = "merge", "rev-1"
NOW = 1_000_000.0
P1 = RawPrincipal("https://issuer.example", "nous", "user-1")


def scope(card=CARD, rev=REV):
    return Scope(TENANT, PROFILE, BOARD, card, ACTION, rev)


class FakeClock:
    def __init__(self):
        self._t = NOW

    def now(self):
        return self._t


class FakeProvenance:
    def prove(self, request_state):
        from gateway.decision_receipts import RegistrarDeny
        p = getattr(request_state, "principal", None)
        if p is None:
            raise RegistrarDeny(403, "interactive_provenance_unavailable")
        return p


class FakeEntitlement:
    def __init__(self, keys):
        self.keys = set(keys)

    def entitled(self, principal, scope):
        return (principal.key(), scope.as_tuple()) in self.keys


class FakeVerifier:
    def __init__(self, table):
        self.table = table

    def verify(self, reference, expected):
        from gateway.decision_receipts import RegistrarDeny
        vd = self.table.get(reference)
        if vd is None:
            raise RegistrarDeny(403, "decision_verifier_unavailable")
        return vd


class FakeCards:
    def __init__(self, revisions):
        self.revisions = revisions

    def current_revision(self, scope):
        return self.revisions.get(scope.as_tuple())


class FakeCsrf:
    def __init__(self, ok=True):
        self.ok = ok

    def validate(self, request_state, principal):
        return self.ok


def vd():
    return VerifiedDecision(
        decision_issuer="https://issuer.example", decision_id="dec-1", original_actor="owner",
        tenant=TENANT, profile=PROFILE, board=BOARD, card_id=CARD, case_action=ACTION,
        card_revision=REV, verbatim_digest="d" * 64, evidence_ref="ev-1",
        evidence_digest="e" * 64, verified_at=NOW - 10, expires_at=NOW + 3600)


def build_app(*, csrf=True, enabled=True):
    tmp = tempfile.mkdtemp()
    repo = ReceiptRepository(str(Path(tmp) / "registrar.sqlite3"))
    keys = [(P1.key(), scope().as_tuple())]
    svc = DecisionReceiptService(
        repo, provenance=FakeProvenance(), entitlement=FakeEntitlement(keys),
        verifier=FakeVerifier({"ref-1": vd()}), cards=FakeCards({scope().as_tuple(): REV}),
        csrf=FakeCsrf(csrf), clock=FakeClock(), enabled=enabled)
    app = FastAPI()

    @app.middleware("http")
    async def _stamp_principal(request, call_next):
        request.state.principal = P1
        return await call_next(request)

    app.include_router(create_router(svc))
    return TestClient(app), svc


def body(card=CARD, rev=REV, **extra):
    b = {"tenant": TENANT, "profile": PROFILE, "board": BOARD, "card_id": card,
         "case_action": ACTION, "card_revision": rev, "reference": "ref-1"}
    b.update(extra)
    return b


def qparams(card=CARD, rev=REV):
    return {"tenant": TENANT, "profile": PROFILE, "board": BOARD, "card_id": card,
            "case_action": ACTION, "card_revision": rev}


def test_register_route_success():
    client, _ = build_app()
    r = client.post("/decision-registrations", json=body())
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["created"] is True and data["status"] == "active" and data["receipt_id"]


def test_register_body_forgery_ignored():
    client, _ = build_app()
    r = client.post("/decision-registrations",
                    json=body(decision_issuer="evil", author="evil", role="owner",
                              original_actor="evil", evidence_digest="f" * 64))
    assert r.status_code == 200, r.text
    rid = r.json()["receipt_id"]
    got = client.get(f"/decision-registrations/{rid}", params=qparams())
    assert got.status_code == 200
    # The stored issuer comes ONLY from the verifier, never the forged body field.
    assert got.json()["decision_issuer"] == "https://issuer.example"


def test_register_replay_same_receipt():
    client, _ = build_app()
    a = client.post("/decision-registrations", json=body()).json()
    b = client.post("/decision-registrations", json=body()).json()
    assert a["receipt_id"] == b["receipt_id"] and b["created"] is False


def test_read_route_no_store():
    client, _ = build_app()
    rid = client.post("/decision-registrations", json=body()).json()["receipt_id"]
    r = client.get(f"/decision-registrations/{rid}", params=qparams())
    assert r.status_code == 200
    assert r.headers.get("cache-control") == "no-store"
    assert r.json()["status"] == "active"


def test_read_wrong_scope_uniform_404():
    client, _ = build_app()
    rid = client.post("/decision-registrations", json=body()).json()["receipt_id"]
    r = client.get(f"/decision-registrations/{rid}", params=qparams(card="other"))
    assert r.status_code == 404


def test_no_delete_route():
    client, _ = build_app()
    rid = client.post("/decision-registrations", json=body()).json()["receipt_id"]
    assert client.delete(f"/decision-registrations/{rid}").status_code == 405


def test_no_list_route():
    client, _ = build_app()
    assert client.get("/decision-registrations").status_code == 405


def test_disabled_default_denies_all_routes():
    client, _ = build_app(enabled=False)
    assert client.post("/decision-registrations", json=body()).status_code == 404
    assert client.get("/decision-registrations/x", params=qparams()).status_code == 404


def test_csrf_failure_route_403():
    client, _ = build_app(csrf=False)
    assert client.post("/decision-registrations", json=body()).status_code == 403


def test_revocation_route():
    client, _ = build_app()
    rid = client.post("/decision-registrations", json=body()).json()["receipt_id"]
    r = client.post(f"/decision-registrations/{rid}/revocations", json=body())
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "revoked"
    assert client.get(f"/decision-registrations/{rid}", params=qparams()).json()["status"] == "revoked"


if __name__ == "__main__":
    import sys
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    failed = 0
    for n, f in fns:
        try:
            f()
            print("PASS", n)
        except Exception as e:  # noqa: BLE001
            failed += 1
            print("FAIL", n, repr(e))
    print(f"{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)