"""Core #2 decision-receipt registrar — service/storage tests (synthetic, offline).

Every positive path injects synthetic evidence through the typed adapters; the production
defaults deny. Storage is a private temporary SQLite file, never the board DB or production
storage. No card mutation, dispatch, or business action is exercised or imported.
"""
from __future__ import annotations

import threading
from pathlib import Path

import contextlib
import tempfile


class _Caught:
    value = None


@contextlib.contextmanager
def raises(exc):
    c = _Caught()
    try:
        yield c
    except exc as e:
        c.value = e
    else:
        raise AssertionError(f"{exc.__name__} not raised")

from gateway.decision_receipts import (
    DecisionReceiptService, ReceiptRepository, RegistrarDeny, Scope, RawPrincipal,
    VerifiedDecision, VerifiedRevocation, DenyProvenance, DenyEntitlement, DenyVerifier,
    DenyRevocationVerifier, DenyCardResolver, DenyCsrf,
)

TENANT, PROFILE, BOARD, CARD = "t1", "p1", "default", "card-1"
ACTION, REV = "merge", "rev-1"
NOW = 1_000_000.0


def scope(rev=REV, card=CARD, action=ACTION, board=BOARD):
    return Scope(TENANT, PROFILE, board, card, action, rev)


class FakeClock:
    def __init__(self, now=NOW):
        self._t = now

    def now(self):
        return self._t


class FakeProvenance:
    """Reads a synthetic principal off request_state; denies when absent (fail closed)."""
    def prove(self, request_state):
        p = getattr(request_state, "principal", None)
        if p is None:
            raise RegistrarDeny(403, "interactive_provenance_unavailable")
        return p


class FakeEntitlement:
    """Entitled only for explicitly-listed RAW identity keys + scope tuples."""
    def __init__(self, keys):
        self.keys = set(keys)

    def entitled(self, principal, scope):
        return (principal.key(), scope.as_tuple()) in self.keys


class FakeVerifier:
    def __init__(self, table):
        self.table = table  # reference -> VerifiedDecision

    def verify(self, reference, expected):
        vd = self.table.get(reference)
        if vd is None:
            raise RegistrarDeny(403, "decision_verifier_unavailable")
        return vd


class FakeRevocationVerifier:
    """reference -> {rev_decision_id, rev_issuer?, target}. target=='ECHO' means the verified
    revocation names the receipt being revoked (happy path); a fixed target exercises the
    target-mismatch denial. Revocation decisions are distinct from approval decisions."""
    def __init__(self, table):
        self.table = table

    def verify_revocation(self, reference, receipt_id, expected):
        t = self.table.get(reference)
        if t is None:
            raise RegistrarDeny(403, "revocation_verifier_unavailable")
        target = receipt_id if t.get("target") == "ECHO" else t["target"]
        return VerifiedRevocation(
            rev_issuer=t.get("rev_issuer", "https://issuer.example"),
            rev_decision_id=t["rev_decision_id"], target_receipt_id=target,
            tenant=TENANT, profile=PROFILE, board=expected.board, card_id=expected.card_id,
            case_action=expected.case_action, card_revision=expected.card_revision,
            verbatim_digest=t.get("verbatim_digest", "d" * 64),
            evidence_ref=t.get("evidence_ref", "ev-r"),
            evidence_digest=t.get("evidence_digest", "e" * 64),
            verified_at=t.get("verified_at", NOW - 10), expires_at=t.get("expires_at", NOW + 3600))


class FakeCards:
    def __init__(self, revisions):
        self.revisions = revisions  # scope tuple -> current revision

    def current_revision(self, scope):
        return self.revisions.get(scope.as_tuple())


class FakeCsrf:
    def __init__(self, ok=True):
        self.ok = ok

    def validate(self, request_state, principal):
        return self.ok


class State:
    def __init__(self, principal):
        self.principal = principal


P1 = RawPrincipal("https://issuer.example", "nous", "user-1")
P2 = RawPrincipal("https://issuer.example", "nous", "user-2")  # collapses to same owner subject


def vd(reference="ref-1", issuer="https://issuer.example", decision_id="dec-1",
       digest="d" * 64, rev=REV, card=CARD, action=ACTION, board=BOARD,
       verified_at=NOW - 10, expires_at=NOW + 3600,
       evidence_ref="ev-1", evidence_digest="e" * 64):
    return VerifiedDecision(
        decision_issuer=issuer, decision_id=decision_id, original_actor="owner",
        tenant=TENANT, profile=PROFILE, board=board, card_id=card, case_action=action,
        card_revision=rev, verbatim_digest=digest, evidence_ref=evidence_ref,
        evidence_digest=evidence_digest, verified_at=verified_at, expires_at=expires_at)


def build(tmp_path, *, principals=(P1,), refs=None, rev_refs=None, cards=None, csrf=True,
          enabled=True, clock=None, adapters=None):
    repo = ReceiptRepository(str(Path(tmp_path) / "registrar.sqlite3"))
    refs = refs if refs is not None else {"ref-1": vd()}
    rev_refs = rev_refs if rev_refs is not None else {
        "rev-ref-1": {"rev_decision_id": "rev-dec-1", "target": "ECHO"}}
    cards = cards if cards is not None else {scope().as_tuple(): REV}
    keys = [(p.key(), scope().as_tuple()) for p in principals]
    kw = dict(provenance=FakeProvenance(), entitlement=FakeEntitlement(keys),
              verifier=FakeVerifier(refs), revocation_verifier=FakeRevocationVerifier(rev_refs),
              cards=FakeCards(cards), csrf=FakeCsrf(csrf),
              clock=clock or FakeClock(), enabled=enabled)
    if adapters:
        kw.update(adapters)
    return DecisionReceiptService(repo, **kw), repo


def deny_status(fn):
    with raises(RegistrarDeny) as ei:
        fn()
    return ei.value.status


# --------------------------------------------------------------------------- #
# Disabled / default-deny.
# --------------------------------------------------------------------------- #
def test_disabled_denies_every_operation():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path, enabled=False)
    st = State(P1)
    assert deny_status(lambda: svc.register(st, reference="ref-1", scope=scope())) == 404
    assert deny_status(lambda: svc.revoke(st, receipt_id="x", reference="ref-1", expected=scope())) == 404
    assert deny_status(lambda: svc.read(st, receipt_id="x", expected=scope())) == 404


def test_default_deny_adapters_grant_nothing():
    tmp_path = tempfile.mkdtemp()
    repo = ReceiptRepository(str(Path(tmp_path) / "r.sqlite3"))
    svc = DecisionReceiptService(repo, provenance=DenyProvenance(), entitlement=DenyEntitlement(),
                                 verifier=DenyVerifier(), revocation_verifier=DenyRevocationVerifier(),
                                 cards=DenyCardResolver(), csrf=DenyCsrf(),
                                 enabled=True)
    assert deny_status(lambda: svc.register(State(P1), reference="ref-1", scope=scope())) == 403


# --------------------------------------------------------------------------- #
# Registration happy path + replay + conflict.
# --------------------------------------------------------------------------- #
def test_register_success_active():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path)
    out = svc.register(State(P1), reference="ref-1", scope=scope())
    assert out["created"] is True and out["status"] == "active" and out["receipt_id"]


def test_register_identical_replay_returns_original():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path)
    a = svc.register(State(P1), reference="ref-1", scope=scope())
    b = svc.register(State(P1), reference="ref-1", scope=scope())
    assert a["receipt_id"] == b["receipt_id"] and b["created"] is False


def test_register_same_key_different_binding_conflicts():
    tmp_path = tempfile.mkdtemp()
    # Same (issuer, decision_id) but a different verbatim digest => different immutable binding.
    refs = {"ref-1": vd(digest="a" * 64), "ref-2": vd(digest="b" * 64)}
    svc, _ = build(tmp_path, refs=refs)
    svc.register(State(P1), reference="ref-1", scope=scope())
    assert deny_status(lambda: svc.register(State(P1), reference="ref-2", scope=scope())) == 409


# --------------------------------------------------------------------------- #
# Raw-identity keying: two principals that collapse to the same owner subject do
# NOT share entitlement. Worker role names never entitle.
# --------------------------------------------------------------------------- #
def test_two_collapsed_principals_do_not_share_entitlement():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path, principals=(P1,))  # only P1 entitled
    assert svc.register(State(P1), reference="ref-1", scope=scope())["created"] is True
    # P2 has a different raw user_id but would collapse to the same host-owner subject.
    assert deny_status(lambda: svc.register(State(P2), reference="ref-1", scope=scope())) == 403


def test_unentitled_principal_denied():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path, principals=())
    assert deny_status(lambda: svc.register(State(P1), reference="ref-1", scope=scope())) == 403


# --------------------------------------------------------------------------- #
# Admission negative matrix.
# --------------------------------------------------------------------------- #
def test_missing_provenance_denied():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path)
    assert deny_status(lambda: svc.register(State(None), reference="ref-1", scope=scope())) == 403


def test_csrf_failure_denied():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path, csrf=False)
    assert deny_status(lambda: svc.register(State(P1), reference="ref-1", scope=scope())) == 403


def test_unknown_reference_denied():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path)
    assert deny_status(lambda: svc.register(State(P1), reference="nope", scope=scope())) == 403


def test_decision_scope_mismatch_denied():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path, refs={"ref-1": vd(card="other-card")})
    assert deny_status(lambda: svc.register(State(P1), reference="ref-1", scope=scope())) == 403


def test_card_revision_mismatch_denied():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path, cards={scope().as_tuple(): "rev-2"})
    assert deny_status(lambda: svc.register(State(P1), reference="ref-1", scope=scope())) == 403


def test_missing_card_denied():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path, cards={})
    assert deny_status(lambda: svc.register(State(P1), reference="ref-1", scope=scope())) == 403


def test_expired_decision_denied():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path, refs={"ref-1": vd(expires_at=NOW - 1)})
    assert deny_status(lambda: svc.register(State(P1), reference="ref-1", scope=scope())) == 403


def test_future_verified_at_denied():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path, refs={"ref-1": vd(verified_at=NOW + 5)})
    assert deny_status(lambda: svc.register(State(P1), reference="ref-1", scope=scope())) == 403


# --------------------------------------------------------------------------- #
# Revocation.
# --------------------------------------------------------------------------- #
def test_revoke_then_status_revoked_and_idempotent():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path)
    rid = svc.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    r1 = svc.revoke(State(P1), receipt_id=rid, reference="rev-ref-1", expected=scope())
    assert r1["revoked"] is True and r1["new_revocation"] is True and r1["status"] == "revoked"
    r2 = svc.revoke(State(P1), receipt_id=rid, reference="rev-ref-1", expected=scope())
    assert r2["new_revocation"] is False and r2["revoked"] is True and r2["status"] == "revoked"


def test_revoke_wrong_scope_uniform_404():
    tmp_path = tempfile.mkdtemp()
    # Entitle P1 for both scopes so admission passes and the STORED-binding mismatch
    # (not an entitlement gap) is what must yield the uniform 404.
    keys = [(P1.key(), scope().as_tuple()), (P1.key(), scope(card="other").as_tuple())]
    svc, _ = build(tmp_path, adapters={"entitlement": FakeEntitlement(keys)})
    rid = svc.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    assert deny_status(lambda: svc.revoke(State(P1), receipt_id=rid, reference="rev-ref-1",
                                          expected=scope(card="other"))) == 404


def test_revoke_missing_receipt_404():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path)
    assert deny_status(lambda: svc.revoke(State(P1), receipt_id="ghost", reference="rev-ref-1",
                                          expected=scope())) == 404


# --------------------------------------------------------------------------- #
# Revocation integrity (R1 P1 fixes): a revocation is a DISTINCT decision that
# NAMES the target receipt; it can never be the approval, nor revoke a second receipt.
# --------------------------------------------------------------------------- #
def test_revoke_with_approval_decision_denied():
    tmp_path = tempfile.mkdtemp()
    # A "revocation" whose verified decision IS the approval (same issuer+decision_id).
    rev_refs = {"rev-as-approval": {"rev_issuer": "https://issuer.example",
                                    "rev_decision_id": "dec-1", "target": "ECHO"}}
    svc, _ = build(tmp_path, rev_refs=rev_refs)
    rid = svc.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    assert deny_status(lambda: svc.revoke(State(P1), receipt_id=rid,
                                          reference="rev-as-approval", expected=scope())) == 403


def test_revoke_wrong_target_denied():
    tmp_path = tempfile.mkdtemp()
    rev_refs = {"rev-wrong-target": {"rev_decision_id": "rev-dec-x", "target": "not-this-rid"}}
    svc, _ = build(tmp_path, rev_refs=rev_refs)
    rid = svc.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    assert deny_status(lambda: svc.revoke(State(P1), receipt_id=rid,
                                          reference="rev-wrong-target", expected=scope())) == 403


def test_revoke_same_decision_cannot_revoke_second_receipt():
    tmp_path = tempfile.mkdtemp()
    refs = {"ref-1": vd(decision_id="dec-1"), "ref-2": vd(decision_id="dec-2")}
    fake_rev = FakeRevocationVerifier({"rev-fixed": {"rev_decision_id": "rev-dec-1",
                                                     "target": "placeholder"}})
    svc, _ = build(tmp_path, refs=refs, adapters={"revocation_verifier": fake_rev})
    rid_a = svc.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    rid_b = svc.register(State(P1), reference="ref-2", scope=scope())["receipt_id"]
    # The verified revocation names receipt A only.
    fake_rev.table["rev-fixed"]["target"] = rid_a
    assert svc.revoke(State(P1), receipt_id=rid_a, reference="rev-fixed", expected=scope())["revoked"]
    # Reusing it against receipt B is a target mismatch, never a silent success.
    assert deny_status(lambda: svc.revoke(State(P1), receipt_id=rid_b,
                                          reference="rev-fixed", expected=scope())) == 403
    assert svc.read(State(P1), receipt_id=rid_b, expected=scope())["status"] == "active"


def test_repository_revoke_duplicate_other_receipt_conflict():
    tmp_path = tempfile.mkdtemp()
    refs = {"ref-1": vd(decision_id="dec-1"), "ref-2": vd(decision_id="dec-2")}
    svc, repo = build(tmp_path, refs=refs)
    rid_a = svc.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    rid_b = svc.register(State(P1), reference="ref-2", scope=scope())["receipt_id"]
    rev = {"rev_issuer": "i", "rev_decision_id": "rd", "reg_issuer": P1.issuer,
           "reg_provider": P1.provider, "reg_user_id": P1.user_id,
           "tenant": TENANT, "profile": PROFILE,
           "board": BOARD, "card_id": CARD, "case_action": ACTION, "card_revision": REV,
           "created_at": NOW}
    assert repo.revoke(rid_a, rev) == (True, True)
    # Same revocation decision against a different receipt: no insert, receipt_match False.
    assert repo.revoke(rid_b, rev) == (False, False)
    assert repo.is_revoked(rid_a) is True and repo.is_revoked(rid_b) is False


def test_revoke_unknown_reference_denied():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path)
    rid = svc.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    assert deny_status(lambda: svc.revoke(State(P1), receipt_id=rid,
                                          reference="nope", expected=scope())) == 403


def test_register_empty_verified_fact_denied():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path, refs={"ref-1": vd(decision_id="")})
    assert deny_status(lambda: svc.register(State(P1), reference="ref-1", scope=scope())) == 403


# --------------------------------------------------------------------------- #
# R2 fixes: non-finite timestamps and empty digest/evidence facts must fail closed.
# --------------------------------------------------------------------------- #
def test_register_non_finite_time_denied():
    tmp_path = tempfile.mkdtemp()
    for bad in (float("nan"), float("inf"), float("-inf")):
        svc, _ = build(tempfile.mkdtemp(), refs={"ref-1": vd(verified_at=bad)})
        assert deny_status(lambda: svc.register(State(P1), reference="ref-1", scope=scope())) == 403
        svc2, _ = build(tempfile.mkdtemp(), refs={"ref-1": vd(expires_at=bad)})
        assert deny_status(lambda: svc2.register(State(P1), reference="ref-1", scope=scope())) == 403


def test_register_empty_digest_or_evidence_denied():
    for facts in (vd(digest=""), vd(evidence_ref=""), vd(evidence_digest="")):
        svc, _ = build(tempfile.mkdtemp(), refs={"ref-1": facts})
        assert deny_status(lambda: svc.register(State(P1), reference="ref-1", scope=scope())) == 403


def test_revoke_empty_digest_or_non_finite_denied():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path, rev_refs={"rev-bad": {"rev_decision_id": "rev-dec-x",
                                                   "target": "ECHO", "verbatim_digest": ""}})
    rid = svc.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    assert deny_status(lambda: svc.revoke(State(P1), receipt_id=rid,
                                          reference="rev-bad", expected=scope())) == 403
    svc2, _ = build(tempfile.mkdtemp(), rev_refs={"rev-nan": {"rev_decision_id": "rev-dec-x",
                                                              "target": "ECHO", "verified_at": float("nan")}})
    rid2 = svc2.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    assert deny_status(lambda: svc2.revoke(State(P1), receipt_id=rid2,
                                           reference="rev-nan", expected=scope())) == 403


def test_repository_revocation_key_disjoint_from_all_approvals():
    tmp_path = tempfile.mkdtemp()
    svc, repo = build(tmp_path)
    rid = svc.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    # A revocation whose key equals an EXISTING approval key (dec-1) is a conflict even
    # though it names a valid target — the two decision key spaces must stay disjoint.
    rev = {"rev_issuer": "https://issuer.example", "rev_decision_id": "dec-1",
           "reg_issuer": P1.issuer, "reg_provider": P1.provider, "reg_user_id": P1.user_id,
           "tenant": TENANT, "profile": PROFILE, "board": BOARD, "card_id": CARD,
           "case_action": ACTION, "card_revision": REV, "created_at": NOW}
    assert repo.revoke(rid, rev) == (False, False)
    assert repo.is_revoked(rid) is False


def test_revocation_provenance_persisted():
    tmp_path = tempfile.mkdtemp()
    svc, repo = build(tmp_path)
    rid = svc.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    svc.revoke(State(P1), receipt_id=rid, reference="rev-ref-1", expected=scope())
    row = repo._conn.execute(
        "SELECT reg_issuer, reg_provider, reg_user_id FROM revocations WHERE receipt_id=?",
        (rid,)).fetchone()
    assert row == (P1.issuer, P1.provider, P1.user_id)


def test_storage_error_maps_to_503():
    tmp_path = tempfile.mkdtemp()
    svc, repo = build(tmp_path)
    repo.close()  # subsequent storage operations fail; must surface 503, never a raw 500
    assert deny_status(lambda: svc.register(State(P1), reference="ref-1", scope=scope())) == 503
    assert deny_status(lambda: svc.read(State(P1), receipt_id="ghost", expected=scope())) == 503


# --------------------------------------------------------------------------- #
# Read: uniform 404 + current-status recomputation (stale/expired/revoked).
# --------------------------------------------------------------------------- #
def test_read_uniform_404_no_existence_oracle():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path)
    rid = svc.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    codes = []
    codes.append(deny_status(lambda: svc.read(State(P1), receipt_id="ghost", expected=scope())))
    codes.append(deny_status(lambda: svc.read(State(P1), receipt_id=rid, expected=scope(card="other"))))
    codes.append(deny_status(lambda: svc.read(State(P2), receipt_id=rid, expected=scope())))
    assert codes == [404, 404, 404]


def test_read_active_then_stale_revision():
    tmp_path = tempfile.mkdtemp()
    cards = {scope().as_tuple(): REV}
    svc, _ = build(tmp_path, cards=cards)
    rid = svc.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    assert svc.read(State(P1), receipt_id=rid, expected=scope())["status"] == "active"
    cards[scope().as_tuple()] = "rev-2"  # card moved on
    assert svc.read(State(P1), receipt_id=rid, expected=scope())["status"] == "stale_revision"


def test_read_expired_after_clock_advance():
    tmp_path = tempfile.mkdtemp()
    clock = FakeClock()
    svc, _ = build(tmp_path, clock=clock)
    rid = svc.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    clock._t = NOW + 7200
    assert svc.read(State(P1), receipt_id=rid, expected=scope())["status"] == "expired"


def test_read_entitlement_removed_denies_404():
    tmp_path = tempfile.mkdtemp()
    svc, repo = build(tmp_path, principals=(P1,))
    rid = svc.register(State(P1), reference="ref-1", scope=scope())["receipt_id"]
    # Rebuild entitlement to drop P1 (simulates server-side entitlement revocation).
    svc._entitlement = FakeEntitlement([])
    assert deny_status(lambda: svc.read(State(P1), receipt_id=rid, expected=scope())) == 404


# --------------------------------------------------------------------------- #
# Transaction race: concurrent identical registrations serialize to one receipt.
# --------------------------------------------------------------------------- #
def test_concurrent_identical_registration_one_receipt():
    tmp_path = tempfile.mkdtemp()
    svc, _ = build(tmp_path)
    results, errors = [], []

    def worker():
        try:
            results.append(svc.register(State(P1), reference="ref-1", scope=scope()))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(results) == 8
    assert len({r["receipt_id"] for r in results}) == 1
    assert sum(1 for r in results if r["created"]) == 1


# --------------------------------------------------------------------------- #
# Zero business action: the registrar imports no card transition / dispatch / DB.
# --------------------------------------------------------------------------- #
def test_no_business_action_imports():
    import ast
    src = Path(__file__).resolve().parents[2] / "gateway" / "decision_receipts.py"
    tree = ast.parse(src.read_text())
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    joined = " ".join(imported)
    for forbidden in ("kanban_db", "kanban_workflow", "dispatch", "transition", "kanban"):
        assert forbidden not in joined, f"registrar must not import {forbidden}"

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
