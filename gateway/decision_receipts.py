"""Core #2 decision-receipt registrar — service + transaction-owned storage.

An ISOLATED registrar that records an ALREADY-EXISTING human decision for one existing
card and exact scope. It makes NO business decision, progresses NO card, and imports no
card-status transition or dispatch function. It ships DISABLED by default and every
dependency DENIES unless a trusted adapter is explicitly injected; only synthetic offline
tests inject positive evidence. Production storage/reader provisioning and the trusted
interactive-provenance/verifier/entitlement adapters are separate release prerequisites and
are NOT implemented or enabled here.

Trust rules (frozen plan r3, sha256 5fe85109…):
- Entitlement is keyed by the verified RAW identity tuple (issuer, provider, user_id),
  NEVER by the derived ``principal_subject``/host-owner subject: two interactive OAuth
  principals that collapse onto the same host-owner subject must NOT share entitlement.
- ``decision_issuer`` used in the uniqueness key comes ONLY from verifier-verified
  original-decision evidence, never from a caller body field.
- Read-path mismatch/missing returns a uniform 404 (no exists-vs-wrong-binding oracle).
- Serialization primitive: a UNIQUE-constraint insert inside ONE transaction (SQLite
  serializes writers); replay/conflict/revocation races resolve by commit order.
"""
from __future__ import annotations

import json
import math
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from typing import NoReturn, Optional, Protocol

SCHEMA_VERSION = 1


class RegistrarDeny(Exception):
    """Fail-closed denial. ``status`` is the HTTP status the route maps to.

    Read-path missing/mismatch uses 404 uniformly so a caller cannot distinguish
    "exists but wrong binding" from "does not exist". Write-path admission failures
    use 403; unreadable storage uses 503 (ops state, not existence).
    """

    def __init__(self, status: int, code: str):
        self.status = status
        self.code = code
        super().__init__(code)


def _deny(status: int, code: str) -> NoReturn:
    raise RegistrarDeny(status, code)


# --------------------------------------------------------------------------- #
# Verified facts produced by trusted, injectable adapters. The registrar never
# trusts caller-supplied author/role/principal/evidence claims.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RawPrincipal:
    issuer: str
    provider: str
    user_id: str

    def key(self) -> tuple:
        return (self.issuer, self.provider, self.user_id)


@dataclass(frozen=True)
class VerifiedDecision:
    """Facts resolved by the trusted verifier from an opaque original-decision reference."""
    decision_issuer: str
    decision_id: str
    original_actor: str
    tenant: str
    profile: str
    board: str
    card_id: str
    case_action: str
    card_revision: str
    verbatim_digest: str
    evidence_ref: str
    evidence_digest: str
    # verified_at is the ORIGINAL decision's verification time and MUST be stable across
    # calls (it is part of the immutable replay binding); a verifier that re-stamps it per
    # call would turn an identical retry into a binding_conflict. expires_at is the decision's
    # own expiry, not a registrar-computed window.
    verified_at: float
    expires_at: float


@dataclass(frozen=True)
class VerifiedRevocation:
    """Facts a trusted revocation verifier attests for a REVOCATION decision.

    Distinct from ``VerifiedDecision``: a revocation must NAME the receipt it revokes
    (``target_receipt_id``) and must be a DIFFERENT decision from the approval being
    revoked. The registrar enforces both; the verifier supplies only verified facts.
    """

    rev_issuer: str
    rev_decision_id: str
    target_receipt_id: str
    tenant: str
    profile: str
    board: str
    card_id: str
    case_action: str
    card_revision: str
    verbatim_digest: str
    evidence_ref: str
    evidence_digest: str
    verified_at: float
    expires_at: float


@dataclass(frozen=True)
class Scope:
    tenant: str
    profile: str
    board: str
    card_id: str
    case_action: str
    card_revision: str

    def as_tuple(self) -> tuple:
        return (self.tenant, self.profile, self.board, self.card_id,
                self.case_action, self.card_revision)


class ProvenanceAdapter(Protocol):
    """Proves an interactive OAuth session path and returns the verified RAW principal.

    Must deny local/native worker, basic/shared-token/session-token/server-internal,
    token-principal and anonymous paths. A provider name alone is not an OAuth proof.
    """
    def prove(self, request_state) -> RawPrincipal: ...


class EntitlementService(Protocol):
    """Current server-side entitlement for a RAW principal + exact scope. Worker role
    names never count. Keyed by raw identity, never the collapsed owner subject."""
    def entitled(self, principal: RawPrincipal, scope: Scope) -> bool: ...


class DecisionVerifier(Protocol):
    """Resolves an opaque original-decision reference to verified facts. The production
    default always denies; references are opaque ids, never caller-selected URLs."""
    def verify(self, reference: str, expected: Scope) -> VerifiedDecision: ...


class RevocationVerifier(Protocol):
    """Resolves an opaque REVOCATION-decision reference to verified revocation facts that
    name the target receipt. Production default denies."""
    def verify_revocation(self, reference: str, receipt_id: str,
                          expected: Scope) -> VerifiedRevocation: ...


class CardResolver(Protocol):
    """Read-only resolution of an existing card + its CURRENT revision in the explicitly
    named board/tenant/profile. No implicit current-board fallback."""
    def current_revision(self, scope: Scope) -> Optional[str]: ...


class CsrfValidator(Protocol):
    """Session-bound synchronizer token + same-origin check, validated server-side per
    mutation. Never a token-minting endpoint for unverified callers."""
    def validate(self, request_state, principal: RawPrincipal) -> bool: ...


class Clock(Protocol):
    def now(self) -> float: ...


class _SystemClock:
    def now(self) -> float:
        return time.time()


# --------------------------------------------------------------------------- #
# Default-deny adapters. These are the production defaults: nothing is entitled,
# nothing is verified, no interactive path is proven. Positive evidence is injected
# only by synthetic offline tests until trusted deployed adapters are approved.
# --------------------------------------------------------------------------- #
class DenyProvenance:
    def prove(self, request_state) -> RawPrincipal:
        _deny(403, "interactive_provenance_unavailable")


class DenyEntitlement:
    def entitled(self, principal: RawPrincipal, scope: Scope) -> bool:
        return False


class DenyVerifier:
    def verify(self, reference: str, expected: Scope) -> VerifiedDecision:
        _deny(403, "decision_verifier_unavailable")


class DenyRevocationVerifier:
    def verify_revocation(self, reference: str, receipt_id: str,
                          expected: Scope) -> VerifiedRevocation:
        _deny(403, "revocation_verifier_unavailable")


class DenyCardResolver:
    def current_revision(self, scope: Scope) -> Optional[str]:
        return None


class DenyCsrf:
    def validate(self, request_state, principal: RawPrincipal) -> bool:
        return False


# --------------------------------------------------------------------------- #
# Immutable receipt model + transaction-owned repository.
# --------------------------------------------------------------------------- #
_RECEIPT_FIELDS = (
    "receipt_id", "schema_version", "decision_issuer", "decision_id", "original_actor",
    "reg_issuer", "reg_provider", "reg_user_id", "reg_subject",
    "tenant", "profile", "board", "card_id", "case_action", "card_revision",
    "verbatim_digest", "evidence_ref", "evidence_digest",
    "verified_at", "expires_at", "created_at",
)


def _canonical_binding(row: dict) -> str:
    """The entire immutable binding, canonically serialized for replay comparison."""
    return json.dumps({k: row[k] for k in _RECEIPT_FIELDS if k not in
                       ("receipt_id", "created_at")}, sort_keys=True, separators=(",", ":"))


class ReceiptRepository:
    """A dedicated Core-controlled SQLite store, NOT the board database.

    This implements an injected repository for offline tests. It MUST NOT be pointed at
    production storage under a worker-writable identity; provisioning a distinct serving
    identity / OS access boundary is a release prerequisite. ``path`` is caller-injected
    (tests use a private temporary file); the registrar route never accepts a caller path.
    """

    def __init__(self, path: str):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._init_schema()
        except Exception:
            self._conn.close()  # do not leak the connection if schema init denies
            raise

    def _init_schema(self):
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                decision_issuer TEXT NOT NULL,
                decision_id TEXT NOT NULL,
                original_actor TEXT NOT NULL,
                reg_issuer TEXT NOT NULL,
                reg_provider TEXT NOT NULL,
                reg_user_id TEXT NOT NULL,
                reg_subject TEXT NOT NULL,
                tenant TEXT NOT NULL,
                profile TEXT NOT NULL,
                board TEXT NOT NULL,
                card_id TEXT NOT NULL,
                case_action TEXT NOT NULL,
                card_revision TEXT NOT NULL,
                verbatim_digest TEXT NOT NULL,
                evidence_ref TEXT NOT NULL,
                evidence_digest TEXT NOT NULL,
                verified_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                created_at REAL NOT NULL,
                binding TEXT NOT NULL,
                UNIQUE (decision_issuer, decision_id)
            );
            CREATE TABLE IF NOT EXISTS revocations (
                revocation_row_id TEXT PRIMARY KEY,
                receipt_id TEXT NOT NULL REFERENCES receipts(receipt_id),
                rev_issuer TEXT NOT NULL,
                rev_decision_id TEXT NOT NULL,
                reg_issuer TEXT NOT NULL,
                reg_provider TEXT NOT NULL,
                reg_user_id TEXT NOT NULL,
                tenant TEXT NOT NULL,
                profile TEXT NOT NULL,
                board TEXT NOT NULL,
                card_id TEXT NOT NULL,
                case_action TEXT NOT NULL,
                card_revision TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE (rev_issuer, rev_decision_id)
            );
            """
        )
        cur = self._conn.execute("SELECT v FROM meta WHERE k='schema_version'")
        row = cur.fetchone()
        if row is None:
            self._conn.execute("INSERT INTO meta(k,v) VALUES('schema_version',?)",
                               (str(SCHEMA_VERSION),))
        elif int(row[0]) != SCHEMA_VERSION:
            _deny(503, "unsupported_schema")

    def close(self):
        with self._lock:
            self._conn.close()

    def _safe_rollback(self):
        try:
            self._conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def register(self, row: dict) -> tuple:
        """Insert-or-replay inside ONE transaction. Returns (receipt_id, created, binding_match).

        UNIQUE(decision_issuer, decision_id) is the serialization primitive: a concurrent
        identical retry replays the original; a different binding for the same key conflicts.
        """
        binding = _canonical_binding(row)
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
            except sqlite3.Error:
                _deny(503, "storage_unavailable")
            try:
                cur = self._conn.execute(
                    "SELECT receipt_id, binding FROM receipts WHERE decision_issuer=? AND decision_id=?",
                    (row["decision_issuer"], row["decision_id"]))
                existing = cur.fetchone()
                if existing is not None:
                    receipt_id, stored_binding = existing
                    self._conn.execute("COMMIT")
                    return receipt_id, False, stored_binding == binding
                receipt_id = row["receipt_id"]
                cols = ",".join(_RECEIPT_FIELDS) + ",binding"
                ph = ",".join("?" for _ in _RECEIPT_FIELDS) + ",?"
                vals = [row[k] for k in _RECEIPT_FIELDS] + [binding]
                self._conn.execute(f"INSERT INTO receipts({cols}) VALUES({ph})", vals)
                self._conn.execute("COMMIT")
                return receipt_id, True, True
            except sqlite3.Error:
                self._safe_rollback()
                _deny(503, "storage_unavailable")
            except Exception:
                self._safe_rollback()
                raise

    def get(self, receipt_id: str) -> Optional[dict]:
        with self._lock:
            try:
                cur = self._conn.execute(
                    f"SELECT {','.join(_RECEIPT_FIELDS)} FROM receipts WHERE receipt_id=?", (receipt_id,))
                r = cur.fetchone()
            except sqlite3.Error:
                _deny(503, "storage_unavailable")
            if r is None:
                return None
            return dict(zip(_RECEIPT_FIELDS, r))

    def revoke(self, receipt_id: str, rev: dict) -> tuple:
        """Append-only revocation. Returns (inserted, receipt_match).

        UNIQUE(rev_issuer, rev_decision_id) binds one revocation decision to ONE receipt.
        A duplicate key replays idempotently only when it names the SAME receipt; a different
        receipt is a binding conflict (receipt_match=False), never a silent no-op success.
        """
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
            except sqlite3.Error:
                _deny(503, "storage_unavailable")
            try:
                cur = self._conn.execute(
                    "SELECT receipt_id FROM revocations WHERE rev_issuer=? AND rev_decision_id=?",
                    (rev["rev_issuer"], rev["rev_decision_id"]))
                existing = cur.fetchone()
                if existing is not None:
                    self._conn.execute("COMMIT")
                    return False, existing[0] == receipt_id
                # Defense-in-depth: a revocation key must also be disjoint from EVERY approval
                # key in the receipts table, not just the target's, so the two decision key
                # spaces can never overlap even if a service-layer check is bypassed.
                clash = self._conn.execute(
                    "SELECT 1 FROM receipts WHERE decision_issuer=? AND decision_id=? LIMIT 1",
                    (rev["rev_issuer"], rev["rev_decision_id"])).fetchone()
                if clash is not None:
                    self._conn.execute("COMMIT")
                    return False, False
                self._conn.execute(
                    """INSERT INTO revocations(revocation_row_id,receipt_id,rev_issuer,
                       rev_decision_id,reg_issuer,reg_provider,reg_user_id,
                       tenant,profile,board,card_id,case_action,card_revision,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (uuid.uuid4().hex, receipt_id, rev["rev_issuer"], rev["rev_decision_id"],
                     rev["reg_issuer"], rev["reg_provider"], rev["reg_user_id"],
                     rev["tenant"], rev["profile"], rev["board"], rev["card_id"],
                     rev["case_action"], rev["card_revision"], rev["created_at"]))
                self._conn.execute("COMMIT")
                return True, True
            except sqlite3.Error:
                self._safe_rollback()
                _deny(503, "storage_unavailable")
            except Exception:
                self._safe_rollback()
                raise

    def is_revoked(self, receipt_id: str) -> bool:
        with self._lock:
            try:
                cur = self._conn.execute("SELECT 1 FROM revocations WHERE receipt_id=? LIMIT 1", (receipt_id,))
                return cur.fetchone() is not None
            except sqlite3.Error:
                _deny(503, "storage_unavailable")


# --------------------------------------------------------------------------- #
# Service: registration / revocation / read. No business action, no card mutation.
# --------------------------------------------------------------------------- #
class DecisionReceiptService:
    def __init__(self, repo: Optional[ReceiptRepository], *, provenance: ProvenanceAdapter,
                 entitlement: EntitlementService, verifier: DecisionVerifier,
                 revocation_verifier: RevocationVerifier,
                 cards: CardResolver, csrf: CsrfValidator, clock: Optional[Clock] = None,
                 enabled: bool = False):
        self._repo = repo
        self._provenance = provenance
        self._entitlement = entitlement
        self._verifier = verifier
        self._revocation_verifier = revocation_verifier
        self._cards = cards
        self._csrf = csrf
        self._clock = clock or _SystemClock()
        self._enabled = enabled

    def _require_enabled(self):
        if not self._enabled:
            _deny(404, "registrar_disabled")

    def _repo_or_deny(self) -> ReceiptRepository:
        if self._repo is None:
            _deny(503, "storage_unavailable")
        return self._repo

    def _prove(self, request_state) -> RawPrincipal:
        """Prove the interactive principal and reject an incomplete raw identity. Shared by
        the write admission path and the read path so neither accepts a partial principal."""
        principal = self._provenance.prove(request_state)
        if not (principal.issuer and principal.provider and principal.user_id):
            _deny(403, "incomplete_principal")
        return principal

    def _admit(self, request_state, scope: Scope) -> RawPrincipal:
        """Interactive provenance + CSRF + current raw-identity entitlement. Fail closed."""
        principal = self._prove(request_state)
        if not self._csrf.validate(request_state, principal):
            _deny(403, "csrf_invalid")
        if not self._entitlement.entitled(principal, scope):
            _deny(403, "not_entitled")
        return principal

    def _check_decision_valid(self, vd: VerifiedDecision | VerifiedRevocation, now: float):
        # Non-finite values (NaN/inf) defeat every ordering comparison below, so reject them
        # explicitly before comparing; a NaN timestamp must never validate or commit.
        if not (math.isfinite(vd.verified_at) and math.isfinite(vd.expires_at) and math.isfinite(now)):
            _deny(403, "decision_invalid_time")
        if vd.verified_at > now or vd.expires_at <= now or vd.expires_at <= vd.verified_at:
            _deny(403, "decision_invalid_time")

    def register(self, request_state, *, reference: str, scope: Scope) -> dict:
        """Register a verified original decision. Returns receipt id + CURRENT status.

        Entitlement and stored provenance use the RAW principal; a derived compatibility
        subject is stored but is never the entitlement key. The caller body never supplies
        decision facts (issuer/id/actor/validity/evidence come only from the verifier).
        """
        self._require_enabled()
        principal = self._admit(request_state, scope)
        vd = self._verifier.verify(reference, scope)
        # decision_issuer comes ONLY from verified evidence (vd), never a caller body field.
        # Every required verified fact must be present and non-empty (fail closed).
        if not (vd.decision_issuer and vd.decision_id and vd.original_actor
                and vd.verbatim_digest and vd.evidence_ref and vd.evidence_digest):
            _deny(403, "incomplete_verified_decision")
        if (vd.tenant, vd.profile, vd.board, vd.card_id, vd.case_action, vd.card_revision) != scope.as_tuple():
            _deny(403, "decision_scope_mismatch")
        now = self._clock.now()
        self._check_decision_valid(vd, now)
        current = self._cards.current_revision(scope)
        if current is None or current != scope.card_revision:
            _deny(403, "card_revision_mismatch")
        row = {
            "receipt_id": uuid.uuid4().hex, "schema_version": SCHEMA_VERSION,
            "decision_issuer": vd.decision_issuer, "decision_id": vd.decision_id,
            "original_actor": vd.original_actor,
            "reg_issuer": principal.issuer, "reg_provider": principal.provider,
            "reg_user_id": principal.user_id,
            "reg_subject": f"{principal.provider}:{principal.user_id}",
            "tenant": scope.tenant, "profile": scope.profile, "board": scope.board,
            "card_id": scope.card_id, "case_action": scope.case_action,
            "card_revision": scope.card_revision,
            "verbatim_digest": vd.verbatim_digest, "evidence_ref": vd.evidence_ref,
            "evidence_digest": vd.evidence_digest,
            "verified_at": vd.verified_at, "expires_at": vd.expires_at, "created_at": now,
        }
        repo = self._repo_or_deny()
        receipt_id, created, binding_match = repo.register(row)
        if not binding_match:
            _deny(409, "binding_conflict")
        return {"receipt_id": receipt_id, "created": created,
                "status": self._current_status(receipt_id, scope, principal)}

    def revoke(self, request_state, *, receipt_id: str, reference: str,
               expected: Scope) -> dict:
        self._require_enabled()
        principal = self._admit(request_state, expected)
        repo = self._repo_or_deny()
        stored = repo.get(receipt_id)
        if stored is None:
            _deny(404, "not_found")
        stored_scope = Scope(stored["tenant"], stored["profile"], stored["board"],
                             stored["card_id"], stored["case_action"], stored["card_revision"])
        if stored_scope.as_tuple() != expected.as_tuple():
            _deny(404, "not_found")
        # A revocation is a DISTINCT verified decision that NAMES this receipt. It is never
        # the approval being revoked, and any scope-entitled principal cannot revoke an
        # arbitrary receipt with an arbitrary verified decision.
        vr = self._revocation_verifier.verify_revocation(reference, receipt_id, expected)
        if not (vr.rev_issuer and vr.rev_decision_id and vr.target_receipt_id
                and vr.verbatim_digest and vr.evidence_ref and vr.evidence_digest):
            _deny(403, "incomplete_verified_revocation")
        if (vr.tenant, vr.profile, vr.board, vr.card_id, vr.case_action, vr.card_revision) != expected.as_tuple():
            _deny(403, "decision_scope_mismatch")
        if vr.target_receipt_id != receipt_id:
            _deny(403, "revocation_target_mismatch")
        if (vr.rev_issuer, vr.rev_decision_id) == (stored["decision_issuer"], stored["decision_id"]):
            _deny(403, "revocation_is_approval")
        now = self._clock.now()
        self._check_decision_valid(vr, now)
        rev = {"rev_issuer": vr.rev_issuer, "rev_decision_id": vr.rev_decision_id,
               "reg_issuer": principal.issuer, "reg_provider": principal.provider,
               "reg_user_id": principal.user_id,
               "tenant": expected.tenant, "profile": expected.profile, "board": expected.board,
               "card_id": expected.card_id, "case_action": expected.case_action,
               "card_revision": expected.card_revision, "created_at": now}
        inserted, receipt_match = repo.revoke(receipt_id, rev)
        if not receipt_match:
            _deny(409, "revocation_binding_conflict")
        # 'revoked' is derived from stored state, never hard-coded.
        return {"receipt_id": receipt_id, "revoked": repo.is_revoked(receipt_id),
                "new_revocation": inserted,
                "status": self._current_status(receipt_id, expected, principal)}

    def read(self, request_state, *, receipt_id: str, expected: Scope) -> dict:
        """Scoped read for a separately authorized reader. Uniform 404 on any mismatch."""
        self._require_enabled()
        reader_principal = self._prove(request_state)
        if not self._entitlement.entitled(reader_principal, expected):
            _deny(404, "not_found")
        repo = self._repo_or_deny()
        stored = repo.get(receipt_id)
        if stored is None:
            _deny(404, "not_found")
        stored_scope = Scope(stored["tenant"], stored["profile"], stored["board"],
                             stored["card_id"], stored["case_action"], stored["card_revision"])
        if stored_scope.as_tuple() != expected.as_tuple():
            _deny(404, "not_found")
        status = self._current_status(receipt_id, expected, reader_principal)
        return {"receipt_id": receipt_id, "status": status,
                "decision_issuer": stored["decision_issuer"], "decision_id": stored["decision_id"],
                "card_revision": stored["card_revision"], "expires_at": stored["expires_at"]}

    def _current_status(self, receipt_id: str, scope: Scope, principal: RawPrincipal) -> str:
        """Recompute CURRENT validity: entitlement + card revision + decision time + revocation.

        A returned 'active' is a point-in-time observation, not permission to dispatch later.
        """
        now = self._clock.now()
        repo = self._repo_or_deny()
        stored = repo.get(receipt_id)
        if stored is None:
            return "missing"
        if repo.is_revoked(receipt_id):
            return "revoked"
        if not self._entitlement.entitled(principal, scope):
            return "not_entitled"
        current = self._cards.current_revision(scope)
        if current is None or current != stored["card_revision"]:
            return "stale_revision"
        if stored["expires_at"] <= now or stored["verified_at"] > now:
            return "expired"
        return "active"


def disabled_service() -> DecisionReceiptService:
    """Default-disabled registrar: deny adapters, no production storage.

    Mounting this grants nothing and changes no behavior. Enabling requires the
    separately-approved release prerequisites (trusted adapters + protected storage/reader).
    """
    return DecisionReceiptService(
        repo=None, provenance=DenyProvenance(), entitlement=DenyEntitlement(),
        verifier=DenyVerifier(), revocation_verifier=DenyRevocationVerifier(),
        cards=DenyCardResolver(), csrf=DenyCsrf(), enabled=False)