#!/usr/bin/env python3
"""
worker_logic.py — Stripe Full Stack Worker (WCP v0.3.0)

Full Stripe API integration: customers, payments, subscriptions, invoices,
refunds, products, and prices. WCP-compliant: attested package, fail-closed
policy gate, append-only hash-chained evidence log, correlation IDs.

SECURITY: Never logs or stores card numbers or CVV. Stripe handles PCI scope.

Auth: set STRIPE_SECRET_KEY environment variable before running.
      sk_test_* keys route to test mode; sk_live_* keys route to production.

Usage:
    python3 bootstrap.py list_customers [--limit 25] [--email addr@example.com]
    python3 bootstrap.py create_customer --email addr@example.com [--name "Jane Doe"]
    python3 bootstrap.py get_customer --customer-id cus_xxx
    python3 bootstrap.py create_payment_intent --amount-cents 1999 --currency usd
    python3 bootstrap.py capture_payment --payment-intent-id pi_xxx
    python3 bootstrap.py create_subscription --customer-id cus_xxx --price-id price_xxx
    python3 bootstrap.py cancel_subscription --subscription-id sub_xxx
    python3 bootstrap.py list_invoices [--customer-id cus_xxx]
    python3 bootstrap.py get_invoice --invoice-id in_xxx
    python3 bootstrap.py create_refund --payment-intent-id pi_xxx [--amount-cents 500]
    python3 bootstrap.py list_products
    python3 bootstrap.py create_product --name "Pro Plan"
    python3 bootstrap.py create_price --product-id prod_xxx --unit-amount-cents 999 --recurring-interval month
"""

from __future__ import annotations

# ============================================================================
# SECTION 1: HEADER + IDENTITY + WCP DECLARATIONS
# ============================================================================

import argparse
import hashlib
import json
import os
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

WORKER_ID          = "org.pyhall.stripe.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.stripe"
WORKER_NAME        = "Stripe Full Stack Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.stripe.write",
    "cap.pyhall.stripe.read",
    "cap.pyhall.stripe.manage",
]

ALLOWED_OPS = {
    "list_customers",
    "create_customer",
    "get_customer",
    "list_payments",
    "create_payment_intent",
    "capture_payment",
    "list_subscriptions",
    "create_subscription",
    "cancel_subscription",
    "list_invoices",
    "get_invoice",
    "create_refund",
    "list_products",
    "create_product",
    "create_price",
}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

ALLOWED_ENVS = {"dev", "stage", "prod"}

# Map ops to their required capability
_OP_CAPABILITY: Dict[str, str] = {
    "list_customers":         "cap.pyhall.stripe.read",
    "create_customer":        "cap.pyhall.stripe.manage",
    "get_customer":           "cap.pyhall.stripe.read",
    "list_payments":          "cap.pyhall.stripe.read",
    "create_payment_intent":  "cap.pyhall.stripe.write",
    "capture_payment":        "cap.pyhall.stripe.write",
    "list_subscriptions":     "cap.pyhall.stripe.read",
    "create_subscription":    "cap.pyhall.stripe.write",
    "cancel_subscription":    "cap.pyhall.stripe.write",
    "list_invoices":          "cap.pyhall.stripe.read",
    "get_invoice":            "cap.pyhall.stripe.read",
    "create_refund":          "cap.pyhall.stripe.write",
    "list_products":          "cap.pyhall.stripe.read",
    "create_product":         "cap.pyhall.stripe.manage",
    "create_price":           "cap.pyhall.stripe.manage",
}


# ============================================================================
# SECTION 2: CORE MODELS
# ============================================================================

@dataclass(frozen=True)
class WCPContext:
    correlation_id: str
    env: str
    capability_id: str
    data_label: str
    tenant_risk: str
    qos_class: str
    requested_at_utc: str


@dataclass(frozen=True)
class WCPDecision:
    allowed: bool
    deny_code: Optional[str]
    deny_message: Optional[str]
    policy_version: str
    matched_rule_id: Optional[str]
    selected_worker_species_id: Optional[str]


@dataclass(frozen=True)
class WorkerResult:
    status: str
    output: Dict[str, Any]
    telemetry_events: List[Dict[str, Any]]
    evidence_receipts: List[Dict[str, Any]]


@dataclass
class StripeOpResult:
    """Lightweight container for a single Stripe API call outcome."""
    op: str
    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None
    stripe_mode: str = "unknown"  # "test" or "live"


# ============================================================================
# SECTION 3: UTILS
# ============================================================================

_CT = ZoneInfo("America/Chicago")


def utc_now_iso() -> str:
    """Return current UTC time as ISO 8601 string with Z suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def now_ct() -> str:
    """Return current Central Time as a human-readable string."""
    return datetime.now(_CT).strftime("%Y-%m-%d %H:%M:%S CT")


def log(msg: str) -> None:
    """Print a timestamped log line (Central Time)."""
    print(f"[{now_ct()}] {msg}")


def sha256_hex_bytes(b: bytes) -> str:
    """Return SHA-256 hex digest of bytes."""
    return hashlib.sha256(b).hexdigest()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def _stripe_mode(api_key: str) -> str:
    """Determine Stripe mode from the key prefix."""
    if api_key.startswith("sk_live_"):
        return "live"
    if api_key.startswith("sk_test_"):
        return "test"
    return "unknown"


# ============================================================================
# SECTION 4: PACKAGE ATTESTATION + SIGNATURE VERIFICATION
# ============================================================================
# required for PyHall APP.
# not strictly required in-file for API-only usage.
# if this worker file changes, a new attestation is required.


def _run_startup_attestation(package_root: Path, manifest_path: Path) -> Dict[str, Any]:
    """
    Run full package attestation using the pyhall PackageAttestationVerifier.

    In dev (PYHALL_ENV != 'prod') or WCP_ATTEST_HMAC_KEY not set:
      - logs a WARNING but does not block execution.
    In prod, any attestation failure raises SystemExit(2).

    Returns attest_meta dict on success (may be empty dict in dev skip).
    """
    env = os.environ.get("PYHALL_ENV", "dev")
    hmac_key_set = bool(os.environ.get("WCP_ATTEST_HMAC_KEY", "").strip())

    try:
        from pyhall.attestation import PackageAttestationVerifier
    except ImportError as exc:
        msg = f"Cannot import pyhall PackageAttestationVerifier: {exc}"
        if env == "prod":
            log(f"FATAL: {msg}")
            raise SystemExit(2)
        log(f"WARNING: {msg} — skipping attestation in dev")
        return {"dev_skip": True, "reason": msg}

    if not hmac_key_set:
        msg = "WCP_ATTEST_HMAC_KEY not set"
        if env == "prod":
            log(f"FATAL: {msg} — attestation requires signing key in prod")
            raise SystemExit(2)
        log(f"WARNING: {msg} — skipping signature verification in dev")
        return {"dev_skip": True, "reason": msg}

    verifier = PackageAttestationVerifier(
        package_root=package_root,
        manifest_path=manifest_path,
        worker_id=WORKER_ID,
        worker_species_id=WORKER_SPECIES_ID,
    )
    ok, deny_code, attest_meta = verifier.verify()

    if not ok:
        msg = f"Package attestation failed: {deny_code} meta={attest_meta}"
        if env == "prod":
            log(f"FATAL: {msg}")
            raise SystemExit(2)
        log(f"WARNING: {msg} — continuing in dev (non-prod env)")
        return {"dev_skip": True, "deny_code": deny_code, "meta": attest_meta}

    log(f"Attestation OK — {attest_meta.get('trust_statement', '')}")
    return attest_meta


# Derive paths from this file's location:
#   code/worker_logic.py  →  parent = code/  →  parent.parent = stripe_worker/
_THIS_FILE     = Path(__file__).resolve()
_PACKAGE_ROOT  = _THIS_FILE.parent.parent   # .../stripe_worker/
_MANIFEST_PATH = _PACKAGE_ROOT / "manifest.json"


# ============================================================================
# SECTION 5: POLICY GATE (FAIL-CLOSED)
# ============================================================================

class PolicyGate:
    """
    Local fail-closed WCP policy gate.

    Every check must pass to allow. Default is deny.
    """

    policy_version = "policy.v0.3.0"

    def evaluate(self, ctx: WCPContext, operation: Dict[str, Any]) -> WCPDecision:
        if ctx.env not in ALLOWED_ENVS:
            return WCPDecision(
                False, "ENV_NOT_ALLOWED",
                f"env={ctx.env!r} not in ALLOWED_ENVS",
                self.policy_version, None, None,
            )

        if ctx.capability_id not in CAPABILITIES:
            return WCPDecision(
                False, "CAPABILITY_NOT_ALLOWED",
                f"capability={ctx.capability_id!r} not declared",
                self.policy_version, None, None,
            )

        op = operation.get("op", "")
        if op not in ALLOWED_OPS:
            return WCPDecision(
                False, "OP_NOT_ALLOWED",
                f"op={op!r} not in ALLOWED_OPS",
                self.policy_version, None, None,
            )

        # Capability must match op's required capability
        required_cap = _OP_CAPABILITY.get(op)
        if required_cap and ctx.capability_id != required_cap:
            return WCPDecision(
                False, "CAPABILITY_OP_MISMATCH",
                f"op={op!r} requires capability={required_cap!r}, got {ctx.capability_id!r}",
                self.policy_version, None, None,
            )

        if not ctx.correlation_id:
            return WCPDecision(
                False, "CORRELATION_ID_REQUIRED",
                "missing correlation_id",
                self.policy_version, None, None,
            )

        rule_id = f"rr_stripe_{op}_allow_v1"
        return WCPDecision(True, None, None, self.policy_version, rule_id, WORKER_SPECIES_ID)


# ============================================================================
# SECTION 6: OBSERVABILITY — HASH-CHAINED EVIDENCE LOG
# ============================================================================

_EVIDENCE_LOG_PATH = Path(
    os.path.expanduser("~/.local/share/pyhall/evidence/")
) / f"{WORKER_SPECIES_ID.replace('.', '_')}_chain.log"


class AppendOnlyEvidenceLog:
    """
    Hash-chained append-only local evidence log.

    Each entry records: prev_hash, entry_hash (sha256 of prev_hash + payload),
    and the receipt dict. Writes are best-effort — will not crash on I/O error.
    """

    def __init__(self, log_path: Path):
        self.log_path = log_path

    def emit_evidence(self, receipt: Dict[str, Any]) -> None:
        """Append a receipt to the hash-chained evidence log."""
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

            prev_hash = "GENESIS"
            if self.log_path.exists() and self.log_path.stat().st_size > 0:
                lines = self.log_path.read_text(encoding="utf-8").strip().splitlines()
                if lines:
                    try:
                        prev = json.loads(lines[-1])
                        prev_hash = prev.get("entry_hash", "GENESIS")
                    except Exception:
                        prev_hash = "GENESIS"

            payload = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
            entry_hash = sha256_hex_bytes(prev_hash.encode("utf-8") + payload)
            row = {"prev_hash": prev_hash, "entry_hash": entry_hash, "receipt": receipt}

            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, sort_keys=True) + "\n")
        except Exception as exc:
            log(f"WARNING: evidence log write failed (best-effort): {exc}")


def build_evidence_receipt(
    ctx: WCPContext,
    decision: WCPDecision,
    status: str,
    detail: str,
    op: str,
    attest_meta: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a WCP evidence receipt dict. extra fields are merged at top level."""
    payload_hash = sha256_hex_bytes(
        json.dumps({"op": op, "worker_id": WORKER_ID}, sort_keys=True).encode("utf-8")
    )
    receipt: Dict[str, Any] = {
        "receipt_type": "wcp_execution_receipt",
        "schema_version": "wcp-receipt.v1",
        "dispatched_at_utc": utc_now_iso(),
        "worker_id": WORKER_ID,
        "worker_species_id": WORKER_SPECIES_ID,
        "capability_id": ctx.capability_id,
        "operation": op,
        "correlation_id": ctx.correlation_id,
        "policy_decision": {
            "allowed": decision.allowed,
            "policy_version": decision.policy_version,
            "matched_rule_id": decision.matched_rule_id,
            "selected_worker_species_id": decision.selected_worker_species_id,
        },
        "controls_verified": REQUIRED_CONTROLS,
        "request_payload_sha256": payload_hash,
        "attested_package_hash": (attest_meta or {}).get("package_hash", "unverified"),
        "status": status,
        "detail": detail,
    }
    if extra:
        receipt.update(extra)
    return receipt


# Module-level singletons (instantiated at import time)
_policy_gate  = PolicyGate()
_evidence_log = AppendOnlyEvidenceLog(_EVIDENCE_LOG_PATH)
_attest_meta: Dict[str, Any] = {}  # populated by run() at startup


def _make_ctx(op: str) -> WCPContext:
    """Build a WCPContext, selecting the correct capability for the op."""
    cap = _OP_CAPABILITY.get(op, CAPABILITIES[0])
    return WCPContext(
        correlation_id=str(uuid.uuid4()),
        env=os.environ.get("PYHALL_ENV", "dev"),
        capability_id=cap,
        data_label="INTERNAL",
        tenant_risk="low",
        qos_class="P2",
        requested_at_utc=utc_now_iso(),
    )


def _gate_and_emit(op: str) -> Tuple[WCPContext, WCPDecision]:
    """Run the policy gate for an op. Emit deny receipt and exit if blocked."""
    ctx = _make_ctx(op)
    decision = _policy_gate.evaluate(ctx, {"op": op})
    if not decision.allowed:
        receipt = build_evidence_receipt(
            ctx, decision, "denied", decision.deny_message or "policy deny", op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        log(f"POLICY DENY [{decision.deny_code}]: {decision.deny_message}")
        raise SystemExit(1)
    return ctx, decision


# ============================================================================
# SECTION 7: DOMAIN LOGIC — STRIPE API
# ============================================================================

# --- Auth helpers ---

def _validate_auth() -> Tuple[str, str]:
    """
    Validate STRIPE_SECRET_KEY is set and return (api_key, mode).

    mode is "test" | "live" | "unknown".
    Raises SystemExit(1) with a clear message if the key is missing.
    NEVER logs the key value itself.
    """
    key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    if not key:
        log("ERROR: STRIPE_SECRET_KEY environment variable is not set.")
        log("  Set it before running: export STRIPE_SECRET_KEY=sk_test_...")
        raise SystemExit(1)

    mode = _stripe_mode(key)
    if mode == "live":
        log("WARNING: Using LIVE Stripe key (sk_live_*) — real charges will be made.")
    elif mode == "test":
        log("INFO: Using test Stripe key (sk_test_*) — safe for development.")
    else:
        log("WARNING: STRIPE_SECRET_KEY prefix not recognized (expected sk_test_ or sk_live_).")

    return key, mode


def _init_stripe() -> str:
    """Import stripe SDK, set api_key, return the mode string."""
    try:
        import stripe as _stripe
    except ImportError:
        log("ERROR: stripe package not installed. Run: pip install stripe>=7.0.0")
        raise SystemExit(1)

    key, mode = _validate_auth()
    _stripe.api_key = key
    return mode


# --- Customer operations ---

def list_customers(limit: int = 25, email: Optional[str] = None) -> StripeOpResult:
    """List Stripe customers. Optionally filter by email."""
    ctx, decision = _gate_and_emit("list_customers")
    mode = _init_stripe()

    import stripe

    try:
        kwargs: Dict[str, Any] = {"limit": limit}
        if email:
            kwargs["email"] = email
        response = stripe.Customer.list(**kwargs)
        customers = [
            {
                "id": c.id,
                "email": c.email,
                "name": c.name,
                "created": c.created,
                "metadata": dict(c.metadata) if c.metadata else {},
            }
            for c in response.auto_paging_iter()
        ][:limit]  # auto_paging_iter respects limit but cap again for safety

        detail = f"list_customers: {len(customers)} customers returned (mode={mode})"
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "list_customers", _attest_meta,
            extra={"stripe_mode": mode, "record_count": len(customers)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("list_customers", True, {"customers": customers}, stripe_mode=mode)

    except stripe.error.StripeError as exc:
        detail = f"list_customers Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "list_customers", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("list_customers", False, {}, error=detail, stripe_mode=mode)


def create_customer(
    email: str,
    name: Optional[str] = None,
    metadata: Optional[Dict[str, str]] = None,
) -> StripeOpResult:
    """Create a new Stripe customer."""
    ctx, decision = _gate_and_emit("create_customer")
    mode = _init_stripe()

    import stripe

    try:
        kwargs: Dict[str, Any] = {"email": email}
        if name:
            kwargs["name"] = name
        if metadata:
            kwargs["metadata"] = metadata

        customer = stripe.Customer.create(**kwargs)

        detail = f"create_customer: id={customer.id} email={email} (mode={mode})"
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "create_customer", _attest_meta,
            extra={"stripe_mode": mode, "customer_id": customer.id},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult(
            "create_customer", True,
            {"id": customer.id, "email": customer.email, "name": customer.name},
            stripe_mode=mode,
        )

    except stripe.error.StripeError as exc:
        detail = f"create_customer Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "create_customer", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("create_customer", False, {}, error=detail, stripe_mode=mode)


def get_customer(customer_id: str) -> StripeOpResult:
    """Retrieve a single Stripe customer by ID."""
    ctx, decision = _gate_and_emit("get_customer")
    mode = _init_stripe()

    import stripe

    try:
        customer = stripe.Customer.retrieve(customer_id)

        detail = f"get_customer: id={customer.id} email={customer.email} (mode={mode})"
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "get_customer", _attest_meta,
            extra={"stripe_mode": mode, "customer_id": customer.id},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult(
            "get_customer", True,
            {
                "id": customer.id,
                "email": customer.email,
                "name": customer.name,
                "created": customer.created,
                "metadata": dict(customer.metadata) if customer.metadata else {},
            },
            stripe_mode=mode,
        )

    except stripe.error.StripeError as exc:
        detail = f"get_customer Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "get_customer", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("get_customer", False, {}, error=detail, stripe_mode=mode)


# --- Payment operations ---

def list_payments(
    limit: int = 25,
    customer_id: Optional[str] = None,
    status: Optional[str] = None,
) -> StripeOpResult:
    """List PaymentIntents. Optionally filter by customer or status."""
    ctx, decision = _gate_and_emit("list_payments")
    mode = _init_stripe()

    import stripe

    try:
        kwargs: Dict[str, Any] = {"limit": limit}
        if customer_id:
            kwargs["customer"] = customer_id
        # Stripe PaymentIntent.list does not support status filter server-side for all statuses,
        # but we pass it if provided and let Stripe handle it.
        # For statuses not natively filterable, we filter client-side below.
        response = stripe.PaymentIntent.list(**kwargs)

        intents = []
        for pi in response.auto_paging_iter():
            if status and pi.status != status:
                continue
            intents.append({
                "id": pi.id,
                "amount_cents": pi.amount,
                "currency": pi.currency,
                "status": pi.status,
                "customer": pi.customer,
                "description": pi.description,
                "created": pi.created,
            })
            if len(intents) >= limit:
                break

        detail = f"list_payments: {len(intents)} payment intents returned (mode={mode})"
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "list_payments", _attest_meta,
            extra={"stripe_mode": mode, "record_count": len(intents)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("list_payments", True, {"payments": intents}, stripe_mode=mode)

    except stripe.error.StripeError as exc:
        detail = f"list_payments Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "list_payments", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("list_payments", False, {}, error=detail, stripe_mode=mode)


def create_payment_intent(
    amount_cents: int,
    currency: str = "usd",
    customer_id: Optional[str] = None,
    description: Optional[str] = None,
) -> StripeOpResult:
    """
    Create a PaymentIntent.

    amount_cents: integer, smallest currency unit (e.g. 1999 = $19.99 USD).
    currency: ISO 4217 lowercase (default "usd").
    NEVER pass raw card data here — Stripe.js handles PCI scope on the client.
    """
    ctx, decision = _gate_and_emit("create_payment_intent")
    mode = _init_stripe()

    import stripe

    try:
        kwargs: Dict[str, Any] = {
            "amount": amount_cents,
            "currency": currency.lower(),
        }
        if customer_id:
            kwargs["customer"] = customer_id
        if description:
            kwargs["description"] = description

        pi = stripe.PaymentIntent.create(**kwargs)

        amount_display = f"{amount_cents / 100:.2f} {currency.upper()}"
        detail = (
            f"create_payment_intent: id={pi.id} amount={amount_display} "
            f"status={pi.status} (mode={mode})"
        )
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "create_payment_intent", _attest_meta,
            extra={
                "stripe_mode": mode,
                "payment_intent_id": pi.id,
                "amount_cents": amount_cents,
                "currency": currency.lower(),
            },
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult(
            "create_payment_intent", True,
            {
                "id": pi.id,
                "amount_cents": pi.amount,
                "currency": pi.currency,
                "status": pi.status,
                "client_secret": pi.client_secret,
            },
            stripe_mode=mode,
        )

    except stripe.error.StripeError as exc:
        detail = f"create_payment_intent Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "create_payment_intent", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("create_payment_intent", False, {}, error=detail, stripe_mode=mode)


def capture_payment(payment_intent_id: str) -> StripeOpResult:
    """Capture a PaymentIntent that was created with capture_method=manual."""
    ctx, decision = _gate_and_emit("capture_payment")
    mode = _init_stripe()

    import stripe

    try:
        pi = stripe.PaymentIntent.capture(payment_intent_id)

        amount_display = f"{pi.amount / 100:.2f} {pi.currency.upper()}"
        detail = (
            f"capture_payment: id={pi.id} amount={amount_display} "
            f"status={pi.status} (mode={mode})"
        )
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "capture_payment", _attest_meta,
            extra={
                "stripe_mode": mode,
                "payment_intent_id": pi.id,
                "amount_cents": pi.amount,
                "currency": pi.currency,
            },
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult(
            "capture_payment", True,
            {"id": pi.id, "amount_cents": pi.amount, "currency": pi.currency, "status": pi.status},
            stripe_mode=mode,
        )

    except stripe.error.StripeError as exc:
        detail = f"capture_payment Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "capture_payment", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("capture_payment", False, {}, error=detail, stripe_mode=mode)


# --- Subscription operations ---

def list_subscriptions(
    customer_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 25,
) -> StripeOpResult:
    """List subscriptions. Optionally filter by customer and/or status."""
    ctx, decision = _gate_and_emit("list_subscriptions")
    mode = _init_stripe()

    import stripe

    try:
        kwargs: Dict[str, Any] = {"limit": limit}
        if customer_id:
            kwargs["customer"] = customer_id
        if status:
            kwargs["status"] = status

        response = stripe.Subscription.list(**kwargs)
        subs = [
            {
                "id": s.id,
                "customer": s.customer,
                "status": s.status,
                "current_period_end": s.current_period_end,
                "cancel_at_period_end": s.cancel_at_period_end,
                "items": [
                    {"price_id": i.price.id, "quantity": i.quantity}
                    for i in s.items.data
                ],
            }
            for s in response.auto_paging_iter()
        ][:limit]

        detail = f"list_subscriptions: {len(subs)} subscriptions returned (mode={mode})"
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "list_subscriptions", _attest_meta,
            extra={"stripe_mode": mode, "record_count": len(subs)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("list_subscriptions", True, {"subscriptions": subs}, stripe_mode=mode)

    except stripe.error.StripeError as exc:
        detail = f"list_subscriptions Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "list_subscriptions", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("list_subscriptions", False, {}, error=detail, stripe_mode=mode)


def create_subscription(
    customer_id: str,
    price_id: str,
    trial_days: Optional[int] = None,
) -> StripeOpResult:
    """Create a subscription for a customer to a price."""
    ctx, decision = _gate_and_emit("create_subscription")
    mode = _init_stripe()

    import stripe

    try:
        kwargs: Dict[str, Any] = {
            "customer": customer_id,
            "items": [{"price": price_id}],
        }
        if trial_days is not None and trial_days > 0:
            kwargs["trial_period_days"] = trial_days

        sub = stripe.Subscription.create(**kwargs)

        detail = (
            f"create_subscription: id={sub.id} customer={customer_id} "
            f"price={price_id} status={sub.status} (mode={mode})"
        )
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "create_subscription", _attest_meta,
            extra={"stripe_mode": mode, "subscription_id": sub.id, "price_id": price_id},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult(
            "create_subscription", True,
            {
                "id": sub.id,
                "customer": sub.customer,
                "status": sub.status,
                "current_period_end": sub.current_period_end,
                "cancel_at_period_end": sub.cancel_at_period_end,
            },
            stripe_mode=mode,
        )

    except stripe.error.StripeError as exc:
        detail = f"create_subscription Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "create_subscription", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("create_subscription", False, {}, error=detail, stripe_mode=mode)


def cancel_subscription(
    subscription_id: str,
    at_period_end: bool = True,
) -> StripeOpResult:
    """
    Cancel a subscription.

    at_period_end=True (default): marks cancel_at_period_end=True, stays active
    until the end of the billing period.
    at_period_end=False: cancels immediately.
    """
    ctx, decision = _gate_and_emit("cancel_subscription")
    mode = _init_stripe()

    import stripe

    try:
        if at_period_end:
            sub = stripe.Subscription.modify(
                subscription_id, cancel_at_period_end=True
            )
        else:
            sub = stripe.Subscription.cancel(subscription_id)

        detail = (
            f"cancel_subscription: id={sub.id} status={sub.status} "
            f"cancel_at_period_end={sub.cancel_at_period_end} (mode={mode})"
        )
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "cancel_subscription", _attest_meta,
            extra={
                "stripe_mode": mode,
                "subscription_id": sub.id,
                "at_period_end": at_period_end,
            },
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult(
            "cancel_subscription", True,
            {
                "id": sub.id,
                "status": sub.status,
                "cancel_at_period_end": sub.cancel_at_period_end,
            },
            stripe_mode=mode,
        )

    except stripe.error.StripeError as exc:
        detail = f"cancel_subscription Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "cancel_subscription", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("cancel_subscription", False, {}, error=detail, stripe_mode=mode)


# --- Invoice operations ---

def list_invoices(
    customer_id: Optional[str] = None,
    limit: int = 25,
) -> StripeOpResult:
    """List invoices. Optionally filter by customer."""
    ctx, decision = _gate_and_emit("list_invoices")
    mode = _init_stripe()

    import stripe

    try:
        kwargs: Dict[str, Any] = {"limit": limit}
        if customer_id:
            kwargs["customer"] = customer_id

        response = stripe.Invoice.list(**kwargs)
        invoices = [
            {
                "id": inv.id,
                "customer": inv.customer,
                "amount_due_cents": inv.amount_due,
                "amount_paid_cents": inv.amount_paid,
                "currency": inv.currency,
                "status": inv.status,
                "created": inv.created,
            }
            for inv in response.auto_paging_iter()
        ][:limit]

        detail = f"list_invoices: {len(invoices)} invoices returned (mode={mode})"
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "list_invoices", _attest_meta,
            extra={"stripe_mode": mode, "record_count": len(invoices)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("list_invoices", True, {"invoices": invoices}, stripe_mode=mode)

    except stripe.error.StripeError as exc:
        detail = f"list_invoices Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "list_invoices", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("list_invoices", False, {}, error=detail, stripe_mode=mode)


def get_invoice(invoice_id: str) -> StripeOpResult:
    """Retrieve a single invoice by ID."""
    ctx, decision = _gate_and_emit("get_invoice")
    mode = _init_stripe()

    import stripe

    try:
        inv = stripe.Invoice.retrieve(invoice_id)

        amount_display = f"{inv.amount_due / 100:.2f} {inv.currency.upper()}"
        detail = (
            f"get_invoice: id={inv.id} amount_due={amount_display} "
            f"status={inv.status} (mode={mode})"
        )
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "get_invoice", _attest_meta,
            extra={"stripe_mode": mode, "invoice_id": inv.id},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult(
            "get_invoice", True,
            {
                "id": inv.id,
                "customer": inv.customer,
                "subscription": inv.subscription,
                "amount_due_cents": inv.amount_due,
                "amount_paid_cents": inv.amount_paid,
                "currency": inv.currency,
                "status": inv.status,
                "invoice_pdf": inv.invoice_pdf,
                "hosted_invoice_url": inv.hosted_invoice_url,
                "created": inv.created,
            },
            stripe_mode=mode,
        )

    except stripe.error.StripeError as exc:
        detail = f"get_invoice Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "get_invoice", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("get_invoice", False, {}, error=detail, stripe_mode=mode)


# --- Refund operations ---

def create_refund(
    payment_intent_id: Optional[str] = None,
    charge_id: Optional[str] = None,
    amount_cents: Optional[int] = None,
    reason: Optional[str] = None,
) -> StripeOpResult:
    """
    Create a refund.

    Provide either payment_intent_id or charge_id (not both).
    amount_cents: if None, refunds the full amount.
    reason: "duplicate" | "fraudulent" | "requested_by_customer" | None
    """
    if not payment_intent_id and not charge_id:
        log("ERROR: create_refund requires either --payment-intent-id or --charge-id")
        raise SystemExit(1)

    ctx, decision = _gate_and_emit("create_refund")
    mode = _init_stripe()

    import stripe

    try:
        kwargs: Dict[str, Any] = {}
        if payment_intent_id:
            kwargs["payment_intent"] = payment_intent_id
        if charge_id:
            kwargs["charge"] = charge_id
        if amount_cents is not None:
            kwargs["amount"] = amount_cents
        if reason:
            kwargs["reason"] = reason

        refund = stripe.Refund.create(**kwargs)

        amount_display = (
            f"{refund.amount / 100:.2f} {refund.currency.upper()}"
            if refund.amount else "full"
        )
        detail = (
            f"create_refund: id={refund.id} amount={amount_display} "
            f"status={refund.status} (mode={mode})"
        )
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "create_refund", _attest_meta,
            extra={
                "stripe_mode": mode,
                "refund_id": refund.id,
                "amount_cents": refund.amount,
                "currency": refund.currency,
            },
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult(
            "create_refund", True,
            {
                "id": refund.id,
                "amount_cents": refund.amount,
                "currency": refund.currency,
                "status": refund.status,
                "payment_intent": refund.payment_intent,
                "charge": refund.charge,
            },
            stripe_mode=mode,
        )

    except stripe.error.StripeError as exc:
        detail = f"create_refund Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "create_refund", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("create_refund", False, {}, error=detail, stripe_mode=mode)


# --- Product operations ---

def list_products(limit: int = 25, active: bool = True) -> StripeOpResult:
    """List products. active=True (default) returns only active products."""
    ctx, decision = _gate_and_emit("list_products")
    mode = _init_stripe()

    import stripe

    try:
        response = stripe.Product.list(limit=limit, active=active)
        products = [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "active": p.active,
                "created": p.created,
                "metadata": dict(p.metadata) if p.metadata else {},
            }
            for p in response.auto_paging_iter()
        ][:limit]

        detail = f"list_products: {len(products)} products returned (mode={mode})"
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "list_products", _attest_meta,
            extra={"stripe_mode": mode, "record_count": len(products)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("list_products", True, {"products": products}, stripe_mode=mode)

    except stripe.error.StripeError as exc:
        detail = f"list_products Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "list_products", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("list_products", False, {}, error=detail, stripe_mode=mode)


def create_product(
    name: str,
    description: Optional[str] = None,
    metadata: Optional[Dict[str, str]] = None,
) -> StripeOpResult:
    """Create a new Stripe product."""
    ctx, decision = _gate_and_emit("create_product")
    mode = _init_stripe()

    import stripe

    try:
        kwargs: Dict[str, Any] = {"name": name}
        if description:
            kwargs["description"] = description
        if metadata:
            kwargs["metadata"] = metadata

        product = stripe.Product.create(**kwargs)

        detail = f"create_product: id={product.id} name={name!r} (mode={mode})"
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "create_product", _attest_meta,
            extra={"stripe_mode": mode, "product_id": product.id},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult(
            "create_product", True,
            {"id": product.id, "name": product.name, "active": product.active},
            stripe_mode=mode,
        )

    except stripe.error.StripeError as exc:
        detail = f"create_product Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "create_product", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("create_product", False, {}, error=detail, stripe_mode=mode)


# --- Price operations ---

def create_price(
    product_id: str,
    unit_amount_cents: int,
    currency: str = "usd",
    recurring_interval: Optional[str] = None,
) -> StripeOpResult:
    """
    Create a price for a product.

    recurring_interval: "month" | "year" for recurring prices, None for one-time.
    unit_amount_cents: integer, smallest currency unit (e.g. 999 = $9.99 USD).
    """
    ctx, decision = _gate_and_emit("create_price")
    mode = _init_stripe()

    import stripe

    try:
        kwargs: Dict[str, Any] = {
            "product": product_id,
            "unit_amount": unit_amount_cents,
            "currency": currency.lower(),
        }
        if recurring_interval:
            if recurring_interval not in ("month", "year"):
                log(f"ERROR: recurring_interval must be 'month' or 'year', got {recurring_interval!r}")
                raise SystemExit(1)
            kwargs["recurring"] = {"interval": recurring_interval}

        price = stripe.Price.create(**kwargs)

        amount_display = f"{unit_amount_cents / 100:.2f} {currency.upper()}"
        price_type = f"recurring/{recurring_interval}" if recurring_interval else "one-time"
        detail = (
            f"create_price: id={price.id} amount={amount_display} "
            f"type={price_type} product={product_id} (mode={mode})"
        )
        log(detail)
        receipt = build_evidence_receipt(
            ctx, decision, "ok", detail, "create_price", _attest_meta,
            extra={
                "stripe_mode": mode,
                "price_id": price.id,
                "product_id": product_id,
                "unit_amount_cents": unit_amount_cents,
                "currency": currency.lower(),
                "recurring_interval": recurring_interval,
            },
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult(
            "create_price", True,
            {
                "id": price.id,
                "product": price.product,
                "unit_amount_cents": price.unit_amount,
                "currency": price.currency,
                "type": price.type,
                "recurring": dict(price.recurring) if price.recurring else None,
            },
            stripe_mode=mode,
        )

    except stripe.error.StripeError as exc:
        detail = f"create_price Stripe error: {exc.user_message or str(exc)}"
        log(f"ERROR: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, "create_price", _attest_meta,
            extra={"stripe_mode": mode, "stripe_error_code": getattr(exc, "code", None)},
        )
        _evidence_log.emit_evidence(receipt)
        return StripeOpResult("create_price", False, {}, error=detail, stripe_mode=mode)


# --- Dispatch table ---

def _dispatch(op: str, args: argparse.Namespace) -> StripeOpResult:
    """Route a parsed CLI op to the appropriate domain function."""
    if op == "list_customers":
        return list_customers(
            limit=args.limit,
            email=args.email,
        )
    elif op == "create_customer":
        metadata = _parse_metadata(args.metadata) if args.metadata else None
        return create_customer(
            email=args.email,
            name=args.name,
            metadata=metadata,
        )
    elif op == "get_customer":
        return get_customer(customer_id=args.customer_id)

    elif op == "list_payments":
        return list_payments(
            limit=args.limit,
            customer_id=args.customer_id,
            status=args.status,
        )
    elif op == "create_payment_intent":
        return create_payment_intent(
            amount_cents=args.amount_cents,
            currency=args.currency,
            customer_id=args.customer_id,
            description=args.description,
        )
    elif op == "capture_payment":
        return capture_payment(payment_intent_id=args.payment_intent_id)

    elif op == "list_subscriptions":
        return list_subscriptions(
            customer_id=args.customer_id,
            status=args.status,
            limit=args.limit,
        )
    elif op == "create_subscription":
        return create_subscription(
            customer_id=args.customer_id,
            price_id=args.price_id,
            trial_days=args.trial_days,
        )
    elif op == "cancel_subscription":
        return cancel_subscription(
            subscription_id=args.subscription_id,
            at_period_end=not args.immediate,
        )

    elif op == "list_invoices":
        return list_invoices(
            customer_id=args.customer_id,
            limit=args.limit,
        )
    elif op == "get_invoice":
        return get_invoice(invoice_id=args.invoice_id)

    elif op == "create_refund":
        return create_refund(
            payment_intent_id=args.payment_intent_id,
            charge_id=args.charge_id,
            amount_cents=args.amount_cents,
            reason=args.reason,
        )

    elif op == "list_products":
        inactive = getattr(args, "inactive", False)
        return list_products(limit=args.limit, active=not inactive)
    elif op == "create_product":
        metadata = _parse_metadata(args.metadata) if args.metadata else None
        return create_product(
            name=args.name,
            description=args.description,
            metadata=metadata,
        )
    elif op == "create_price":
        return create_price(
            product_id=args.product_id,
            unit_amount_cents=args.unit_amount_cents,
            currency=args.currency,
            recurring_interval=args.recurring_interval,
        )

    else:
        log(f"ERROR: unknown op={op!r}")
        raise SystemExit(1)


def _parse_metadata(raw: str) -> Dict[str, str]:
    """Parse key=value,key2=value2 into a dict. Raises SystemExit on parse error."""
    try:
        pairs = [pair.strip() for pair in raw.split(",") if pair.strip()]
        return dict(pair.split("=", 1) for pair in pairs)
    except Exception as exc:
        log(f"ERROR: could not parse metadata {raw!r}: {exc}")
        log("  Expected format: key1=value1,key2=value2")
        raise SystemExit(1)


# ============================================================================
# SECTION 8: ENTRY POINT
# ============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=WORKER_NAME,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 bootstrap.py list_customers --limit 10\n"
            "  python3 bootstrap.py create_customer --email user@example.com --name 'Jane Doe'\n"
            "  python3 bootstrap.py get_customer --customer-id cus_xxx\n"
            "  python3 bootstrap.py list_payments --customer-id cus_xxx --status succeeded\n"
            "  python3 bootstrap.py create_payment_intent --amount-cents 1999 --currency usd\n"
            "  python3 bootstrap.py capture_payment --payment-intent-id pi_xxx\n"
            "  python3 bootstrap.py list_subscriptions --customer-id cus_xxx\n"
            "  python3 bootstrap.py create_subscription --customer-id cus_xxx --price-id price_xxx\n"
            "  python3 bootstrap.py cancel_subscription --subscription-id sub_xxx\n"
            "  python3 bootstrap.py cancel_subscription --subscription-id sub_xxx --immediate\n"
            "  python3 bootstrap.py list_invoices --customer-id cus_xxx\n"
            "  python3 bootstrap.py get_invoice --invoice-id in_xxx\n"
            "  python3 bootstrap.py create_refund --payment-intent-id pi_xxx --amount-cents 500\n"
            "  python3 bootstrap.py create_refund --payment-intent-id pi_xxx  # full refund\n"
            "  python3 bootstrap.py list_products\n"
            "  python3 bootstrap.py create_product --name 'Pro Plan' --description 'All features'\n"
            "  python3 bootstrap.py create_price --product-id prod_xxx --unit-amount-cents 999 "
            "--recurring-interval month\n"
        ),
    )

    p.add_argument(
        "op",
        choices=sorted(ALLOWED_OPS),
        help="Operation to perform",
    )

    # ── Shared / reused args ──────────────────────────────────────────────────
    p.add_argument("--limit", type=int, default=25, metavar="N",
                   help="Max records to return (default: 25)")
    p.add_argument("--email", default=None, metavar="EMAIL",
                   help="Customer email (filter or create)")
    p.add_argument("--name", default=None, metavar="NAME",
                   help="Name (customer or product)")
    p.add_argument("--description", default=None, metavar="TEXT",
                   help="Description (product or payment)")
    p.add_argument("--metadata", default=None, metavar="KEY=VAL,KEY2=VAL2",
                   help="Metadata pairs (customer or product)")
    p.add_argument("--currency", default="usd", metavar="CURRENCY",
                   help="ISO 4217 currency code (default: usd)")
    p.add_argument("--status", default=None, metavar="STATUS",
                   help="Filter by status (list_payments, list_subscriptions)")

    # ── ID args ───────────────────────────────────────────────────────────────
    p.add_argument("--customer-id", default=None, dest="customer_id", metavar="cus_xxx",
                   help="Stripe customer ID")
    p.add_argument("--payment-intent-id", default=None, dest="payment_intent_id", metavar="pi_xxx",
                   help="Stripe PaymentIntent ID")
    p.add_argument("--charge-id", default=None, dest="charge_id", metavar="ch_xxx",
                   help="Stripe Charge ID (for create_refund)")
    p.add_argument("--subscription-id", default=None, dest="subscription_id", metavar="sub_xxx",
                   help="Stripe Subscription ID")
    p.add_argument("--invoice-id", default=None, dest="invoice_id", metavar="in_xxx",
                   help="Stripe Invoice ID")
    p.add_argument("--product-id", default=None, dest="product_id", metavar="prod_xxx",
                   help="Stripe Product ID (for create_price)")
    p.add_argument("--price-id", default=None, dest="price_id", metavar="price_xxx",
                   help="Stripe Price ID (for create_subscription)")

    # ── Amount / financial args ───────────────────────────────────────────────
    p.add_argument("--amount-cents", type=int, default=None, dest="amount_cents",
                   metavar="CENTS",
                   help="Amount in smallest currency unit (e.g. 1999 = $19.99)")
    p.add_argument("--unit-amount-cents", type=int, default=None, dest="unit_amount_cents",
                   metavar="CENTS",
                   help="Unit amount in cents for create_price")

    # ── Subscription-specific ─────────────────────────────────────────────────
    p.add_argument("--trial-days", type=int, default=None, dest="trial_days",
                   metavar="DAYS",
                   help="Trial period days for create_subscription")
    p.add_argument("--immediate", action="store_true",
                   help="Cancel subscription immediately (default: at period end)")

    # ── Refund-specific ───────────────────────────────────────────────────────
    p.add_argument("--reason", default=None,
                   choices=["duplicate", "fraudulent", "requested_by_customer"],
                   help="Refund reason")

    # ── Price-specific ────────────────────────────────────────────────────────
    p.add_argument(
        "--recurring-interval", default=None, dest="recurring_interval",
        choices=["month", "year"],
        help="Billing interval for recurring price (omit for one-time)",
    )

    # ── Product filter ────────────────────────────────────────────────────────
    p.add_argument("--inactive", action="store_true",
                   help="list_products: include inactive products instead of active")

    # ── Output ────────────────────────────────────────────────────────────────
    p.add_argument("--json", action="store_true", dest="output_json",
                   help="Output result as JSON to stdout")

    return p


def run() -> None:
    """WCP worker entry point. Called from bootstrap.py and CLI shim."""
    global _attest_meta

    # Startup attestation — warning in dev, hard-fail in prod
    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    parser = build_arg_parser()
    args = parser.parse_args()
    op = args.op

    result = _dispatch(op, args)

    if args.output_json:
        print(json.dumps(result.data, indent=2, default=str))
    else:
        if result.success:
            log(f"Done: op={op} status=ok mode={result.stripe_mode}")
        else:
            log(f"Done: op={op} status=error: {result.error}")
            sys.exit(1)


if __name__ == "__main__":
    run()
