#!/usr/bin/env python3
"""
worker_logic.py — HuggingFace Worker (WCP v0.3.0)

Provides access to the HuggingFace Inference API and Hub API.
Supports text generation, summarization, zero-shot classification, embeddings,
model/space/dataset discovery, and Gradio Space API calls.

Auth: set HF_TOKEN in the environment before running.
Evidence log: ~/.local/share/pyhall/evidence/wrk_pyhall_huggingface_chain.log

Quick start:
    python3 bootstrap.py run_text_generation --model-id "mistralai/Mistral-7B-Instruct-v0.3" --prompt "Hello, world!"
    python3 bootstrap.py run_summarization --text "Long article text here..."
    python3 bootstrap.py run_classification --model-id "facebook/bart-large-mnli" --text "I love this!" --labels '["positive","negative"]'
    python3 bootstrap.py run_embeddings --texts '["Hello world","Foo bar"]'
    python3 bootstrap.py list_models --task text-generation --limit 10
    python3 bootstrap.py get_model_info --model-id "gpt2"
    python3 bootstrap.py search_models --query "sentence transformers" --limit 5
    python3 bootstrap.py list_spaces --limit 10
    python3 bootstrap.py get_space_info --space-id "stabilityai/stable-diffusion"
    python3 bootstrap.py list_datasets --search "common voice" --limit 10
    python3 bootstrap.py get_dataset_info --dataset-id "mozilla-foundation/common_voice_11_0"
    python3 bootstrap.py run_inference --model-id "gpt2" --inputs "The quick brown fox"
    python3 bootstrap.py run_space_api --space-id "ResembleAI/chatterbox" --api-name "/generate" --inputs '["Hello!"]'
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
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

WORKER_ID          = "org.pyhall.huggingface.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.huggingface"
WORKER_NAME        = "HuggingFace Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.huggingface.inference",
    "cap.pyhall.huggingface.read",
    "cap.pyhall.huggingface.manage",
]

ALLOWED_OPS = {
    "run_inference",
    "run_text_generation",
    "run_summarization",
    "run_classification",
    "run_embeddings",
    "list_models",
    "get_model_info",
    "list_spaces",
    "get_space_info",
    "list_datasets",
    "get_dataset_info",
    "run_space_api",
    "search_models",
}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

ALLOWED_ENVS = {"dev", "stage", "prod"}

# Map ops → capability_id
_OP_CAPABILITY: Dict[str, str] = {
    "run_inference":        "cap.pyhall.huggingface.inference",
    "run_text_generation":  "cap.pyhall.huggingface.inference",
    "run_summarization":    "cap.pyhall.huggingface.inference",
    "run_classification":   "cap.pyhall.huggingface.inference",
    "run_embeddings":       "cap.pyhall.huggingface.inference",
    "run_space_api":        "cap.pyhall.huggingface.inference",
    "list_models":          "cap.pyhall.huggingface.read",
    "get_model_info":       "cap.pyhall.huggingface.read",
    "search_models":        "cap.pyhall.huggingface.read",
    "list_spaces":          "cap.pyhall.huggingface.read",
    "get_space_info":       "cap.pyhall.huggingface.read",
    "list_datasets":        "cap.pyhall.huggingface.read",
    "get_dataset_info":     "cap.pyhall.huggingface.read",
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
class InferenceRecord:
    """Lightweight record of an inference call."""
    model_id: str
    op: str
    status: str
    requested_at: str
    detail: Optional[str]


# ============================================================================
# SECTION 3: UTILS
# ============================================================================

_CT = ZoneInfo("America/Chicago")

# HuggingFace API base URLs
_HF_INFERENCE_BASE = "https://api-inference.huggingface.co/models"
_HF_HUB_BASE       = "https://huggingface.co/api"

# Model loading retry config
_MODEL_LOAD_RETRIES   = 3
_MODEL_LOAD_WAIT_SECS = 20


def utc_now_iso() -> str:
    """Return current UTC time as ISO 8601 string with Z suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def now_ct() -> str:
    """Return current Central Time as human-readable string."""
    return datetime.now(_CT).strftime("%Y-%m-%d %H:%M:%S CT")


def log(msg: str) -> None:
    """Print a message with Central Time timestamp."""
    print(f"[{now_ct()}] {msg}")


def sha256_hex_bytes(b: bytes) -> str:
    """Return SHA-256 hex digest of bytes."""
    return hashlib.sha256(b).hexdigest()


def load_json(path: Path) -> Any:
    """Load JSON from a file path."""
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    """Write JSON to a file path, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


# ============================================================================
# SECTION 4: PACKAGE ATTESTATION + SIGNATURE VERIFICATION
# ============================================================================
# required for PyHall APP.
# not strictly required in-file for API-only usage.
# if this worker file changes, a new attestation is required.


def _run_startup_attestation(package_root: Path, manifest_path: Path) -> Dict[str, Any]:
    """
    Run full package attestation using the pyhall PackageAttestationVerifier.

    In dev (PYHALL_ENV != 'prod') and WCP_ATTEST_HMAC_KEY not set:
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
#   code/worker_logic.py → package root is huggingface_worker/
_THIS_FILE     = Path(__file__).resolve()
_PACKAGE_ROOT  = _THIS_FILE.parent.parent   # .../huggingface_worker/
_MANIFEST_PATH = _PACKAGE_ROOT / "manifest.json"


# ============================================================================
# SECTION 5: POLICY GATE (FAIL-CLOSED)
# ============================================================================

class PolicyGate:
    """
    Local fail-closed WCP policy gate.

    Evaluates a WCPContext + operation dict. Returns WCPDecision.
    Deny is the default — every check must pass to allow.
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

        if not ctx.correlation_id:
            return WCPDecision(
                False, "CORRELATION_ID_REQUIRED",
                "missing correlation_id",
                self.policy_version, None, None,
            )

        rule_id = f"rr_huggingface_{op}_allow_v1"
        return WCPDecision(True, None, None, self.policy_version, rule_id, WORKER_SPECIES_ID)


# ============================================================================
# SECTION 6: OBSERVABILITY — HASH-CHAINED EVIDENCE LOG
# ============================================================================

_EVIDENCE_LOG_PATH = (
    Path(os.path.expanduser("~/.local/share/pyhall/evidence/"))
    / f"{WORKER_SPECIES_ID.replace('.', '_')}_chain.log"
)


class AppendOnlyEvidenceLog:
    """
    Hash-chained append-only local evidence log.

    Each entry records: prev_hash, entry_hash (prev_hash + payload), receipt dict.
    Writes are best-effort — will not crash if directory is absent.
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
) -> Dict[str, Any]:
    """Build a WCP evidence receipt dict."""
    payload_hash = sha256_hex_bytes(
        json.dumps({"op": op, "worker_id": WORKER_ID}, sort_keys=True).encode("utf-8")
    )
    return {
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


# Module-level singletons
_policy_gate  = PolicyGate()
_evidence_log = AppendOnlyEvidenceLog(_EVIDENCE_LOG_PATH)
_attest_meta: Dict[str, Any] = {}   # populated by run() at startup


def _make_ctx(op: str) -> WCPContext:
    """Build a WCPContext for the given operation."""
    return WCPContext(
        correlation_id=str(uuid.uuid4()),
        env=os.environ.get("PYHALL_ENV", "dev"),
        capability_id=_OP_CAPABILITY.get(op, CAPABILITIES[0]),
        data_label="INTERNAL",
        tenant_risk="low",
        qos_class="P2",
        requested_at_utc=utc_now_iso(),
    )


def _gate_and_emit(op: str) -> Tuple[WCPContext, WCPDecision]:
    """Run the policy gate for an operation and emit a deny receipt if blocked."""
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
# SECTION 7: DOMAIN LOGIC — HUGGINGFACE INFERENCE + HUB APIs
# ============================================================================

# ---------------------------------------------------------------------------
# HuggingFace client helpers
# ---------------------------------------------------------------------------

def _get_hf_token() -> str:
    """
    Return the HuggingFace API token from the environment.

    Checks HF_TOKEN by default, or the var named in HF_TOKEN_ENV.
    Raises RuntimeError with a clear message if not set.
    """
    token_env = os.environ.get("HF_TOKEN_ENV", "HF_TOKEN")
    token = os.environ.get(token_env, "").strip()
    if not token:
        raise RuntimeError(
            f"HuggingFace API token not set (checked env var: {token_env!r}). "
            "Export HF_TOKEN=<your-token> before running."
        )
    return token


def _hf_headers(token: str) -> Dict[str, str]:
    """Return standard HuggingFace request headers."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _hf_post_with_retry(
    url: str,
    payload: Dict[str, Any],
    token: str,
    retries: int = _MODEL_LOAD_RETRIES,
    wait_secs: int = _MODEL_LOAD_WAIT_SECS,
) -> Any:
    """
    POST to a HuggingFace Inference API endpoint with model-loading retry logic.

    HuggingFace returns HTTP 503 with {"error": "...", "estimated_time": N}
    when a model is still loading. Retries up to `retries` times, waiting
    `wait_secs` seconds between attempts.

    Returns parsed JSON response on success.
    Raises RuntimeError on unrecoverable errors.
    """
    try:
        import requests as _requests
    except ImportError as exc:
        raise RuntimeError(
            f"requests package not installed: {exc}. Run: pip install 'requests>=2.28.0'"
        ) from exc

    for attempt in range(1, retries + 2):  # +2: initial try + retries
        resp = _requests.post(url, headers=_hf_headers(token), json=payload, timeout=120)

        if resp.status_code == 503:
            body: Any = {}
            try:
                body = resp.json()
            except Exception:
                pass
            error_str = str(body.get("error", "")).lower() if isinstance(body, dict) else ""
            is_loading = "loading" in error_str or "currently loading" in error_str

            if is_loading and attempt <= retries:
                wait = body.get("estimated_time", wait_secs) if isinstance(body, dict) else wait_secs
                wait = min(float(wait), 60.0)  # cap at 60s regardless of HF estimate
                log(
                    f"Model loading (attempt {attempt}/{retries}), "
                    f"waiting {wait:.0f}s — {url}"
                )
                time.sleep(wait)
                continue

            # 503 but not a loading state, or retries exhausted
            raise RuntimeError(
                f"HF Inference API 503 after {attempt} attempt(s): {body}"
            )

        if not resp.ok:
            raise RuntimeError(
                f"HF Inference API error {resp.status_code}: {resp.text[:500]}"
            )

        return resp.json()

    # Should not be reached, but guard anyway
    raise RuntimeError(f"HF Inference API: exhausted {retries} retries for {url}")


def _hf_get(
    url: str,
    token: str,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    """
    GET from a HuggingFace Hub API endpoint.

    Returns parsed JSON on success. Raises RuntimeError on failure.
    """
    try:
        import requests as _requests
    except ImportError as exc:
        raise RuntimeError(
            f"requests package not installed: {exc}. Run: pip install 'requests>=2.28.0'"
        ) from exc

    headers = {
        "Authorization": f"Bearer {token}",
    }
    resp = _requests.get(url, headers=headers, params=params, timeout=60)

    if not resp.ok:
        raise RuntimeError(
            f"HF Hub API error {resp.status_code}: {resp.text[:500]}"
        )

    return resp.json()


# ---------------------------------------------------------------------------
# Op: run_inference
# ---------------------------------------------------------------------------

def run_inference(
    model_id: str,
    inputs: Any,
    parameters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    POST to HuggingFace Inference API for the given model_id.

    Returns raw model output wrapped in a result dict.

    Args:
        model_id:   HuggingFace model ID, e.g. "gpt2", "facebook/bart-large-cnn"
        inputs:     Inputs to the model (string, list of strings, etc.)
        parameters: Optional parameters dict passed directly to the model
    """
    op = "run_inference"
    ctx, decision = _gate_and_emit(op)

    try:
        token = _get_hf_token()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hf_token_missing", "detail": str(exc)}

    url = f"{_HF_INFERENCE_BASE}/{model_id}"
    payload: Dict[str, Any] = {"inputs": inputs}
    if parameters:
        payload["parameters"] = parameters

    try:
        raw_output = _hf_post_with_retry(url, payload, token)
    except RuntimeError as exc:
        log(f"ERROR run_inference model_id={model_id}: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"run_inference model_id={model_id} error: {exc}", op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "inference_error", "model_id": model_id, "detail": str(exc)}

    detail = f"run_inference: model_id={model_id} completed"
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return {"model_id": model_id, "output": raw_output}


# ---------------------------------------------------------------------------
# Op: run_text_generation
# ---------------------------------------------------------------------------

def run_text_generation(
    model_id: str,
    prompt: str,
    max_new_tokens: int = 200,
    temperature: float = 0.7,
    do_sample: bool = True,
) -> Dict[str, Any]:
    """
    Run text generation on the specified model.

    Returns {"model_id": str, "generated_text": str, "raw_output": ...}

    Args:
        model_id:       HuggingFace model ID, e.g. "mistralai/Mistral-7B-Instruct-v0.3"
        prompt:         Input prompt string
        max_new_tokens: Maximum tokens to generate (default 200)
        temperature:    Sampling temperature (default 0.7)
        do_sample:      Use sampling (True) or greedy decoding (False)
    """
    op = "run_text_generation"
    ctx, decision = _gate_and_emit(op)

    try:
        token = _get_hf_token()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hf_token_missing", "detail": str(exc)}

    url = f"{_HF_INFERENCE_BASE}/{model_id}"
    payload: Dict[str, Any] = {
        "inputs": prompt,
        "parameters": {
            "max_new_tokens": max_new_tokens,
            "temperature": temperature,
            "do_sample": do_sample,
            "return_full_text": False,
        },
    }

    try:
        raw_output = _hf_post_with_retry(url, payload, token)
    except RuntimeError as exc:
        log(f"ERROR run_text_generation model_id={model_id}: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"run_text_generation model_id={model_id} error: {exc}", op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "inference_error", "model_id": model_id, "detail": str(exc)}

    # Extract generated text from standard HF text-gen response shape
    generated_text = ""
    if isinstance(raw_output, list) and len(raw_output) > 0:
        first = raw_output[0]
        if isinstance(first, dict):
            generated_text = first.get("generated_text", str(first))
        else:
            generated_text = str(first)
    elif isinstance(raw_output, dict):
        generated_text = raw_output.get("generated_text", str(raw_output))
    else:
        generated_text = str(raw_output)

    detail = f"run_text_generation: model_id={model_id} generated {len(generated_text)} chars"
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return {
        "model_id": model_id,
        "generated_text": generated_text,
        "raw_output": raw_output,
    }


# ---------------------------------------------------------------------------
# Op: run_summarization
# ---------------------------------------------------------------------------

def run_summarization(
    text: str,
    model_id: str = "facebook/bart-large-cnn",
    max_length: int = 130,
    min_length: int = 30,
) -> Dict[str, Any]:
    """
    Run summarization on the given text.

    Returns {"model_id": str, "summary": str, "raw_output": ...}

    Args:
        text:      Text to summarize
        model_id:  Summarization model (default: facebook/bart-large-cnn)
        max_length: Max tokens in summary (default 130)
        min_length: Min tokens in summary (default 30)
    """
    op = "run_summarization"
    ctx, decision = _gate_and_emit(op)

    try:
        token = _get_hf_token()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hf_token_missing", "detail": str(exc)}

    url = f"{_HF_INFERENCE_BASE}/{model_id}"
    payload: Dict[str, Any] = {
        "inputs": text,
        "parameters": {
            "max_length": max_length,
            "min_length": min_length,
        },
    }

    try:
        raw_output = _hf_post_with_retry(url, payload, token)
    except RuntimeError as exc:
        log(f"ERROR run_summarization model_id={model_id}: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"run_summarization model_id={model_id} error: {exc}", op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "inference_error", "model_id": model_id, "detail": str(exc)}

    # Extract summary text from standard HF summarization response shape
    summary = ""
    if isinstance(raw_output, list) and len(raw_output) > 0:
        first = raw_output[0]
        if isinstance(first, dict):
            summary = first.get("summary_text", str(first))
        else:
            summary = str(first)
    elif isinstance(raw_output, dict):
        summary = raw_output.get("summary_text", str(raw_output))
    else:
        summary = str(raw_output)

    detail = f"run_summarization: model_id={model_id} summary {len(summary)} chars"
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return {
        "model_id": model_id,
        "summary": summary,
        "raw_output": raw_output,
    }


# ---------------------------------------------------------------------------
# Op: run_classification
# ---------------------------------------------------------------------------

def run_classification(
    text: str,
    candidate_labels: List[str],
    model_id: str = "facebook/bart-large-mnli",
) -> Dict[str, Any]:
    """
    Run zero-shot classification on the given text.

    Returns {"model_id": str, "classifications": [{"label": str, "score": float}]}
    sorted by score descending.

    Args:
        text:             Text to classify
        candidate_labels: List of candidate label strings
        model_id:         Zero-shot classification model (default: facebook/bart-large-mnli)
    """
    op = "run_classification"
    ctx, decision = _gate_and_emit(op)

    try:
        token = _get_hf_token()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hf_token_missing", "detail": str(exc)}

    if not candidate_labels:
        detail = "run_classification: candidate_labels must not be empty"
        log(f"ERROR {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "invalid_input", "detail": detail}

    url = f"{_HF_INFERENCE_BASE}/{model_id}"
    payload: Dict[str, Any] = {
        "inputs": text,
        "parameters": {"candidate_labels": candidate_labels},
    }

    try:
        raw_output = _hf_post_with_retry(url, payload, token)
    except RuntimeError as exc:
        log(f"ERROR run_classification model_id={model_id}: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"run_classification model_id={model_id} error: {exc}", op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "inference_error", "model_id": model_id, "detail": str(exc)}

    # Standard HF zero-shot response: {"labels": [...], "scores": [...], "sequence": "..."}
    classifications: List[Dict[str, Any]] = []
    if isinstance(raw_output, dict):
        labels = raw_output.get("labels", [])
        scores = raw_output.get("scores", [])
        classifications = [
            {"label": lbl, "score": float(scr)}
            for lbl, scr in zip(labels, scores)
        ]
        # Sort descending by score (HF already does this, but ensure it)
        classifications.sort(key=lambda x: x["score"], reverse=True)
    else:
        classifications = [{"raw": raw_output}]  # type: ignore[list-item]

    detail = (
        f"run_classification: model_id={model_id} "
        f"{len(candidate_labels)} labels, top={classifications[0]['label'] if classifications else 'n/a'}"
    )
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return {
        "model_id": model_id,
        "classifications": classifications,
        "raw_output": raw_output,
    }


# ---------------------------------------------------------------------------
# Op: run_embeddings
# ---------------------------------------------------------------------------

def run_embeddings(
    texts: List[str],
    model_id: str = "sentence-transformers/all-MiniLM-L6-v2",
) -> Dict[str, Any]:
    """
    Generate embeddings for a list of texts.

    Returns {"model_id": str, "embeddings": [[float, ...], ...], "count": int}

    Args:
        texts:    List of strings to embed
        model_id: Embedding model (default: sentence-transformers/all-MiniLM-L6-v2)
    """
    op = "run_embeddings"
    ctx, decision = _gate_and_emit(op)

    try:
        token = _get_hf_token()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hf_token_missing", "detail": str(exc)}

    if not texts:
        detail = "run_embeddings: texts must not be empty"
        log(f"ERROR {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "invalid_input", "detail": detail}

    url = f"{_HF_INFERENCE_BASE}/{model_id}"
    payload: Dict[str, Any] = {"inputs": texts}

    try:
        raw_output = _hf_post_with_retry(url, payload, token)
    except RuntimeError as exc:
        log(f"ERROR run_embeddings model_id={model_id}: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"run_embeddings model_id={model_id} error: {exc}", op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "inference_error", "model_id": model_id, "detail": str(exc)}

    # raw_output should be a list of float lists (one per input text)
    embeddings: List[List[float]] = []
    if isinstance(raw_output, list):
        embeddings = raw_output
    else:
        embeddings = [raw_output]

    detail = (
        f"run_embeddings: model_id={model_id} "
        f"{len(texts)} texts → {len(embeddings)} embeddings"
    )
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return {
        "model_id": model_id,
        "embeddings": embeddings,
        "count": len(embeddings),
    }


# ---------------------------------------------------------------------------
# Op: list_models
# ---------------------------------------------------------------------------

def list_models(
    search: Optional[str] = None,
    task: Optional[str] = None,
    limit: int = 20,
    sort: str = "downloads",
) -> Dict[str, Any]:
    """
    List models from the HuggingFace Hub.

    Returns {"models": [...], "count": int}
    Each model entry: modelId, task, downloads, likes, lastModified, tags

    Args:
        search: Optional search query string
        task:   Optional task filter, e.g. "text-generation"
        limit:  Maximum results (default 20)
        sort:   Sort field — "downloads" (default), "likes", "lastModified"
    """
    op = "list_models"
    ctx, decision = _gate_and_emit(op)

    try:
        token = _get_hf_token()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hf_token_missing", "detail": str(exc)}

    params: Dict[str, Any] = {"limit": limit, "sort": sort, "direction": -1}
    if search:
        params["search"] = search
    if task:
        params["pipeline_tag"] = task

    try:
        raw_output = _hf_get(f"{_HF_HUB_BASE}/models", token, params=params)
    except RuntimeError as exc:
        log(f"ERROR list_models: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", f"list_models error: {exc}", op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hub_api_error", "detail": str(exc)}

    models = []
    raw_list = raw_output if isinstance(raw_output, list) else []
    for m in raw_list:
        if not isinstance(m, dict):
            continue
        models.append({
            "modelId":      m.get("modelId") or m.get("id", ""),
            "task":         m.get("pipeline_tag", ""),
            "downloads":    m.get("downloads", 0),
            "likes":        m.get("likes", 0),
            "lastModified": m.get("lastModified", ""),
            "tags":         m.get("tags", []),
        })

    detail = f"list_models: {len(models)} models returned (search={search!r}, task={task!r})"
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return {"models": models, "count": len(models)}


# ---------------------------------------------------------------------------
# Op: get_model_info
# ---------------------------------------------------------------------------

def get_model_info(model_id: str) -> Dict[str, Any]:
    """
    Retrieve detailed metadata for a specific model from the HuggingFace Hub.

    Returns: modelId, task, downloads, likes, tags, cardData, siblings (files)
    """
    op = "get_model_info"
    ctx, decision = _gate_and_emit(op)

    try:
        token = _get_hf_token()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hf_token_missing", "detail": str(exc)}

    try:
        raw = _hf_get(f"{_HF_HUB_BASE}/models/{model_id}", token)
    except RuntimeError as exc:
        log(f"ERROR get_model_info model_id={model_id}: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"get_model_info model_id={model_id} error: {exc}", op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hub_api_error", "model_id": model_id, "detail": str(exc)}

    result: Dict[str, Any] = {}
    if isinstance(raw, dict):
        result = {
            "modelId":      raw.get("modelId") or raw.get("id", model_id),
            "task":         raw.get("pipeline_tag", ""),
            "downloads":    raw.get("downloads", 0),
            "likes":        raw.get("likes", 0),
            "tags":         raw.get("tags", []),
            "cardData":     raw.get("cardData", {}),
            "siblings":     raw.get("siblings", []),
        }
    else:
        result = {"raw": raw}

    detail = f"get_model_info: model_id={model_id} retrieved"
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# ---------------------------------------------------------------------------
# Op: search_models
# ---------------------------------------------------------------------------

def search_models(
    query: str,
    task: Optional[str] = None,
    limit: int = 10,
) -> Dict[str, Any]:
    """
    Search for models by query string on the HuggingFace Hub.

    Returns {"models": [...], "count": int, "query": str}
    """
    op = "search_models"
    ctx, decision = _gate_and_emit(op)

    try:
        token = _get_hf_token()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hf_token_missing", "detail": str(exc)}

    params: Dict[str, Any] = {
        "search": query,
        "limit": limit,
        "sort": "downloads",
        "direction": -1,
    }
    if task:
        params["pipeline_tag"] = task

    try:
        raw_output = _hf_get(f"{_HF_HUB_BASE}/models", token, params=params)
    except RuntimeError as exc:
        log(f"ERROR search_models query={query!r}: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", f"search_models error: {exc}", op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hub_api_error", "detail": str(exc)}

    models = []
    raw_list = raw_output if isinstance(raw_output, list) else []
    for m in raw_list:
        if not isinstance(m, dict):
            continue
        models.append({
            "modelId":      m.get("modelId") or m.get("id", ""),
            "task":         m.get("pipeline_tag", ""),
            "downloads":    m.get("downloads", 0),
            "likes":        m.get("likes", 0),
            "lastModified": m.get("lastModified", ""),
            "tags":         m.get("tags", []),
        })

    detail = f"search_models: query={query!r} returned {len(models)} results"
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return {"models": models, "count": len(models), "query": query}


# ---------------------------------------------------------------------------
# Op: list_spaces
# ---------------------------------------------------------------------------

def list_spaces(
    search: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    List Spaces from the HuggingFace Hub.

    Returns {"spaces": [...], "count": int}
    Each space entry: id, title, author, likes, sdk, tags
    """
    op = "list_spaces"
    ctx, decision = _gate_and_emit(op)

    try:
        token = _get_hf_token()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hf_token_missing", "detail": str(exc)}

    params: Dict[str, Any] = {"limit": limit}
    if search:
        params["search"] = search

    try:
        raw_output = _hf_get(f"{_HF_HUB_BASE}/spaces", token, params=params)
    except RuntimeError as exc:
        log(f"ERROR list_spaces: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", f"list_spaces error: {exc}", op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hub_api_error", "detail": str(exc)}

    spaces = []
    raw_list = raw_output if isinstance(raw_output, list) else []
    for s in raw_list:
        if not isinstance(s, dict):
            continue
        spaces.append({
            "id":     s.get("id", ""),
            "title":  s.get("cardData", {}).get("title", s.get("id", "")) if isinstance(s.get("cardData"), dict) else s.get("id", ""),
            "author": s.get("author", ""),
            "likes":  s.get("likes", 0),
            "sdk":    s.get("sdk", ""),
            "tags":   s.get("tags", []),
        })

    detail = f"list_spaces: {len(spaces)} spaces returned (search={search!r})"
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return {"spaces": spaces, "count": len(spaces)}


# ---------------------------------------------------------------------------
# Op: get_space_info
# ---------------------------------------------------------------------------

def get_space_info(space_id: str) -> Dict[str, Any]:
    """
    Retrieve detailed metadata for a specific Space from the HuggingFace Hub.
    """
    op = "get_space_info"
    ctx, decision = _gate_and_emit(op)

    try:
        token = _get_hf_token()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hf_token_missing", "detail": str(exc)}

    try:
        raw = _hf_get(f"{_HF_HUB_BASE}/spaces/{space_id}", token)
    except RuntimeError as exc:
        log(f"ERROR get_space_info space_id={space_id}: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"get_space_info space_id={space_id} error: {exc}", op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hub_api_error", "space_id": space_id, "detail": str(exc)}

    detail = f"get_space_info: space_id={space_id} retrieved"
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return raw if isinstance(raw, dict) else {"raw": raw}


# ---------------------------------------------------------------------------
# Op: list_datasets
# ---------------------------------------------------------------------------

def list_datasets(
    search: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    List datasets from the HuggingFace Hub.

    Returns {"datasets": [...], "count": int}
    Each dataset entry: id, downloads, likes, tags, lastModified
    """
    op = "list_datasets"
    ctx, decision = _gate_and_emit(op)

    try:
        token = _get_hf_token()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hf_token_missing", "detail": str(exc)}

    params: Dict[str, Any] = {"limit": limit, "sort": "downloads", "direction": -1}
    if search:
        params["search"] = search

    try:
        raw_output = _hf_get(f"{_HF_HUB_BASE}/datasets", token, params=params)
    except RuntimeError as exc:
        log(f"ERROR list_datasets: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", f"list_datasets error: {exc}", op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hub_api_error", "detail": str(exc)}

    datasets = []
    raw_list = raw_output if isinstance(raw_output, list) else []
    for d in raw_list:
        if not isinstance(d, dict):
            continue
        datasets.append({
            "id":           d.get("id", ""),
            "downloads":    d.get("downloads", 0),
            "likes":        d.get("likes", 0),
            "tags":         d.get("tags", []),
            "lastModified": d.get("lastModified", ""),
        })

    detail = f"list_datasets: {len(datasets)} datasets returned (search={search!r})"
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return {"datasets": datasets, "count": len(datasets)}


# ---------------------------------------------------------------------------
# Op: get_dataset_info
# ---------------------------------------------------------------------------

def get_dataset_info(dataset_id: str) -> Dict[str, Any]:
    """
    Retrieve detailed metadata for a specific dataset from the HuggingFace Hub.
    """
    op = "get_dataset_info"
    ctx, decision = _gate_and_emit(op)

    try:
        token = _get_hf_token()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hf_token_missing", "detail": str(exc)}

    try:
        raw = _hf_get(f"{_HF_HUB_BASE}/datasets/{dataset_id}", token)
    except RuntimeError as exc:
        log(f"ERROR get_dataset_info dataset_id={dataset_id}: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"get_dataset_info dataset_id={dataset_id} error: {exc}", op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hub_api_error", "dataset_id": dataset_id, "detail": str(exc)}

    detail = f"get_dataset_info: dataset_id={dataset_id} retrieved"
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return raw if isinstance(raw, dict) else {"raw": raw}


# ---------------------------------------------------------------------------
# Op: run_space_api
# ---------------------------------------------------------------------------

def run_space_api(
    space_id: str,
    api_name: str,
    inputs: List[Any],
) -> Dict[str, Any]:
    """
    Call a Gradio Space API endpoint via gradio_client.

    Enables calling Gradio-based Spaces such as ResembleAI/chatterbox (TTS).

    Returns {"space_id": str, "api_name": str, "output": ...}

    Args:
        space_id:  HuggingFace Space ID, e.g. "ResembleAI/chatterbox"
        api_name:  Gradio API endpoint name, e.g. "/generate"
        inputs:    List of positional inputs to pass to the Space endpoint
    """
    op = "run_space_api"
    ctx, decision = _gate_and_emit(op)

    # gradio_client is optional — guard the import
    try:
        from gradio_client import Client as GradioClient
    except ImportError:
        detail = (
            "gradio_client is not installed. "
            "Run: pip install 'gradio_client>=1.0.0' then retry."
        )
        log(f"ERROR run_space_api: {detail}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", detail, op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {
            "error": "gradio_client_not_installed",
            "detail": detail,
            "install": "pip install 'gradio_client>=1.0.0'",
        }

    try:
        token = _get_hf_token()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "hf_token_missing", "detail": str(exc)}

    try:
        client = GradioClient(
            f"https://huggingface.co/spaces/{space_id}",
            hf_token=token,
        )
        output = client.predict(*inputs, api_name=api_name)
    except Exception as exc:
        log(f"ERROR run_space_api space_id={space_id} api_name={api_name}: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"run_space_api space_id={space_id} api_name={api_name} error: {exc}",
            op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        return {
            "error": "space_api_error",
            "space_id": space_id,
            "api_name": api_name,
            "detail": str(exc),
        }

    detail = (
        f"run_space_api: space_id={space_id} api_name={api_name} "
        f"inputs_count={len(inputs)} completed"
    )
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return {
        "space_id": space_id,
        "api_name": api_name,
        "output": output,
    }


# ============================================================================
# SECTION 8: ENTRY POINT
# ============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=WORKER_NAME,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            '  worker_logic.py run_inference --model-id "gpt2" --inputs "The quick brown fox"\n'
            '  worker_logic.py run_text_generation --model-id "mistralai/Mistral-7B-Instruct-v0.3" --prompt "Hello!"\n'
            '  worker_logic.py run_summarization --text "Long article..."\n'
            '  worker_logic.py run_classification --text "I love this!" --labels \'["positive","negative"]\'\n'
            '  worker_logic.py run_embeddings --texts \'["Hello world","Foo bar"]\'\n'
            '  worker_logic.py list_models --task text-generation --limit 10\n'
            '  worker_logic.py get_model_info --model-id "gpt2"\n'
            '  worker_logic.py search_models --query "sentence transformers"\n'
            '  worker_logic.py list_spaces --search "stable diffusion"\n'
            '  worker_logic.py get_space_info --space-id "stabilityai/stable-diffusion"\n'
            '  worker_logic.py list_datasets --search "common voice" --limit 10\n'
            '  worker_logic.py get_dataset_info --dataset-id "mozilla-foundation/common_voice_11_0"\n'
            '  worker_logic.py run_space_api --space-id "ResembleAI/chatterbox" --api-name "/generate" --inputs \'["Hello!"]\'\n'
        ),
    )

    p.add_argument(
        "op",
        choices=sorted(ALLOWED_OPS),
        help="Operation to perform",
    )

    # ── Inference args ──────────────────────────────────────────────────────
    p.add_argument(
        "--model-id",
        metavar="MODEL_ID",
        default=None,
        help="HuggingFace model ID (e.g. 'gpt2', 'facebook/bart-large-cnn')",
    )
    p.add_argument(
        "--inputs",
        metavar="JSON_OR_STRING",
        default=None,
        help="Inputs for run_inference: raw string or JSON value",
    )
    p.add_argument(
        "--parameters",
        metavar="JSON",
        default=None,
        help="Optional parameters dict as JSON for run_inference",
    )
    p.add_argument(
        "--prompt",
        metavar="TEXT",
        default=None,
        help="Prompt text for run_text_generation",
    )
    p.add_argument(
        "--max-new-tokens",
        type=int,
        default=200,
        help="Max new tokens for run_text_generation (default: 200)",
    )
    p.add_argument(
        "--temperature",
        type=float,
        default=0.7,
        help="Sampling temperature for run_text_generation (default: 0.7)",
    )
    p.add_argument(
        "--text",
        metavar="TEXT",
        default=None,
        help="Input text for run_summarization and run_classification",
    )
    p.add_argument(
        "--max-length",
        type=int,
        default=130,
        help="Max summary length for run_summarization (default: 130)",
    )
    p.add_argument(
        "--min-length",
        type=int,
        default=30,
        help="Min summary length for run_summarization (default: 30)",
    )
    p.add_argument(
        "--labels",
        metavar="JSON_ARRAY",
        default=None,
        help="Candidate labels as JSON array for run_classification, e.g. '[\"pos\",\"neg\"]'",
    )
    p.add_argument(
        "--texts",
        metavar="JSON_ARRAY",
        default=None,
        help="List of texts as JSON array for run_embeddings",
    )

    # ── Hub / search args ───────────────────────────────────────────────────
    p.add_argument(
        "--search",
        metavar="QUERY",
        default=None,
        help="Search query for list_models, list_spaces, list_datasets",
    )
    p.add_argument(
        "--query",
        metavar="QUERY",
        default=None,
        help="Search query for search_models",
    )
    p.add_argument(
        "--task",
        metavar="TASK",
        default=None,
        help="Pipeline task filter for list_models and search_models, e.g. 'text-generation'",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum results to return (default: 20)",
    )
    p.add_argument(
        "--sort",
        default="downloads",
        help="Sort field for list_models (default: 'downloads')",
    )

    # ── Space API args ──────────────────────────────────────────────────────
    p.add_argument(
        "--space-id",
        metavar="SPACE_ID",
        default=None,
        help="HuggingFace Space ID for get_space_info and run_space_api",
    )
    p.add_argument(
        "--api-name",
        metavar="API_NAME",
        default=None,
        help="Gradio API endpoint name for run_space_api, e.g. '/generate'",
    )

    # ── Dataset args ────────────────────────────────────────────────────────
    p.add_argument(
        "--dataset-id",
        metavar="DATASET_ID",
        default=None,
        help="HuggingFace dataset ID for get_dataset_info",
    )

    # ── Output ──────────────────────────────────────────────────────────────
    p.add_argument(
        "--output",
        metavar="PATH",
        default=None,
        help="Write JSON result to this file path",
    )

    return p


def _parse_json_arg(value: str, arg_name: str) -> Any:
    """Parse a JSON string argument, exiting with an error on failure."""
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        log(f"ERROR: --{arg_name} is not valid JSON: {exc}")
        raise SystemExit(1)


def run() -> None:
    """WCP worker entry point."""
    global _attest_meta

    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    parser = _build_arg_parser()
    args = parser.parse_args()
    op = args.op

    result: Dict[str, Any] = {}

    # ── Dispatch ─────────────────────────────────────────────────────────────

    if op == "run_inference":
        if not args.model_id:
            log("ERROR: --model-id is required for run_inference")
            raise SystemExit(1)
        if args.inputs is None:
            log("ERROR: --inputs is required for run_inference")
            raise SystemExit(1)
        # Try JSON parse first; fall back to raw string
        try:
            inputs = json.loads(args.inputs)
        except (json.JSONDecodeError, TypeError):
            inputs = args.inputs
        parameters = _parse_json_arg(args.parameters, "parameters") if args.parameters else None
        result = run_inference(args.model_id, inputs, parameters=parameters)

    elif op == "run_text_generation":
        if not args.prompt:
            log("ERROR: --prompt is required for run_text_generation")
            raise SystemExit(1)
        model_id = args.model_id or os.environ.get(
            "HF_DEFAULT_TEXT_GEN_MODEL", "mistralai/Mistral-7B-Instruct-v0.3"
        )
        result = run_text_generation(
            model_id=model_id,
            prompt=args.prompt,
            max_new_tokens=args.max_new_tokens,
            temperature=args.temperature,
        )

    elif op == "run_summarization":
        if not args.text:
            log("ERROR: --text is required for run_summarization")
            raise SystemExit(1)
        model_id = args.model_id or "facebook/bart-large-cnn"
        result = run_summarization(
            text=args.text,
            model_id=model_id,
            max_length=args.max_length,
            min_length=args.min_length,
        )

    elif op == "run_classification":
        if not args.text:
            log("ERROR: --text is required for run_classification")
            raise SystemExit(1)
        if not args.labels:
            log("ERROR: --labels is required for run_classification")
            raise SystemExit(1)
        candidate_labels = _parse_json_arg(args.labels, "labels")
        if not isinstance(candidate_labels, list):
            log("ERROR: --labels must be a JSON array of strings")
            raise SystemExit(1)
        model_id = args.model_id or "facebook/bart-large-mnli"
        result = run_classification(
            text=args.text,
            candidate_labels=candidate_labels,
            model_id=model_id,
        )

    elif op == "run_embeddings":
        if not args.texts:
            log("ERROR: --texts is required for run_embeddings")
            raise SystemExit(1)
        texts = _parse_json_arg(args.texts, "texts")
        if not isinstance(texts, list):
            log("ERROR: --texts must be a JSON array of strings")
            raise SystemExit(1)
        model_id = args.model_id or "sentence-transformers/all-MiniLM-L6-v2"
        result = run_embeddings(texts=texts, model_id=model_id)

    elif op == "list_models":
        result = list_models(
            search=args.search,
            task=args.task,
            limit=args.limit,
            sort=args.sort,
        )

    elif op == "get_model_info":
        if not args.model_id:
            log("ERROR: --model-id is required for get_model_info")
            raise SystemExit(1)
        result = get_model_info(args.model_id)

    elif op == "search_models":
        query = args.query or args.search
        if not query:
            log("ERROR: --query is required for search_models")
            raise SystemExit(1)
        result = search_models(query=query, task=args.task, limit=args.limit)

    elif op == "list_spaces":
        result = list_spaces(search=args.search, limit=args.limit)

    elif op == "get_space_info":
        if not args.space_id:
            log("ERROR: --space-id is required for get_space_info")
            raise SystemExit(1)
        result = get_space_info(args.space_id)

    elif op == "list_datasets":
        result = list_datasets(search=args.search, limit=args.limit)

    elif op == "get_dataset_info":
        if not args.dataset_id:
            log("ERROR: --dataset-id is required for get_dataset_info")
            raise SystemExit(1)
        result = get_dataset_info(args.dataset_id)

    elif op == "run_space_api":
        if not args.space_id:
            log("ERROR: --space-id is required for run_space_api")
            raise SystemExit(1)
        if not args.api_name:
            log("ERROR: --api-name is required for run_space_api")
            raise SystemExit(1)
        if args.inputs is None:
            log("ERROR: --inputs is required for run_space_api (JSON array)")
            raise SystemExit(1)
        inputs = _parse_json_arg(args.inputs, "inputs")
        if not isinstance(inputs, list):
            log("ERROR: --inputs for run_space_api must be a JSON array")
            raise SystemExit(1)
        result = run_space_api(
            space_id=args.space_id,
            api_name=args.api_name,
            inputs=inputs,
        )

    # ── Output ────────────────────────────────────────────────────────────────

    result_json = json.dumps(result, indent=2, default=str)

    if args.output:
        out_path = Path(args.output).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(result_json, encoding="utf-8")
        log(f"Result written to {out_path}")
    else:
        print(result_json)

    log(f"Done: op={op}")


if __name__ == "__main__":
    run()
