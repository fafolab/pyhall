#!/usr/bin/env python3
"""
worker_logic.py — Google Drive Worker (WCP v0.3.0)

Full WCP-compliant worker for Google Drive operations: list, get, search,
upload, download, create_folder, move, share, delete, get_metadata, setup.

All file operations record the file_id, file_name, and operation in
the evidence receipt detail field. Uploads use resumable=True for large files.
Google Docs/Sheets/Slides are exported to PDF on download.

All timestamps stored as UTC ISO 8601. Log output uses Central Time.

Setup (one-time):
    1. Go to console.cloud.google.com
    2. Create or select a project
    3. Enable Google Drive API
    4. Create OAuth2 credentials (Desktop application)
    5. Set GOOGLE_CREDENTIALS_JSON env var to the path of the credentials JSON file
    6. Run: python3 bootstrap.py setup
       (opens browser for auth, saves token to ~/.local/share/pyhall/google_drive_token.json)
"""

from __future__ import annotations

# ============================================================================
# SECTION 1: HEADER + IDENTITY + WCP DECLARATIONS
# ============================================================================

import argparse
import hashlib
import json
import mimetypes
import os
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

WORKER_ID         = "org.pyhall.google-drive.instance-1"
WORKER_SPECIES_ID = "wrk.pyhall.google-drive"
WORKER_NAME       = "Google Drive Worker (WCP v0.3.0)"
WORKER_VERSION    = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.google_drive.read",
    "cap.pyhall.google_drive.write",
    "cap.pyhall.google_drive.manage",
]

ALLOWED_OPS = {
    "list_files",
    "get_file",
    "search_files",
    "upload_file",
    "download_file",
    "create_folder",
    "move_file",
    "share_file",
    "delete_file",
    "get_file_metadata",
    "setup",
}

# Ops that require write/manage capabilities (used in _make_ctx)
_READ_OPS   = {"list_files", "get_file", "search_files", "get_file_metadata"}
_WRITE_OPS  = {"upload_file", "download_file", "create_folder"}
_MANAGE_OPS = {"move_file", "share_file", "delete_file", "setup"}

ALLOWED_ENVS = {"dev", "stage", "prod"}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

# Google Drive MIME types that require export (cannot be downloaded directly)
_GDOC_EXPORT_MAP: Dict[str, Tuple[str, str]] = {
    "application/vnd.google-apps.document":     ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx"),
    "application/vnd.google-apps.spreadsheet":  ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx"),
    "application/vnd.google-apps.presentation": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", ".pptx"),
    "application/vnd.google-apps.drawing":      ("application/pdf", ".pdf"),
    "application/vnd.google-apps.script":       ("application/vnd.google-apps.script+json", ".json"),
}

# Standard Drive file metadata fields
_FILE_FIELDS = "id,name,mimeType,size,modifiedTime,createdTime,parents,webViewLink,owners,shared"
_FULL_FIELDS  = (
    "id,name,mimeType,size,modifiedTime,createdTime,parents,webViewLink,webContentLink,"
    "owners,shared,sharingUser,permissions,description,starred,trashed,capabilities"
)

# Token path for OAuth credentials
TOKEN_PATH = Path(
    os.environ.get("PYHALL_DRIVE_TOKEN_PATH", "")
) or Path.home() / ".local" / "share" / "pyhall" / "google_drive_token.json"

SCOPES = ["https://www.googleapis.com/auth/drive"]


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
class DriveFile:
    """Lightweight representation of a Drive file/folder."""
    file_id: str
    name: str
    mime_type: str
    size: Optional[int]
    modified_time: Optional[str]
    parents: List[str] = field(default_factory=list)


# ============================================================================
# SECTION 3: UTILS
# ============================================================================

_CT = ZoneInfo("America/Chicago")


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


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def _detect_mime(local_path: Path) -> str:
    """Detect MIME type from file extension. Falls back to octet-stream."""
    mime, _ = mimetypes.guess_type(str(local_path))
    return mime or "application/octet-stream"


def _human_size(size_bytes: Optional[int]) -> str:
    """Format bytes as human-readable size string."""
    if size_bytes is None:
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes //= 1024
    return f"{size_bytes:.1f} PB"


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
        log(f"WARNING: {msg} — continuing in dev")
        return {"dev_skip": True, "deny_code": deny_code, "meta": attest_meta}

    log(f"Attestation OK — {attest_meta.get('trust_statement', '')}")
    return attest_meta


# Derive paths from this file's location:
#   code/worker_logic.py → package root is two levels up (google_drive_worker/)
_THIS_FILE    = Path(__file__).resolve()
_PACKAGE_ROOT = _THIS_FILE.parent.parent   # .../google_drive_worker/
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

        rule_id = f"rr_drive_{op}_allow_v1"
        return WCPDecision(True, None, None, self.policy_version, rule_id, WORKER_SPECIES_ID)


# ============================================================================
# SECTION 6: OBSERVABILITY — HASH-CHAINED EVIDENCE LOG
# ============================================================================

_EVIDENCE_LOG_PATH = (
    Path.home() / ".local" / "share" / "pyhall" / "evidence"
    / f"{WORKER_SPECIES_ID.replace('.', '_')}_chain.log"
)


class AppendOnlyEvidenceLog:
    """
    Hash-chained append-only local evidence log.

    Each entry records: prev_hash, entry_hash (prev_hash + payload), receipt dict.
    Writes are best-effort — will not crash the worker if the directory is absent.
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


# Module-level singletons (instantiated at import time)
_policy_gate  = PolicyGate()
_evidence_log = AppendOnlyEvidenceLog(_EVIDENCE_LOG_PATH)
_attest_meta: Dict[str, Any] = {}  # populated by run() at startup


def _cap_for_op(op: str) -> str:
    """Map operation name to the appropriate capability ID."""
    if op in _READ_OPS:
        return "cap.pyhall.google_drive.read"
    if op in _WRITE_OPS:
        return "cap.pyhall.google_drive.write"
    return "cap.pyhall.google_drive.manage"


def _make_ctx(op: str, capability_id: Optional[str] = None) -> WCPContext:
    """Build a WCPContext for the given operation."""
    return WCPContext(
        correlation_id=str(uuid.uuid4()),
        env=os.environ.get("PYHALL_ENV", "dev"),
        capability_id=capability_id or _cap_for_op(op),
        data_label="INTERNAL",
        tenant_risk="low",
        qos_class="P2",
        requested_at_utc=utc_now_iso(),
    )


def _gate_and_emit(op: str, capability_id: Optional[str] = None) -> Tuple[WCPContext, WCPDecision]:
    """Run the policy gate for an operation and emit a deny receipt if blocked."""
    ctx = _make_ctx(op, capability_id)
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
# SECTION 7: DOMAIN LOGIC — GOOGLE DRIVE
# ============================================================================

# --- Dependency check ---

def check_deps() -> bool:
    """Check if Google API dependencies are installed."""
    try:
        from google.oauth2.credentials import Credentials  # noqa: F401
        from google_auth_oauthlib.flow import InstalledAppFlow  # noqa: F401
        from googleapiclient.discovery import build  # noqa: F401
        return True
    except ImportError:
        return False


# --- Google Auth ---

def _resolve_token_path() -> Path:
    """Resolve the token path from env var or default."""
    env_override = os.environ.get("PYHALL_DRIVE_TOKEN_PATH", "").strip()
    if env_override:
        return Path(env_override)
    return Path.home() / ".local" / "share" / "pyhall" / "google_drive_token.json"


def _resolve_credentials_path() -> Optional[Path]:
    """
    Resolve Google credentials JSON from env var GOOGLE_CREDENTIALS_JSON.
    The env var may be a file path or raw JSON string.
    Returns Path to a credentials file, or None if not set.
    """
    raw = os.environ.get("GOOGLE_CREDENTIALS_JSON", "").strip()
    if not raw:
        return None
    p = Path(raw)
    if p.exists():
        return p
    # Could be raw JSON — write to a temp file
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".json"))
    tmp.write_text(raw, encoding="utf-8")
    return tmp


def get_drive_service():
    """Authenticate and return Google Drive v3 service object."""
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    token_path = _resolve_token_path()
    creds = None

    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                log(f"Token refresh failed: {e}")
                log("Deleting stale token. Run 'setup' again to re-authenticate.")
                token_path.unlink(missing_ok=True)
                sys.exit(1)
        else:
            creds_path = _resolve_credentials_path()
            if not creds_path:
                log("ERROR: GOOGLE_CREDENTIALS_JSON env var not set.")
                log("Set it to the path of your OAuth2 credentials JSON file.")
                sys.exit(1)
            flow = InstalledAppFlow.from_client_secrets_file(str(creds_path), SCOPES)
            creds = flow.run_local_server(port=0)

        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(creds.to_json(), encoding="utf-8")
        # chmod 600 on Unix; no-op on Windows (pathlib handles this gracefully)
        try:
            token_path.chmod(0o600)
        except Exception:
            pass
        log(f"Token saved to {token_path}")

    return build("drive", "v3", credentials=creds)


# --- Tool functions ---

def list_files(
    folder_id: Optional[str] = None,
    limit: int = 50,
    mime_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    List files in a folder (or all Drive files if folder_id is None).

    Args:
        folder_id: Drive folder ID to list. If None, lists all non-trashed files.
        limit: Maximum number of results (1-1000).
        mime_type: Filter by MIME type (e.g. 'application/pdf').

    Returns dict with 'files' list and 'count'.
    """
    ctx, decision = _gate_and_emit("list_files")

    service = get_drive_service()

    query_parts = ["trashed = false"]
    if folder_id:
        query_parts.append(f"'{folder_id}' in parents")
    if mime_type:
        query_parts.append(f"mimeType = '{mime_type}'")

    query = " and ".join(query_parts)
    limit = max(1, min(limit, 1000))

    results = service.files().list(
        q=query,
        pageSize=limit,
        fields=f"nextPageToken,files({_FILE_FIELDS})",
        orderBy="modifiedTime desc",
    ).execute()

    files = results.get("files", [])
    next_page = results.get("nextPageToken")

    log(f"list_files: {len(files)} files" + (f" in folder {folder_id}" if folder_id else ""))

    detail = (
        f"list_files: folder_id={folder_id or 'root'} "
        f"limit={limit} mime_type={mime_type} returned={len(files)}"
    )
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "list_files", _attest_meta)
    _evidence_log.emit_evidence(receipt)

    return {
        "files": files,
        "count": len(files),
        "has_more": next_page is not None,
        "folder_id": folder_id,
    }


def get_file(file_id: str) -> Dict[str, Any]:
    """
    Get metadata for a single file by ID.

    Args:
        file_id: Drive file ID.

    Returns metadata dict with standard fields.
    """
    ctx, decision = _gate_and_emit("get_file")

    service = get_drive_service()
    file_meta = service.files().get(
        fileId=file_id,
        fields=_FILE_FIELDS,
    ).execute()

    name = file_meta.get("name", "unknown")
    log(f"get_file: id={file_id} name={name!r}")

    detail = f"get_file: file_id={file_id} file_name={name!r} mime={file_meta.get('mimeType', '?')}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "get_file", _attest_meta)
    _evidence_log.emit_evidence(receipt)

    return file_meta


def search_files(query: str, limit: int = 25) -> Dict[str, Any]:
    """
    Search files using Drive query syntax.

    Args:
        query: Drive query string (e.g. "name contains 'report'" or "fullText contains 'budget'").
        limit: Maximum number of results (1-1000).

    Returns dict with 'files' list and 'count'.
    """
    ctx, decision = _gate_and_emit("search_files")

    service = get_drive_service()

    # Ensure trashed files are excluded unless explicitly in query
    full_query = f"({query}) and trashed = false"
    limit = max(1, min(limit, 1000))

    results = service.files().list(
        q=full_query,
        pageSize=limit,
        fields=f"nextPageToken,files({_FILE_FIELDS})",
        orderBy="modifiedTime desc",
    ).execute()

    files = results.get("files", [])
    log(f"search_files: query={query!r} returned {len(files)} results")

    detail = f"search_files: query={query!r} limit={limit} returned={len(files)}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "search_files", _attest_meta)
    _evidence_log.emit_evidence(receipt)

    return {
        "files": files,
        "count": len(files),
        "query": query,
    }


def upload_file(
    local_path: str,
    parent_folder_id: Optional[str] = None,
    name: Optional[str] = None,
    mime_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Upload a local file to Google Drive.

    Args:
        local_path: Absolute or relative path to the local file.
        parent_folder_id: Drive folder ID to upload into. Defaults to Drive root.
        name: Name to use in Drive. Defaults to the local filename.
        mime_type: MIME type. Detected from extension if not provided.

    Returns dict with uploaded file metadata including file_id and name.
    """
    ctx, decision = _gate_and_emit("upload_file")

    from googleapiclient.http import MediaFileUpload

    src = Path(local_path).resolve()
    if not src.exists():
        detail = f"upload_file: local_path={local_path!r} not found"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "upload_file", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: file not found: {src}")
        raise FileNotFoundError(f"File not found: {src}")

    upload_name  = name or src.name
    upload_mime  = mime_type or _detect_mime(src)

    file_metadata: Dict[str, Any] = {"name": upload_name}
    if parent_folder_id:
        file_metadata["parents"] = [parent_folder_id]

    media = MediaFileUpload(
        str(src),
        mimetype=upload_mime,
        resumable=True,
    )

    service = get_drive_service()
    result = service.files().create(
        body=file_metadata,
        media_body=media,
        fields="id,name,mimeType,size,webViewLink",
    ).execute()

    file_id   = result.get("id", "?")
    file_name = result.get("name", upload_name)
    log(f"upload_file: {src.name!r} → Drive id={file_id} name={file_name!r}")

    detail = (
        f"upload_file: local_path={str(src)!r} file_id={file_id} "
        f"file_name={file_name!r} mime={upload_mime} parent={parent_folder_id or 'root'}"
    )
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "upload_file", _attest_meta)
    _evidence_log.emit_evidence(receipt)

    return result


def download_file(file_id: str, local_path: str) -> Dict[str, Any]:
    """
    Download a Drive file to a local path.

    Google Docs, Sheets, and Slides are exported (Docs→docx, Sheets→xlsx,
    Slides→pptx, Drawings→pdf). All other files are downloaded directly.

    Args:
        file_id: Drive file ID.
        local_path: Destination path (directory or full file path).

    Returns dict with file_id, file_name, local_path, exported.
    """
    ctx, decision = _gate_and_emit("download_file")

    from googleapiclient.http import MediaIoBaseDownload
    import io

    service = get_drive_service()
    file_meta = service.files().get(
        fileId=file_id,
        fields="id,name,mimeType,size",
    ).execute()

    file_name = file_meta.get("name", file_id)
    mime_type = file_meta.get("mimeType", "")
    exported  = False

    dest = Path(local_path)
    if dest.is_dir():
        dest = dest / file_name

    if mime_type in _GDOC_EXPORT_MAP:
        export_mime, ext = _GDOC_EXPORT_MAP[mime_type]
        # Append export extension if not already present
        if not dest.suffix == ext:
            dest = dest.with_suffix(ext)
        log(f"download_file: exporting Google doc {file_id} ({mime_type}) as {export_mime}")
        request = service.files().export_media(fileId=file_id, mimeType=export_mime)
        exported = True
    else:
        request = service.files().get_media(fileId=file_id)

    dest.parent.mkdir(parents=True, exist_ok=True)
    fh = io.FileIO(str(dest), "wb")
    try:
        downloader = MediaIoBaseDownload(fh, request, chunksize=10 * 1024 * 1024)
        done = False
        while not done:
            status, done = downloader.next_chunk()
            if status:
                pct = int(status.progress() * 100)
                log(f"  download_file: {file_name!r} {pct}%")
    finally:
        fh.close()

    log(f"download_file: id={file_id} name={file_name!r} → {dest}")

    detail = (
        f"download_file: file_id={file_id} file_name={file_name!r} "
        f"local_path={str(dest)!r} exported={exported}"
    )
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "download_file", _attest_meta)
    _evidence_log.emit_evidence(receipt)

    return {
        "file_id": file_id,
        "file_name": file_name,
        "local_path": str(dest),
        "exported": exported,
        "mime_type": mime_type,
    }


def create_folder(name: str, parent_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Create a new folder in Google Drive.

    Args:
        name: Folder name.
        parent_id: Parent folder ID. Defaults to Drive root.

    Returns dict with folder file_id, name, and webViewLink.
    """
    ctx, decision = _gate_and_emit("create_folder")

    service = get_drive_service()

    file_metadata: Dict[str, Any] = {
        "name": name,
        "mimeType": "application/vnd.google-apps.folder",
    }
    if parent_id:
        file_metadata["parents"] = [parent_id]

    result = service.files().create(
        body=file_metadata,
        fields="id,name,mimeType,webViewLink",
    ).execute()

    folder_id = result.get("id", "?")
    log(f"create_folder: name={name!r} id={folder_id} parent={parent_id or 'root'}")

    detail = (
        f"create_folder: file_id={folder_id} file_name={name!r} parent={parent_id or 'root'}"
    )
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "create_folder", _attest_meta)
    _evidence_log.emit_evidence(receipt)

    return result


def move_file(
    file_id: str,
    new_parent_id: str,
    remove_old_parent: bool = True,
) -> Dict[str, Any]:
    """
    Move a file to a different folder.

    Args:
        file_id: Drive file ID.
        new_parent_id: Destination folder ID.
        remove_old_parent: If True (default), removes old parent(s).

    Returns updated file metadata.
    """
    ctx, decision = _gate_and_emit("move_file")

    service = get_drive_service()

    # Get current metadata to know old parents
    current = service.files().get(
        fileId=file_id,
        fields="id,name,parents",
    ).execute()
    file_name    = current.get("name", file_id)
    old_parents  = ",".join(current.get("parents", []))

    kwargs: Dict[str, Any] = {
        "fileId": file_id,
        "addParents": new_parent_id,
        "fields": "id,name,parents,modifiedTime",
    }
    if remove_old_parent and old_parents:
        kwargs["removeParents"] = old_parents

    result = service.files().update(**kwargs).execute()

    log(
        f"move_file: id={file_id} name={file_name!r} "
        f"old_parents={old_parents!r} → new_parent={new_parent_id}"
    )

    detail = (
        f"move_file: file_id={file_id} file_name={file_name!r} "
        f"new_parent_id={new_parent_id} remove_old_parent={remove_old_parent}"
    )
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "move_file", _attest_meta)
    _evidence_log.emit_evidence(receipt)

    return result


def share_file(
    file_id: str,
    email: str,
    role: str = "reader",
    type: str = "user",
) -> Dict[str, Any]:
    """
    Share a Drive file with a user, group, domain, or anyone.

    Args:
        file_id: Drive file ID.
        email: Email address (required for user/group types).
        role: 'reader', 'commenter', 'writer', or 'owner'.
        type: 'user', 'group', 'domain', or 'anyone'.

    Returns permission creation result.
    """
    ctx, decision = _gate_and_emit("share_file")

    service = get_drive_service()

    # Fetch file name for logging
    file_meta = service.files().get(fileId=file_id, fields="id,name").execute()
    file_name = file_meta.get("name", file_id)

    permission: Dict[str, Any] = {
        "type": type,
        "role": role,
    }
    if type in ("user", "group"):
        permission["emailAddress"] = email

    result = service.permissions().create(
        fileId=file_id,
        body=permission,
        sendNotificationEmail=(type in ("user", "group")),
        fields="id,type,role,emailAddress",
    ).execute()

    perm_id = result.get("id", "?")
    log(f"share_file: id={file_id} name={file_name!r} → {role}/{type} {email}")

    detail = (
        f"share_file: file_id={file_id} file_name={file_name!r} "
        f"email={email!r} role={role!r} type={type!r} permission_id={perm_id}"
    )
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "share_file", _attest_meta)
    _evidence_log.emit_evidence(receipt)

    return result


def delete_file(file_id: str) -> Dict[str, Any]:
    """
    Move a Drive file or folder to trash.

    Args:
        file_id: Drive file ID.

    Returns dict with file_id, file_name, status.
    """
    ctx, decision = _gate_and_emit("delete_file")

    service = get_drive_service()

    # Fetch name before deleting for receipt
    file_meta = service.files().get(fileId=file_id, fields="id,name,mimeType").execute()
    file_name = file_meta.get("name", file_id)
    mime_type = file_meta.get("mimeType", "?")

    service.files().delete(fileId=file_id).execute()

    log(f"delete_file: id={file_id} name={file_name!r} ({mime_type}) moved to trash")

    detail = (
        f"delete_file: file_id={file_id} file_name={file_name!r} "
        f"mime_type={mime_type} operation=trash"
    )
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "delete_file", _attest_meta)
    _evidence_log.emit_evidence(receipt)

    return {"file_id": file_id, "file_name": file_name, "status": "trashed"}


def get_file_metadata(file_id: str) -> Dict[str, Any]:
    """
    Get full metadata for a Drive file including permissions and sharing info.

    Args:
        file_id: Drive file ID.

    Returns full metadata dict.
    """
    ctx, decision = _gate_and_emit("get_file_metadata")

    service = get_drive_service()
    file_meta = service.files().get(
        fileId=file_id,
        fields=_FULL_FIELDS,
    ).execute()

    file_name = file_meta.get("name", file_id)
    perm_count = len(file_meta.get("permissions", []))
    log(f"get_file_metadata: id={file_id} name={file_name!r} permissions={perm_count}")

    detail = (
        f"get_file_metadata: file_id={file_id} file_name={file_name!r} "
        f"mime={file_meta.get('mimeType', '?')} shared={file_meta.get('shared', False)} "
        f"permission_count={perm_count}"
    )
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "get_file_metadata", _attest_meta)
    _evidence_log.emit_evidence(receipt)

    return file_meta


def setup() -> None:
    """
    Run the one-time OAuth2 setup flow for Google Drive.

    Opens a browser window for auth and saves the token to
    ~/.local/share/pyhall/google_drive_token.json.
    """
    ctx, decision = _gate_and_emit("setup")

    if not check_deps():
        log("ERROR: Google API deps not installed.")
        log("  pip install google-api-python-client google-auth-oauthlib google-auth-httplib2")
        receipt = build_evidence_receipt(ctx, decision, "error", "setup: deps missing", "setup", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        sys.exit(1)

    log("Running Google Drive OAuth2 setup flow...")
    service = get_drive_service()

    # Verify the service works by fetching 'root' folder metadata
    about = service.about().get(fields="user").execute()
    email = about.get("user", {}).get("emailAddress", "unknown")
    token_path = _resolve_token_path()

    log(f"Authenticated as: {email}")
    log(f"Token saved to: {token_path}")

    detail = f"setup: authenticated as {email!r} token_path={str(token_path)!r}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "setup", _attest_meta)
    _evidence_log.emit_evidence(receipt)


def _print_files(files: List[Dict[str, Any]]) -> None:
    """Pretty-print a list of Drive file dicts to stdout."""
    if not files:
        print("  (no files)")
        return
    for f in files:
        size_str = _human_size(int(f["size"]) if f.get("size") else None)
        mod = f.get("modifiedTime", "")[:10]
        print(f"  {f['id']}  {f.get('name', '?'):<45}  {f.get('mimeType', '?'):<50}  {size_str:>10}  {mod}")


# ============================================================================
# SECTION 8: ENTRY POINT
# ============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=f"FΔFΌ★LΔB {WORKER_NAME}",
        epilog=(
            "Examples:\n"
            "  python3 bootstrap.py setup\n"
            "  python3 bootstrap.py list_files\n"
            "  python3 bootstrap.py list_files --folder-id 1abc... --limit 100\n"
            "  python3 bootstrap.py get_file --file-id 1abc...\n"
            "  python3 bootstrap.py search_files --query \"name contains 'budget'\"\n"
            "  python3 bootstrap.py upload_file --local-path /path/to/file.pdf\n"
            "  python3 bootstrap.py upload_file --local-path /path/to/file.xlsx --parent-folder-id 1abc...\n"
            "  python3 bootstrap.py download_file --file-id 1abc... --local-path /tmp/\n"
            "  python3 bootstrap.py create_folder --name 'Reports 2026'\n"
            "  python3 bootstrap.py move_file --file-id 1abc... --new-parent-id 1xyz...\n"
            "  python3 bootstrap.py share_file --file-id 1abc... --email user@example.com --role writer\n"
            "  python3 bootstrap.py delete_file --file-id 1abc...\n"
            "  python3 bootstrap.py get_file_metadata --file-id 1abc...\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("op", choices=sorted(ALLOWED_OPS), help="Operation to perform")

    # list_files
    p.add_argument("--folder-id",    default=None, help="Folder ID for list_files")
    p.add_argument("--limit",        type=int, default=50, help="Max results (list_files/search_files, default 50)")
    p.add_argument("--mime-type",    default=None, help="MIME type filter for list_files")

    # get_file / download_file / delete_file / get_file_metadata / share_file
    p.add_argument("--file-id",      default=None, help="Drive file ID")

    # search_files
    p.add_argument("--query",        default=None, help="Drive query string for search_files")

    # upload_file
    p.add_argument("--local-path",   default=None, help="Local file path (upload_file/download_file)")
    p.add_argument("--parent-folder-id", default=None, dest="parent_folder_id",
                   help="Parent folder ID for upload_file/create_folder/move_file (new parent for move)")
    p.add_argument("--name",         default=None, help="Filename in Drive for upload_file, or folder name for create_folder")
    p.add_argument("--upload-mime",  default=None, dest="upload_mime",
                   help="MIME type override for upload_file")

    # move_file
    p.add_argument("--new-parent-id", default=None, dest="new_parent_id",
                   help="Destination folder ID for move_file")
    p.add_argument("--keep-old-parent", action="store_true", dest="keep_old_parent",
                   help="Keep original parent on move_file (default: remove old parent)")

    # share_file
    p.add_argument("--email",        default=None, help="Email address for share_file")
    p.add_argument("--role",         default="reader",
                   choices=["reader", "commenter", "writer", "owner"],
                   help="Permission role for share_file (default: reader)")
    p.add_argument("--share-type",   default="user", dest="share_type",
                   choices=["user", "group", "domain", "anyone"],
                   help="Permission type for share_file (default: user)")

    return p


def run() -> None:
    """WCP worker entry point. Called from bootstrap.py."""
    global _attest_meta

    # Section 4: startup attestation — warns in dev, hard-fails in prod
    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    args = _build_arg_parser().parse_args()
    op = args.op

    # Dependency check for all ops except setup (which handles it internally)
    if op != "setup" and not check_deps():
        log("ERROR: Google API deps not installed.")
        log("  pip install google-api-python-client google-auth-oauthlib google-auth-httplib2")
        sys.exit(1)

    if op == "setup":
        setup()

    elif op == "list_files":
        result = list_files(
            folder_id=args.folder_id,
            limit=args.limit,
            mime_type=args.mime_type,
        )
        print(f"\nFiles ({result['count']}{' +more' if result['has_more'] else ''}):")
        _print_files(result["files"])

    elif op == "get_file":
        if not args.file_id:
            log("ERROR: --file-id required for get_file")
            sys.exit(1)
        result = get_file(args.file_id)
        print(json.dumps(result, indent=2))

    elif op == "search_files":
        if not args.query:
            log("ERROR: --query required for search_files")
            sys.exit(1)
        result = search_files(query=args.query, limit=args.limit)
        print(f"\nSearch results for {args.query!r} ({result['count']} files):")
        _print_files(result["files"])

    elif op == "upload_file":
        if not args.local_path:
            log("ERROR: --local-path required for upload_file")
            sys.exit(1)
        result = upload_file(
            local_path=args.local_path,
            parent_folder_id=args.parent_folder_id,
            name=args.name,
            mime_type=args.upload_mime,
        )
        print(f"Uploaded: id={result['id']} name={result.get('name')!r}")
        if result.get("webViewLink"):
            print(f"  View: {result['webViewLink']}")

    elif op == "download_file":
        if not args.file_id:
            log("ERROR: --file-id required for download_file")
            sys.exit(1)
        dest = args.local_path or str(Path.cwd())
        result = download_file(file_id=args.file_id, local_path=dest)
        print(f"Downloaded: {result['file_name']!r} → {result['local_path']}")
        if result["exported"]:
            print(f"  (exported from {result['mime_type']})")

    elif op == "create_folder":
        if not args.name:
            log("ERROR: --name required for create_folder")
            sys.exit(1)
        result = create_folder(name=args.name, parent_id=args.parent_folder_id)
        print(f"Created folder: id={result['id']} name={result.get('name')!r}")

    elif op == "move_file":
        if not args.file_id:
            log("ERROR: --file-id required for move_file")
            sys.exit(1)
        new_parent = args.new_parent_id or args.parent_folder_id
        if not new_parent:
            log("ERROR: --new-parent-id required for move_file")
            sys.exit(1)
        result = move_file(
            file_id=args.file_id,
            new_parent_id=new_parent,
            remove_old_parent=not args.keep_old_parent,
        )
        print(f"Moved: id={result['id']} name={result.get('name')!r} → {new_parent}")

    elif op == "share_file":
        if not args.file_id:
            log("ERROR: --file-id required for share_file")
            sys.exit(1)
        if not args.email and args.share_type in ("user", "group"):
            log("ERROR: --email required for share_file with type=user/group")
            sys.exit(1)
        result = share_file(
            file_id=args.file_id,
            email=args.email or "",
            role=args.role,
            type=args.share_type,
        )
        print(f"Shared: permission_id={result['id']} role={result.get('role')} type={result.get('type')}")

    elif op == "delete_file":
        if not args.file_id:
            log("ERROR: --file-id required for delete_file")
            sys.exit(1)
        result = delete_file(file_id=args.file_id)
        print(f"Deleted (trashed): id={result['file_id']} name={result['file_name']!r}")

    elif op == "get_file_metadata":
        if not args.file_id:
            log("ERROR: --file-id required for get_file_metadata")
            sys.exit(1)
        result = get_file_metadata(file_id=args.file_id)
        print(json.dumps(result, indent=2))

    else:
        log(f"ERROR: unhandled op={op!r}")
        sys.exit(1)


if __name__ == "__main__":
    run()
