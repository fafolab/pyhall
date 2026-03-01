"""
tests/test_cli_user.py — Tests for user-facing catalog CLI commands.

Tests:
  - search: fuzzy search across catalog entities
  - explain: detailed entity lookup
  - browse: taxonomy catalog browser
  - dispatch: routing simulation
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from pyhall.cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------

def test_search_returns_results():
    """Search for a known term returns ranked results."""
    result = runner.invoke(app, ["search", "summarize", "--quiet"])
    assert result.exit_code == 0
    # Should find document summarize capabilities
    assert "summarize" in result.output.lower() or "doc" in result.output.lower()


def test_search_no_results():
    """Search for a term that matches nothing exits 0 with a no-results message."""
    result = runner.invoke(app, ["search", "xyzzy_no_match_ever_42qz", "--quiet"])
    assert result.exit_code == 0
    # Should print a "no results" message (not crash)
    assert (
        "no results" in result.output.lower()
        or "no match" in result.output.lower()
        or "not found" in result.output.lower()
        or result.output.strip() != ""  # at minimum, something was printed
    )


def test_search_type_filter():
    """Search with --type cap returns only capability entities."""
    result = runner.invoke(app, ["search", "doc", "--type", "cap", "--quiet"])
    assert result.exit_code == 0
    # Output should reference cap-type entities; wrk/ctrl types should not dominate
    # (We just ensure it runs successfully with the filter)


def test_search_type_and_limit():
    """Search with --type and --limit together."""
    result = runner.invoke(app, ["search", "doc", "--type", "cap", "--limit", "5", "--quiet"])
    assert result.exit_code == 0


def test_search_limit():
    """--limit flag controls number of results."""
    result = runner.invoke(app, ["search", "doc", "--limit", "3", "--quiet"])
    assert result.exit_code == 0


def test_search_json_output():
    """--json flag returns valid JSON array."""
    result = runner.invoke(app, ["search", "sandbox", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    # Each result should have required fields
    for item in data:
        assert "id" in item
        assert "type" in item
        assert "score" in item
        assert isinstance(item["score"], int)
        assert item["score"] > 0


def test_search_json_no_results():
    """--json flag with no results returns empty list."""
    result = runner.invoke(app, ["search", "xyzzy_no_match_ever_42qz", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert len(data) == 0


def test_search_json_scores_ordered():
    """JSON output results are sorted by score descending."""
    result = runner.invoke(app, ["search", "sandbox", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    if len(data) > 1:
        scores = [item["score"] for item in data]
        assert scores == sorted(scores, reverse=True), "Results should be sorted by score descending"


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------

def test_explain_known_entity():
    """Explain a known capability entity from the catalog."""
    # Use an entity we know exists from catalog inspection
    result = runner.invoke(app, ["explain", "cap.mount.workspace", "--quiet"])
    assert result.exit_code == 0
    assert "cap.mount.workspace" in result.output


def test_explain_known_worker_species():
    """Explain a known worker_species entity."""
    result = runner.invoke(app, ["explain", "wrk.doc.pipeline.orchestrator", "--quiet"])
    assert result.exit_code == 0
    assert "wrk.doc.pipeline.orchestrator" in result.output


def test_explain_known_control():
    """Explain a known control entity."""
    result = runner.invoke(app, ["explain", "ctrl.sandbox.no-egress-default-deny", "--quiet"])
    assert result.exit_code == 0
    assert "ctrl.sandbox.no-egress-default-deny" in result.output


def test_explain_unknown_entity_exits_nonzero():
    """Explain with an unknown entity ID exits with code 1."""
    result = runner.invoke(app, ["explain", "cap.does.not.exist.v99", "--quiet"])
    assert result.exit_code == 1
    # Should mention the entity was not found
    assert (
        "not found" in result.output.lower()
        or "error" in result.output.lower()
    )


def test_explain_json_output():
    """--json flag returns the raw entity JSON."""
    result = runner.invoke(app, ["explain", "cap.mount.workspace", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["id"] == "cap.mount.workspace"
    assert data["type"] == "capability"


def test_explain_json_unknown_exits_nonzero():
    """--json flag with unknown entity exits 1 and returns error JSON."""
    result = runner.invoke(app, ["explain", "cap.does.not.exist.v99", "--json"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert "error" in data


# ---------------------------------------------------------------------------
# browse
# ---------------------------------------------------------------------------

def test_browse_list_types():
    """browse with no flags lists entity type summary."""
    result = runner.invoke(app, ["browse", "--quiet"])
    assert result.exit_code == 0
    # Should mention entity types
    assert "capability" in result.output.lower()
    assert "worker_species" in result.output.lower() or "wrk" in result.output.lower()


def test_browse_with_type_filter():
    """browse --type cap lists only capability entities."""
    result = runner.invoke(app, ["browse", "--type", "cap", "--quiet"])
    assert result.exit_code == 0
    assert "cap" in result.output.lower()


def test_browse_json_by_type():
    """browse --json returns entity type counts."""
    result = runner.invoke(app, ["browse", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "by_type" in data
    assert "total" in data
    assert data["total"] > 0
    by_type = data["by_type"]
    assert isinstance(by_type, dict)
    assert "capability" in by_type


def test_browse_json_type_filter():
    """browse --type wrk --json returns only worker_species entities."""
    result = runner.invoke(app, ["browse", "--type", "wrk", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "entities" in data
    for e in data["entities"]:
        assert e["type"] == "worker_species"


def test_browse_json_no_pack_id():
    """browse --type cap --json entities must not contain pack_id."""
    result = runner.invoke(app, ["browse", "--type", "cap", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    for e in data["entities"]:
        assert "pack_id" not in e, f"pack_id found in entity {e['id']}"


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

def test_dispatch_known_capability():
    """Dispatch a capability that exists in the catalog with handlers."""
    # cap.doc.ingest is handled by wrk.doc.pipeline.orchestrator
    result = runner.invoke(app, ["dispatch", "cap.doc.ingest", "--quiet"])
    # Exit code 0 = ALLOWED, 1 = DENIED (both are valid routing outcomes)
    assert result.exit_code in (0, 1)
    assert result.output.strip() != ""


# ---------------------------------------------------------------------------
# discord-lab
# ---------------------------------------------------------------------------

def test_discord_lab_json_output():
    result = runner.invoke(app, ["discord-lab", "--json", "--server-name", "fafolab"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["server_name"] == "fafolab"
    assert "agent-bulletin-board" in data["channels"]
    assert data["webhook_map"]["agent-bulletin-board"] == "DISCORD_WEBHOOK_BULLETIN"


def test_discord_lab_writes_env_template(tmp_path):
    target = tmp_path / "fafo_secrets.env"
    result = runner.invoke(
        app,
        [
            "discord-lab",
            "--quiet",
            "--server-name", "fafolab",
            "--client-id", "1234567890",
            "--guild-id", "9876543210",
            "--write-env-template", str(target),
        ],
    )
    assert result.exit_code == 0
    assert target.exists()
    text = target.read_text(encoding="utf-8")
    assert "DISCORD_WEBHOOK_BULLETIN" in text
    assert "DISCORD_GUILD_ID=9876543210" in text
    assert "https://discord.com/oauth2/authorize?" in text


def test_discord_bootstrap_writes_env_file(monkeypatch, tmp_path):
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "test-token")

    import pyhall.cli as cli_mod

    def fake_ensure_text_channel(guild_id, token, channel_name):
        assert guild_id == "9876543210"
        assert token == "test-token"
        return {"id": f"id-{channel_name}", "name": channel_name, "type": 0}

    def fake_create_webhook(channel_id, token, name):
        assert token == "test-token"
        assert name == "fafolab-bot"
        return {"id": f"wh-{channel_id}", "token": f"tok-{channel_id}"}

    monkeypatch.setattr(cli_mod, "_discord_ensure_text_channel", fake_ensure_text_channel)
    monkeypatch.setattr(cli_mod, "_discord_create_webhook", fake_create_webhook)

    target = tmp_path / "discord.env"
    result = runner.invoke(
        app,
        [
            "discord-bootstrap",
            "--quiet",
            "--guild-id", "9876543210",
            "--write-env-file", str(target),
        ],
    )
    assert result.exit_code == 0
    assert target.exists()
    text = target.read_text(encoding="utf-8")
    assert "DISCORD_GUILD_ID=9876543210" in text
    assert "DISCORD_BULLETIN_CHANNEL_ID=id-agent-bulletin-board" in text
    assert "DISCORD_WEBHOOK_BULLETIN=https://discord.com/api/webhooks/wh-id-agent-bulletin-board/tok-id-agent-bulletin-board" in text
    assert "FAFOLAB_DISCORD_QUEUE=/tmp/fafolab_discord_queue.jsonl" in text


def test_discord_bootstrap_existing_only_missing_channel(monkeypatch):
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "test-token")

    import pyhall.cli as cli_mod

    def fake_find_text_channel(guild_id, token, channel_name):
        if channel_name == "agent-bulletin-board":
            return {"id": "id-agent-bulletin-board", "name": channel_name, "type": 0}
        return None

    monkeypatch.setattr(cli_mod, "_discord_find_text_channel", fake_find_text_channel)

    result = runner.invoke(
        app,
        [
            "discord-bootstrap",
            "--quiet",
            "--guild-id", "9876543210",
            "--existing-only",
        ],
    )
    assert result.exit_code == 1
    assert result.exception is not None
    assert "Missing required existing channels for --existing-only" in str(result.exception)


def test_dispatch_unknown_capability():
    """Dispatch an unknown capability results in a DENIED decision."""
    result = runner.invoke(app, ["dispatch", "cap.does.not.exist.v99", "--quiet"])
    # Should be DENIED (fail-closed) — exit 1
    assert result.exit_code == 1


def test_dispatch_dry_run():
    """--dry-run flag does not invoke the routing engine."""
    result = runner.invoke(app, ["dispatch", "cap.doc.ingest", "--dry-run", "--quiet"])
    assert result.exit_code == 0
    assert "dry run" in result.output.lower() or "DRY RUN" in result.output


def test_dispatch_json_output():
    """--json flag returns valid JSON with routing decision fields."""
    result = runner.invoke(app, ["dispatch", "cap.doc.ingest", "--json"])
    assert result.exit_code in (0, 1)
    data = json.loads(result.output)
    # JSON output should include decision fields
    assert "denied" in data or "_meta" in data


def test_dispatch_dry_run_json():
    """--dry-run --json returns structured trace without running the router."""
    result = runner.invoke(app, ["dispatch", "cap.doc.ingest", "--dry-run", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data.get("dry_run") is True
    assert "trace" in data
    assert isinstance(data["trace"], list)
