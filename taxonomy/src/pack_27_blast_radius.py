"""Pack 27: Blast Radius, Determinism & Privilege Envelopes (proposed)"""

PACKS = [
    {
        "id": "pack.27",
        "name": "Blast Radius, Determinism & Privilege Envelopes (proposed)",
        "entity_count": 6,
    },
]

ENTITIES = [
    # --- Controls ---
    {
        "id": "ctrl.blast_radius_scoring",
        "type": "control",
        "pack_id": "pack.27",
        "name": "Blast Radius Scoring",
        "description": "Compute blast score (0-100) from env, data_label, QoS, and request hints; gate actions with score >= 85 in prod.",
        "tags": ["blast-radius", "governance", "safety"],
        "enforcement_point": "hall",
        "required_for_risk_tiers": ["high", "critical"],
    },
    {
        "id": "ctrl.privilege_envelopes_required",
        "type": "control",
        "pack_id": "pack.27",
        "name": "Privilege Envelopes Required",
        "description": "Workers must declare a privilege envelope (secrets, egress, writes, tools) before execution.",
        "tags": ["blast-radius", "least-privilege", "security"],
        "enforcement_point": "hall",
        "required_for_risk_tiers": ["medium", "high", "critical"],
    },
    # --- Policies ---
    {
        "id": "pol.egress_allowlist_policy",
        "type": "policy",
        "pack_id": "pack.27",
        "name": "Egress Allowlist Policy",
        "description": "In prod/edge with RESTRICTED data, any egress destinations must be explicitly allowlisted.",
        "tags": ["blast-radius", "egress", "policy"],
        "controls_required": [
            "ctrl.sandbox.no_egress_default_deny",
            "ctrl.sandbox.path_allowlists",
            "ctrl.blast_radius_scoring",
        ],
    },
    {
        "id": "pol.replay_safety_policy",
        "type": "policy",
        "pack_id": "pack.27",
        "name": "Replay Safety Policy",
        "description": "Nondeterministic workers require checkpoints and approvals before replay.",
        "tags": ["blast-radius", "replay", "policy"],
        "controls_required": [
            "ctrl.obs.audit_log_append_only",
            "ctrl.blast_radius_scoring",
        ],
    },
    {
        "id": "pol.sandbox.default_deny",
        "type": "policy",
        "pack_id": "pack.27",
        "name": "Sandbox Default Deny Policy",
        "description": "All workers must operate in sandbox default-deny posture unless explicitly exempted.",
        "tags": ["blast-radius", "sandbox", "policy"],
        "controls_required": [
            "ctrl.sandbox.no_egress_default_deny",
            "ctrl.sandbox.secrets_denied_by_default",
            "ctrl.privilege_envelopes_required",
        ],
    },
    {
        "id": "pol.pol.default_deny",
        "type": "policy",
        "pack_id": "pack.27",
        "name": "Policy Default Deny",
        "description": "Policy engine must default-deny all capability requests not covered by explicit policy.",
        "tags": ["blast-radius", "policy", "authorization"],
        "controls_required": [
            "ctrl.pol.default_deny",
            "ctrl.pol.policy_engine_runtime",
            "ctrl.blast_radius_scoring",
        ],
    },
]
