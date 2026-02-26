"""Pack source — pack_27_blast_radius"""

ENTITIES = [
    {
        'id': 'ctrl.blast-radius-scoring',
        'type': 'control',
        'name': 'Blast Radius Scoring',
        'description': 'Compute blast score (0-100) from env, data_label, QoS, and request hints; gate actions with score >= 85 in prod.',
        'tags': [
            'blast-radius',
            'governance',
            'safety',
        ],
        'enforcement_point': 'hall',
        'required_for_risk_tiers': [
            'high',
            'critical',
        ],
        'wcp_namespace': 'reserved',
    },
    {
        'id': 'ctrl.privilege-envelopes-required',
        'type': 'control',
        'name': 'Privilege Envelopes Required',
        'description': 'Workers must declare a privilege envelope (secrets, egress, writes, tools) before execution.',
        'tags': [
            'blast-radius',
            'least-privilege',
            'security',
        ],
        'enforcement_point': 'hall',
        'required_for_risk_tiers': [
            'medium',
            'high',
            'critical',
        ],
        'wcp_namespace': 'reserved',
    },
    {
        'id': 'pol.egress-allowlist-policy',
        'type': 'policy',
        'name': 'Egress Allowlist Policy',
        'description': 'In prod/edge with RESTRICTED data, any egress destinations must be explicitly allowlisted.',
        'tags': [
            'blast-radius',
            'egress',
            'policy',
        ],
        'controls_required': [
            'ctrl.sandbox.no-egress-default-deny',
            'ctrl.sandbox.path-allowlists',
            'ctrl.blast-radius-scoring',
        ],
        'wcp_namespace': 'reserved',
    },
    {
        'id': 'pol.replay-safety-policy',
        'type': 'policy',
        'name': 'Replay Safety Policy',
        'description': 'Nondeterministic workers require checkpoints and approvals before replay.',
        'tags': [
            'blast-radius',
            'replay',
            'policy',
        ],
        'controls_required': [
            'ctrl.obs.audit-log-append-only',
            'ctrl.blast-radius-scoring',
        ],
        'wcp_namespace': 'reserved',
    },
    {
        'id': 'pol.sandbox.default-deny',
        'type': 'policy',
        'name': 'Sandbox Default Deny Policy',
        'description': 'All workers must operate in sandbox default-deny posture unless explicitly exempted.',
        'tags': [
            'blast-radius',
            'sandbox',
            'policy',
        ],
        'controls_required': [
            'ctrl.sandbox.no-egress-default-deny',
            'ctrl.sandbox.secrets-denied-by-default',
            'ctrl.privilege-envelopes-required',
        ],
        'wcp_namespace': 'reserved',
    },
    {
        'id': 'pol.default-deny',
        'type': 'policy',
        'name': 'Policy Default Deny',
        'description': 'Policy engine must default-deny all capability requests not covered by explicit policy.',
        'tags': [
            'blast-radius',
            'policy',
            'authorization',
        ],
        'controls_required': [
            'ctrl.pol.default-deny',
            'ctrl.pol.policy-engine-runtime',
            'ctrl.blast-radius-scoring',
        ],
        'wcp_namespace': 'reserved',
    },
]
