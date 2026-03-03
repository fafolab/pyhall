"""
PyHall — Python reference implementation of WCP (Worker Class Protocol).

The Hall is the governed dispatch layer between a capability request and
its execution. Agents contact the Hall; the Hall routes to workers.

Quick start:

    from pyhall import make_decision, RouteInput, Registry, load_rules

    rules = load_rules("my_rules.json")
    registry = Registry(registry_dir="enrolled/")

    inp = RouteInput(
        capability_id="cap.hello.greet",
        env="dev",
        data_label="PUBLIC",
        tenant_risk="low",
        qos_class="P2",
        tenant_id="demo",
        correlation_id="550e8400-e29b-41d4-a716-446655440000",
    )

    decision = make_decision(
        inp=inp,
        rules=rules,
        registry_controls_present=registry.controls_present(),
        registry_worker_available=registry.worker_available,
    )

    print(decision.denied)                   # False
    print(decision.selected_worker_species_id)  # "wrk.hello.greeter"
"""

__version__ = "0.2.0"
__wcp_version__ = "0.1"

from .router import make_decision, detect_shadow_rules
from .models import RouteInput, RouteDecision, HallConfig
from .registry import Registry
from .policy_gate import PolicyGate
from .rules import load_rules, load_rules_from_dict, Rule
from .registry_client import RegistryClient, RegistryRateLimitError, VerifyResponse, BanEntry

__all__ = [
    "make_decision",
    "RouteInput",
    "RouteDecision",
    "HallConfig",
    "Registry",
    "PolicyGate",
    "load_rules",
    "load_rules_from_dict",
    "Rule",
    "detect_shadow_rules",
    "RegistryClient",
    "RegistryRateLimitError",
    "VerifyResponse",
    "BanEntry",
]
