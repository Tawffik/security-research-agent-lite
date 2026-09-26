from agent_lite.opportunities.engine import OpportunityEngine, detect_object_reference
from agent_lite.security.invariants import InvariantRegistry
from agent_lite.target.context import TargetContext


def test_detect_object_patterns():
    assert detect_object_reference("/api/orders/{id}")
    assert detect_object_reference("/api/users/{user_id}")
    assert detect_object_reference("/x", ["order_id"])
    assert not detect_object_reference("/health")


def test_invariant_exists():
    inv = InvariantRegistry().authz_object()
    assert inv.invariant_id == "INV-AUTHZ-001"


def test_opportunity_from_context():
    ctx = TargetContext(
        engagement_id="e",
        primary_host="api.acme-demo.test",
        endpoints=[{"method": "GET", "path": "/api/orders/{id}"}],
        actors=[{"actor_id": "user_a"}, {"actor_id": "user_b"}],
        resources=[{"name": "order-1", "owner_actor_id": "user_a"}],
    )
    opps = OpportunityEngine("e").extract(ctx)
    assert opps
    assert "object_reference" in opps[0].signals
