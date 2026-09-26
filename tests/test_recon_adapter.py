from agent_lite.recon.adapter import ReconAdapter


def test_adapt_minimal():
    n = ReconAdapter().adapt({
        "host": "api.acme-demo.test",
        "urls": ["/api/orders/{id}"],
        "identities": ["user_a", "user_b"],
    })
    assert n.primary_host == "api.acme-demo.test"
    assert n.endpoints
