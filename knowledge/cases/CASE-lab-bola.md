---
id: CASE-LITE-001
type: case
security_property: Owner-only order access
description: Synthetic lab non-owner receives order body with private fields
preconditions: lab fixture
procedure: owner vs non-owner GET /api/orders/{id}
evidence_requirements: status+body both identities
known_false_positives: N/A
provenance: synthetic
version: "0.1"
---
