---
id: PAT-LITE-001
type: pattern
security_property: Object-level authorization binds actor to resource
description: Authenticated caller supplies object id without ownership check
preconditions: multi-identity, object-keyed endpoint
procedure: cross-identity differential on same object id
evidence_requirements: both responses, private field or denial proof
known_false_positives: public resources, shared ACL
provenance: OWASP API1 + full-agent knowledge concepts
version: "0.1"
---
