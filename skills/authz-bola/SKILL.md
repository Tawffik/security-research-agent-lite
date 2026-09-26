# authz-bola

## When to use
Object IDs, actor/resource relationships, authenticated resource access, suspected BOLA/IDOR.

## When not to use
No Actor↔Resource↔Authorization relationship; pure host enumeration without objects.

## Procedure
1. Identify object-keyed endpoint and two identities.
2. Owner baseline request.
3. Non-owner same object request (one discriminating pair — not ID spray).
4. Compare status **and** sensitive fields.
5. Rule out public/shared/role explanations.

## Evidence requirements
Both identities, both responses, ownership markers or denial, scope allow.

## Failure modes
Treating 200 as automatic vuln; ignoring public/shared markers.
