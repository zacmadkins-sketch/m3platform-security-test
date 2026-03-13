# COMPLIANCE_NOTES.md
## SOC 2 Type II + HIPAA Compliance Mapping — M3Platform Health Records API

---

## HIPAA Technical Safeguards (45 CFR § 164.312)

### § 164.312(a)(1) — Access Control
**Fix applied: FIX-BOLA-1**

Before: No ownership check in `getRecord`, `createShareLink`, or `generateGuidance`. Any authenticated user could access any patient record (IDOR). After: All three methods enforce `record.ownerUserId === user.userId` or `user.role === "admin"` before proceeding. Denied access is audited.

**Minimum necessary standard (§ 164.502(b)):** Each response returns only the requested record; the fix ensures users cannot access records beyond their need.

---

### § 164.312(b) — Audit Controls
**Fix applied: FIX-GCS-1, FIX-GCS-2, FIX-GCS-3, FIX-AUDIT-1**

Before: Audit events included full PHI in `details`. Share creation and guidance generation produced no audit events. GCS object names were predictable and overwritable (second read of `rec-100` silently replaced the first audit entry).

After:
- `sanitizeEvent()` strips `details` — audit objects contain only `actor`, `action`, `targetId`, `result`, `timestamp`.
- Object names include ISO timestamp + random suffix: `audit/{action}/{targetId}/{ts}-{suffix}.json` — each event creates a new immutable object.
- Audit write failures are caught and logged to stderr with structured context. They do not silently fail.
- `createShareLink` and `generateGuidance` now emit audit events.

**Infrastructure requirement (documented):** GCS bucket must have a retention lock (minimum 7 years per HIPAA § 164.530(j)) and versioning enabled.

---

### § 164.312(c)(1) — Integrity Controls
**Fix applied: FIX-REDIS-2, FIX-REDIS-3, FIX-GCS-1**

Before: Share tokens never expired, could not be revoked, and reuse was undetectable. GCS objects were overwritten silently.

After: Redis tokens expire after 24 hours (configurable). `redeemShare()` marks tokens `used=true` on first use — subsequent redemption attempts return invalid. GCS audit objects are non-overwritable by design (unique names).

---

### § 164.312(d) — Person or Entity Authentication
**Status: Not fully remediated (residual risk)**

Header-based auth remains. This is the highest-priority remaining item. Recommended path: `@fastify/jwt` with RS256 signed tokens, verified on every request. Current fixes add defense-in-depth (ownership checks) that reduce blast radius even if auth is bypassed, but do not replace proper authentication.

---

### § 164.312(e)(2)(ii) — Encryption and Decryption
**Infrastructure assumption documented**

Application code does not manage encryption directly. GCS bucket encryption (GMEK minimum, CMEK recommended) and Redis TLS (`rediss://` URL scheme) are assumed infrastructure controls. Redis connection string should use TLS in production.

---

## HIPAA Administrative Safeguards (45 CFR § 164.308)

### § 164.308(a)(1)(ii)(D) — Information System Activity Review
**Fix applied: FIX-AUDIT-1, FIX-GCS-1, FIX-GCS-3**

All PHI access events (read, share, guidance) now produce structured audit records in GCS. Unique object names allow complete enumeration of access history per record. Sanitized payloads mean audit logs can be reviewed without further PHI exposure.

### § 164.308(a)(3) — Workforce Access Management
**Fix applied: FIX-BOLA-1**

Ownership-based access control ensures that workforce members can only access records assigned to them, enforcing minimum necessary access at the application layer.

---

## SOC 2 Type II — Trust Services Criteria

### CC6.1 — Logical Access Controls
**Fix applied: FIX-BOLA-1**

Prior to fix: any authenticated session accessed any record. After fix: access is scoped to record owner or admin. Evidence for SOC 2 auditors: audit log entries show `record_read_denied` for cross-user access attempts; 403 responses confirm enforcement at the HTTP layer.

### CC6.3 — Role-Based Access / Least Privilege
**Fix applied: FIX-BOLA-1, FIX-REDIS-1**

Ownership check implements least-privilege at the record level. Redis values no longer store PHI — only the metadata needed for validation (`createdBy`, `createdAt`, `used`).

### CC6.7 — Protection of Confidential Information in Transmission/Storage
**Fix applied: FIX-LOG-1, FIX-GCS-3, FIX-REDIS-1**

PHI no longer written into application logs or audit payloads. Redis values contain no PHI. Infrastructure-level encryption (GCS CMEK, Redis TLS) documented as required control.

### CC7.2 — System Monitoring
**Fix applied: FIX-AUDIT-1, FIX-GCS-1, FIX-GCS-2**

All three sensitive operations now emit audit events. GCS write failures produce structured stderr output suitable for log aggregation and alerting. Unique object names make audit trail enumerable and complete.

### CC9.2 — Vendor / Third-Party Risk (GCS, Redis)
**Fix applied: FIX-GCS-1, FIX-GCS-2, FIX-REDIS-2**

GCS: unique object names, failure handling, and documented bucket IAM/retention assumptions reduce reliance on implicit GCS behavior. Redis: TTL prevents unbounded data accumulation; connection URL is externalized via env for production TLS configuration.

---

## Compliance Controls Summary

| Control | HIPAA | SOC 2 | Implemented | Residual |
|---|---|---|---|---|
| Record ownership enforcement | § 164.312(a)(1) | CC6.1, CC6.3 | FIX-BOLA-1 | Header auth still weak |
| PHI stripped from logs | § 164.312(b) | CC6.7 | FIX-LOG-1, FIX-GCS-3 | Log infra access controls (ops) |
| Audit completeness | § 164.312(b) | CC7.2 | FIX-AUDIT-1 | None |
| Audit immutability | § 164.312(b) | CC7.2 | FIX-GCS-1 + bucket retention lock | Retention lock is infra, not code |
| Audit write failure handling | § 164.308(a)(1) | CC7.2 | FIX-GCS-2 | Alert pipeline is ops concern |
| Token expiry + revocation | § 164.312(c)(1) | CC6.1 | FIX-REDIS-2, FIX-REDIS-3 | Concurrency edge case in redemption |
| Input validation | § 164.306(a)(3) | CC6.7 | FIX-INJECT-1 | Semantic injection undetected |
| Authentication | § 164.312(d) | CC6.1 | Not fixed | Highest residual risk |
