# DECISIONS.md
## Implementation Decisions — M3Platform Security Assessment

---

## Decision 1: Use `crypto.randomUUID()` for share tokens, remove recordId prefix

**What:** Token generation changed from `${recordId}-${Math.random().toString(36).slice(2, 8)}` to `randomUUID()` from Node's built-in `crypto` module.

**Why:** The original approach had two compounding problems. `Math.random()` is not cryptographically secure — it can be predicted if an attacker can observe enough outputs. The `recordId` prefix meant a token for `rec-100` always started with `rec-100-`, reducing the search space for a targeted brute-force attack from the full token space to just the 6-character suffix (~2.2B combinations). `crypto.randomUUID()` provides 122 bits of entropy with no external dependency and is the correct tool for security-sensitive token generation in Node.js.

The Redis key structure changed to `share:{recordId}:{token}` so the recordId is encoded in the key (needed for scoped lookup) without being embedded in the token value itself.

---

## Decision 2: Set Redis TTL to 24 hours, make it configurable via `SHARE_TOKEN_TTL_SECONDS`

**What:** All Redis share tokens are stored with `{ EX: ttlSeconds }` where `ttlSeconds` defaults to 86400 (24 hours) but is overridable via environment variable.

**Why:** Share tokens in a clinical context serve a specific short-term purpose — a clinician sharing a record for a colleague to review. A 24-hour window covers same-day clinical workflows without leaving tokens valid indefinitely. I chose 24 hours over shorter windows (1 hour felt too tight for async workflows) and longer windows (7 days means a token for a sensitive health record is valid across a work week with no intervention needed). Making it configurable via env allows deployment-specific tuning without code changes.

---

## Decision 3: Implement one-time-use token redemption rather than just TTL

**What:** Added `redeemShare()` method that marks a token `used: true` on first redemption. Subsequent calls return `{ valid: false }`.

**Why:** TTL alone doesn't prevent a valid token from being used multiple times within the expiry window. In a healthcare context, the share link model should ideally grant a single viewing session — once the record has been accessed via the share link, the link should no longer work. This is especially important because share links are transmitted via channels (email, chat) that may have their own retention and forwarding risks. One-time-use means a forwarded link is useless after first use.

I used a simple `used` flag in the Redis value rather than `GETDEL` because the `redeemShare` call needs to read the value (to verify it exists and isn't already used) before deciding to delete or mark it. A Lua script would make this fully atomic; the current approach is sufficient for the concurrency level of a clinical records system and the comment in code documents the upgrade path.

---

## Decision 4: Strip PHI from audit events at the `sanitizeEvent()` layer, not at call sites

**What:** Rather than fixing each call to `this.audit.log()` to not pass PHI, I introduced `sanitizeEvent()` inside `audit.ts` that drops the `details` field regardless of what callers pass.

**Why:** Defense-in-depth. If a developer adds a new audit call site in the future and inadvertently passes `details: record`, the sanitization layer catches it. Relying solely on call-site discipline means one missed line in a future PR creates a new PHI leak. I also fixed the call sites in `recordManager.ts` to not pass PHI, so the protection exists at both layers — the sanitization function is a safety net, not the primary control.

---

## Decision 5: Audit write failures are non-blocking but always observable

**What:** The GCS audit write is wrapped in try/catch. On failure, a structured `AUDIT_WRITE_FAILED` message is written to stderr and the primary operation (record read, share create, etc.) completes successfully.

**Why:** The alternative — failing the entire request if audit logging fails — would mean a GCS outage or misconfiguration takes down the entire application. Healthcare systems must prioritize availability for clinical operations; a provider reading a patient record during an incident cannot wait for audit infrastructure to recover. However, silently swallowing the error would create invisible compliance gaps. The chosen approach surfaces the failure to the log aggregation pipeline (stderr is captured by every standard log infrastructure) where it can be alerted on by ops, while keeping the application operational. The structured error payload includes enough context (`actor`, `action`, `targetId`) to reconstruct the missing audit entry if needed.

---

## Rejected Alternative: Return 404 instead of 403 for unauthorized record access

**What I considered:** When a user requests a record they don't own, return `404 Not Found` instead of `403 Forbidden`.

**Why it was considered:** The security argument for 404 is that it prevents "oracle" attacks — an attacker can't distinguish "this record exists and you can't see it" from "this record doesn't exist." If the API always returns 404 for missing or unauthorized records, enumerating valid record IDs becomes harder because valid-but-unauthorized IDs look the same as invalid IDs.

**Why I rejected it:** In this codebase, record IDs are sequential and short (`rec-100`, `rec-200`). An attacker can trivially confirm a record exists by creating it themselves or through other side channels. The 404 obfuscation provides minimal security benefit in this design. More importantly, returning 403 is the semantically correct response — the resource exists, the user is authenticated, but they are not authorized. Returning 404 breaks the principle of least surprise for legitimate callers and makes debugging authorization issues significantly harder for developers and support teams. The correct long-term fix for ID enumeration is to use non-sequential UUIDs for record IDs, not to misuse HTTP status codes.
