import { Storage } from "@google-cloud/storage";
import type { AuditEvent } from "../types.js";

export type AuditLogger = {
  log: (event: AuditEvent) => Promise<void>;
};

// FIX-GCS-3: Sanitized audit payload type — explicitly excludes the `details` field
// that previously caused full PHI to be written into GCS objects.
type SanitizedAuditEvent = {
  actor: string;
  action: string;
  targetId: string;
  result: string;
  timestamp: string;
  // `details` is intentionally omitted — audit logs record WHO/WHAT/WHEN, never PHI content.
};

function sanitizeEvent(event: AuditEvent): SanitizedAuditEvent {
  return {
    actor: event.actor,
    action: event.action,
    targetId: event.targetId,
    result: event.result,
    timestamp: new Date().toISOString(),
    // Explicitly drop event.details — it may contain raw PHI.
  };
}

function createConsoleAuditLogger(): AuditLogger {
  return {
    async log(event) {
      // FIX-GCS-3: Log only sanitized metadata, not the full event with PHI details.
      const sanitized = sanitizeEvent(event);
      console.log("AUDIT", JSON.stringify(sanitized));
    },
  };
}

function createGcsAuditLogger(): AuditLogger {
  const projectId = process.env.GCP_PROJECT_ID;
  const bucketName = process.env.GCS_AUDIT_BUCKET ?? "dev-audit-bucket";
  const storage = new Storage({ projectId });

  return {
    async log(event) {
      // FIX-GCS-3: Strip PHI from the audit payload before writing to GCS.
      const sanitized = sanitizeEvent(event);

      // FIX-GCS-1: Non-overwritable object strategy.
      // Object names are timestamped to the millisecond + random suffix so that:
      //   (a) no two audit events overwrite each other (previously `audit-action-id.json`
      //       meant the second read of rec-100 silently clobbered the first), and
      //   (b) events are naturally sortable by time for forensic review.
      // Bucket-level immutability (retention lock + versioning) is documented in
      // COMPLIANCE_NOTES.md as a required infrastructure control — this naming strategy
      // is a complementary application-layer control.
      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      const suffix = Math.random().toString(36).slice(2, 8);
      const objectName = `audit/${event.action}/${event.targetId}/${ts}-${suffix}.json`;

      // FIX-GCS-2: Audit write failures are caught and handled.
      // We log the failure to stderr (never silently swallow it) but do NOT throw —
      // an audit write failure should not prevent the primary operation from completing.
      // In production, this should also emit a metric/alert so ops can detect
      // sustained audit pipeline failures.
      try {
        await storage
          .bucket(bucketName)
          .file(objectName)
          .save(JSON.stringify(sanitized), {
            contentType: "application/json",
            // metadata: resumable:false is appropriate for small audit objects
            resumable: false,
          });
      } catch (err) {
        // Structured error log — observable, but non-blocking.
        console.error("AUDIT_WRITE_FAILED", JSON.stringify({
          objectName,
          actor: event.actor,
          action: event.action,
          targetId: event.targetId,
          error: err instanceof Error ? err.message : String(err),
        }));
        // Do not rethrow — audit failure is a degraded-but-operational state.
      }
    },
  };
}

export function createAuditLogger(): AuditLogger {
  if (process.env.USE_GCS_AUDIT_LOGGING === "true") {
    return createGcsAuditLogger();
  }
  return createConsoleAuditLogger();
}
