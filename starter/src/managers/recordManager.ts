import { buildGuidancePrompt } from "../config/promptTemplate.js";
import type { AuditLogger } from "../security/audit.js";
import { InMemoryRecordRepository } from "../storage/recordRepository.js";
import type { AppUser, HealthRecord } from "../types.js";
import type { AppLogger } from "../utils/logger.js";

// FIX-MISC-1: Maximum length for user-supplied patientSummary input.
// Prevents prompt injection via oversized or directive-laden input.
const MAX_PATIENT_SUMMARY_LENGTH = 500;

export class RecordManager {
  constructor(
    private repository: InMemoryRecordRepository,
    private logger: AppLogger,
    private audit: AuditLogger,
    private guidanceTemplate: string,
  ) {}

  async getRecord(recordId: string, user: AppUser): Promise<HealthRecord> {
    const record = this.repository.getRecordById(recordId);

    if (!record) {
      throw new Error("record_not_found");
    }

    // FIX-BOLA-1: Enforce record ownership. A user may only access their own records
    // unless they hold the admin role. Without this check, any authenticated user
    // could read any record by guessing or enumerating recordIds (IDOR/BOLA).
    if (record.ownerUserId !== user.userId && user.role !== "admin") {
      // Audit the denied attempt before throwing.
      await this.audit.log({
        actor: user.userId,
        action: "record_read_denied",
        targetId: recordId,
        result: "denied",
      });
      throw new Error("access_denied");
    }

    // FIX-LOG-1: Log only metadata — never the record content.
    // Previously: this.logger.info("record_read", { user, record }) — logged full PHI.
    this.logger.info("record_read", { userId: user.userId, recordId });

    await this.audit.log({
      actor: user.userId,
      action: "record_read",
      targetId: recordId,
      result: "success",
      // FIX-GCS-3: `details` field removed — audit.ts sanitizeEvent() also enforces this,
      // but we stop passing PHI here as defense-in-depth.
    });

    return record;
  }

  async createShareLink(recordId: string, user: AppUser): Promise<{ url: string }> {
    const record = this.repository.getRecordById(recordId);

    if (!record) {
      throw new Error("record_not_found");
    }

    // FIX-BOLA-1: Same ownership check as getRecord.
    if (record.ownerUserId !== user.userId && user.role !== "admin") {
      await this.audit.log({
        actor: user.userId,
        action: "record_share_denied",
        targetId: recordId,
        result: "denied",
      });
      throw new Error("access_denied");
    }

    const share = await this.repository.createShare(recordId, user.userId);

    // FIX-LOG-1: Log only token and recordId — not the record content.
    this.logger.info("record_share_created", { userId: user.userId, recordId, token: share.token });

    // FIX-AUDIT-1: createShareLink previously had NO audit log call at all.
    // Share creation is a sensitive PHI access event and must be audited.
    await this.audit.log({
      actor: user.userId,
      action: "record_share_created",
      targetId: recordId,
      result: "success",
    });

    return {
      url: `https://example.local/share/${share.token}`,
    };
  }

  async generateGuidance(
    recordId: string,
    user: AppUser,
    patientSummary: string,
  ): Promise<{ promptPreview: string }> {
    const record = this.repository.getRecordById(recordId);

    if (!record) {
      throw new Error("record_not_found");
    }

    // FIX-BOLA-1: Ownership check before generating AI guidance.
    if (record.ownerUserId !== user.userId && user.role !== "admin") {
      await this.audit.log({
        actor: user.userId,
        action: "guidance_denied",
        targetId: recordId,
        result: "denied",
      });
      throw new Error("access_denied");
    }

    // FIX-INJECT-1: Validate and truncate patientSummary before it enters the prompt.
    // Rejects inputs that exceed the max length rather than silently truncating,
    // so callers receive a clear error instead of unexpected partial behavior.
    if (typeof patientSummary !== "string") {
      throw new Error("invalid_input");
    }
    if (patientSummary.length > MAX_PATIENT_SUMMARY_LENGTH) {
      throw new Error(`patient_summary_too_long:max_${MAX_PATIENT_SUMMARY_LENGTH}`);
    }

    const prompt = buildGuidancePrompt(this.guidanceTemplate, patientSummary);

    // FIX-LOG-1: Log only metadata — not the prompt content or record fields.
    // Previously: this.logger.info("guidance_generated", { user, record, prompt }) — logged full PHI + prompt.
    this.logger.info("guidance_generated", { userId: user.userId, recordId });

    // FIX-AUDIT-1: generateGuidance previously had no audit log call.
    await this.audit.log({
      actor: user.userId,
      action: "guidance_generated",
      targetId: recordId,
      result: "success",
    });

    return {
      promptPreview: prompt.slice(0, 300),
    };
  }
}
