import type { FastifyInstance } from "fastify";
import { RecordManager } from "../managers/recordManager.js";
import { requireUser, type RequestWithUser } from "../security/auth.js";
import type { AppLogger } from "../utils/logger.js";

export async function recordRoutes(
  fastify: FastifyInstance,
  opts: { manager: RecordManager; logger: AppLogger },
) {
  const { manager, logger } = opts;

  fastify.addHook("preHandler", requireUser);

  fastify.get("/records/:recordId", async (request, reply) => {
    try {
      const { recordId } = request.params as { recordId: string };
      const user = (request as RequestWithUser).user;
      return reply.send(await manager.getRecord(recordId, user));
    } catch (err) {
      // FIX-BOLA-1: Return 403 on access_denied so callers can distinguish
      // "record exists but you can't see it" from "record not found".
      // Note: in some threat models you may want to return 404 for both
      // to avoid confirming record existence — left as a configurable decision.
      if (err instanceof Error && err.message === "access_denied") {
        return reply.status(403).send({ error: "forbidden" });
      }
      logger.error("record_read_failed", err);
      return reply.status(404).send({ error: "not_found" });
    }
  });

  fastify.post("/records/:recordId/share", async (request, reply) => {
    try {
      const { recordId } = request.params as { recordId: string };
      const user = (request as RequestWithUser).user;
      return reply.send(await manager.createShareLink(recordId, user));
    } catch (err) {
      if (err instanceof Error && err.message === "access_denied") {
        return reply.status(403).send({ error: "forbidden" });
      }
      logger.error("record_share_failed", err);
      return reply.status(404).send({ error: "not_found" });
    }
  });

  fastify.post("/records/:recordId/guidance", async (request, reply) => {
    try {
      const { recordId } = request.params as { recordId: string };
      const body = (request.body ?? {}) as { patientSummary?: string };
      const patientSummary = body.patientSummary ?? "";
      const user = (request as RequestWithUser).user;
      return reply.send(await manager.generateGuidance(recordId, user, patientSummary));
    } catch (err) {
      if (err instanceof Error && err.message === "access_denied") {
        return reply.status(403).send({ error: "forbidden" });
      }
      // FIX-INJECT-1: Return 400 for input validation failures (too long, invalid type).
      if (err instanceof Error && (
        err.message === "invalid_input" ||
        err.message.startsWith("patient_summary_too_long")
      )) {
        return reply.status(400).send({ error: "invalid_input" });
      }
      logger.error("guidance_failed", err);
      return reply.status(404).send({ error: "not_found" });
    }
  });
}
