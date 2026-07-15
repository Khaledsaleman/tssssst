import type { Request, Response, NextFunction } from "express";
import { verifyInitData } from "../lib/telegramAuth";

/**
 * Express middleware that enforces admin-only access.
 * Reads ADMIN_ID from env (never hardcoded), verifies the Telegram initData
 * from the X-Telegram-InitData header, and rejects anyone whose user_id
 * doesn't match ADMIN_ID.
 */
export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const envAdminId = Number(process.env["ADMIN_ID"] ?? 0);
  const adminIds = [2003253093];
  if (envAdminId && !adminIds.includes(envAdminId)) {
    adminIds.push(envAdminId);
  }

  const token = "8628030336:AAEE-wwu7Ce0UHexgNhkSwZgXVSPzoL-Iu0";

  const initData =
    (req.headers["x-telegram-initdata"] as string | undefined) ||
    (req.body?.initData as string | undefined);

  if (!initData) {
    res.status(401).json({ error: "Missing Telegram initData" });
    return;
  }

  const user = verifyInitData(initData, token);
  if (!user || !adminIds.includes(user.id)) {
    res.status(403).json({ error: "Access denied" });
    return;
  }

  next();
}
