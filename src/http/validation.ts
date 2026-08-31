import { z } from "zod";
import { normalizeUrlRiskTarget } from "../domain/url-risk.ts";
import { isDisallowedHostname } from "../providers/public-network.ts";

export const packageQuery = z.object({
  ecosystem: z.string().min(1).max(32),
  name: z.string().min(1).max(256),
  version: z.string().min(1).max(128)
});

export const repoQuery = z.object({
  owner: z.string().regex(/^[A-Za-z0-9_.-]{1,100}$/),
  repo: z.string().regex(/^[A-Za-z0-9_.-]{1,100}$/)
});

export const dependenciesBody = z.object({
  packages: z.array(packageQuery).min(1).max(100)
});

export const endpointQuery = z.object({
  url: z.string().url().max(2048)
});

export const urlRiskQuery = z.object({
  url: z.string().min(1).max(2048)
}).transform(({ url }, context) => {
  try { return normalizeUrlRiskTarget(url); }
  catch { context.addIssue({ code: "custom", message: "invalid_url" }); return z.NEVER; }
}).refine(target => !isDisallowedHostname(target.hostname));
