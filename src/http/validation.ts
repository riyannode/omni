import { z } from "zod";

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

/**
 * Agent risk query parameters.
 *
 * chain: CAIP-2 chain reference (e.g. "eip155:1"). REQUIRED.
 * agentId: decimal uint256 string only (NO hex). REQUIRED.
 * targetUrl: optional HTTPS URL (caller-supplied, opt-in).
 */
export const agentQuery = z.object({
  chain: z.string().regex(/^eip155:[0-9]+$/, "chain must be a CAIP-2 chain reference (e.g. eip155:1)"),
  agentId: z.string().regex(/^[0-9]{1,78}$/, "agentId must be a decimal uint256 string (hex not accepted)"),
  targetUrl: z.string().url().max(2048)
    .refine((url) => url.startsWith("https://"), "targetUrl must be HTTPS in v1")
    .optional(),
});
