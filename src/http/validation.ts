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

export const agentQuery = z.object({
  /** ERC-8004 agent token id. Accepts decimal or 0x-prefixed hex string. */
  agentId: z.string().regex(/^(0x[0-9a-fA-F]{1,64}|[0-9]{1,78})$/, "agentId must be a decimal integer or 0x-prefixed hex"),
  /** Optional target URL to check for redirect-to-private (caller-supplied, opt-in). */
  targetUrl: z.string().url().max(2048).optional(),
});
