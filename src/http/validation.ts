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

// UINT256_MAX as string for comparison
const UINT256_MAX_STR = "115792089237316195423570985008687907853269984665640564039457584007913129639935";

/**
 * Agent risk query parameters.
 *
 * chain: CAIP-2 chain reference (e.g. "eip155:1"). REQUIRED.
 * agentId: decimal uint256 string only (NO hex). REQUIRED.
 */
export const agentQuery = z.object({
  chain: z.string().regex(/^eip155:[0-9]+$/, "chain must be a CAIP-2 chain reference (e.g. eip155:1)"),
  agentId: z.string().regex(/^[0-9]+$/, "agentId must be a non-negative decimal integer")
    .refine((val) => {
      // Reject empty, leading zeros (except "0"), and values > UINT256_MAX
      if (val.length === 0) return false;
      if (val.length > 1 && val.startsWith("0")) return false;
      if (val.length > 78) return false;
      if (val.length < 78) return true;
      // Same length as max, compare lexicographically
      return val <= UINT256_MAX_STR;
    }, `agentId must be a valid uint256 (0 to ${UINT256_MAX_STR})`),
}).strict();
