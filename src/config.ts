import { z } from "zod";
import type { AgentReputationPolicy, RecognizedTagPolicy } from "./domain/risk.ts";

const envSchema = z.object({
  SELLER_ADDRESS: z.string().regex(/^0x[a-fA-F0-9]{40}$/).refine((value: string) => !/^0x0{40}$/i.test(value), "SELLER_ADDRESS must not be the zero address"),
  CIRCLE_FACILITATOR_URL: z.string().url().optional(),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  PUBLIC_BASE_URL: z.string().url().optional(),
  DATABASE_URL: z.string().min(1).optional(),
  REDIS_URL: z.string().min(1).optional(),
  MAX_IN_FLIGHT: z.coerce.number().int().min(32).max(100_000).default(512),
  UPSTREAM_TIMEOUT_MS: z.coerce.number().int().min(250).max(15_000).default(3000),
  UPSTREAM_MAX_IN_FLIGHT: z.coerce.number().int().min(8).max(4096).default(256),
  UPSTREAM_MAX_QUEUE: z.coerce.number().int().min(0).max(50_000).default(2048),
  OMNI_KEV_FEED_URLS: z.string().default(""),
  OMNI_AGENT_REPUTATION_POLICY_JSON: z.string().default("{}"),
  GITHUB_TOKEN: z.string().min(1).optional()
});

const reputationPolicySchema = z.object({
  trustedReviewers: z.array(z.string().regex(/^0x[a-fA-F0-9]{40}$/)).default([]),
  recognizedTags: z.array(z.object({
    tag: z.string().min(1).max(128),
    direction: z.enum(["higher_is_better", "lower_is_better"]),
    threshold: z.union([z.string().min(1).max(128), z.number().finite().refine(value => !String(value).toLowerCase().includes("e"), "threshold must use decimal notation")]),
    expectedDecimals: z.number().int().min(0).max(18).optional(),
    allowedDecimals: z.array(z.number().int().min(0).max(18)).max(19).optional(),
    riskWeight: z.number().int().min(0).max(100)
  }).strict()).default([])
}).strict();

function parseAgentReputationPolicy(raw: string): AgentReputationPolicy {
  try {
    const parsed = reputationPolicySchema.parse(JSON.parse(raw)) as {
      trustedReviewers: string[];
      recognizedTags: RecognizedTagPolicy[];
    };
    return {
      trustedReviewers: new Set(parsed.trustedReviewers.map(address => address.toLowerCase())),
      recognizedTags: parsed.recognizedTags,
    };
  } catch (error) {
    throw new Error(`Invalid OMNI_AGENT_REPUTATION_POLICY_JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
  throw new Error(`Invalid environment: ${parsed.error.message}`);
}

export const config = {
  ...parsed.data,
  kevFeedUrls: parsed.data.OMNI_KEV_FEED_URLS.split(",").map((x: string) => x.trim()).filter(Boolean),
  agentReputationPolicy: parseAgentReputationPolicy(parsed.data.OMNI_AGENT_REPUTATION_POLICY_JSON),
};
