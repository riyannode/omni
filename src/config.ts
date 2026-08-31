import { z } from "zod";

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
  PHISHING_DATABASE_MAX_AGE_HOURS: z.coerce.number().int().min(1).max(720).default(6),
  GITHUB_TOKEN: z.string().min(1).optional()
});

const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
  throw new Error(`Invalid environment: ${parsed.error.message}`);
}

export const config = {
  ...parsed.data,
  kevFeedUrls: parsed.data.OMNI_KEV_FEED_URLS.split(",").map((x: string) => x.trim()).filter(Boolean)
};
