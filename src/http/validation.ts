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
