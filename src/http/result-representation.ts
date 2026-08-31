import type { Response } from "express";
import { renderRiskMarkdown } from "./risk-markdown.ts";

export type ResultRepresentation = "json" | "markdown";
export type MarkdownArtifact = {
  filename: string;
  mediaType: "text/markdown";
  content: string;
};

const ARTIFACT_FILENAME_BY_ROUTE = {
  package: "package.risk.md",
  repository: "repo.risk.md",
  dependencies: "dependencies.risk.md",
  endpoint_preflight: "x402.endpoint.preflight.md",
  url_risk: "url.risk.md"
} as const;

export function artifactFilenameForRoute(route: string): string | undefined {
  if (!Object.hasOwn(ARTIFACT_FILENAME_BY_ROUTE, route)) return undefined;
  return ARTIFACT_FILENAME_BY_ROUTE[route as keyof typeof ARTIFACT_FILENAME_BY_ROUTE];
}

export function representationFromAccept(accepted: string | false): ResultRepresentation | undefined {
  if (accepted === false) return undefined;
  return accepted === "markdown" ? "markdown" : "json";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function addArtifact(result: unknown, route: string): unknown {
  const filename = artifactFilenameForRoute(route);
  if (filename === undefined || !isRecord(result)) return result;
  const artifact: MarkdownArtifact = {
    filename,
    mediaType: "text/markdown",
    content: renderRiskMarkdown(result)
  };
  return { ...result, artifact };
}

export function sendResult(res: Response, status: number, result: unknown, representation: ResultRepresentation, route: string): void {
  res.vary("Accept");
  if (representation === "markdown") {
    res.status(status).type("text/markdown").send(renderRiskMarkdown(result));
    return;
  }
  res.status(status).json(status >= 200 && status < 300 ? addArtifact(result, route) : result);
}
