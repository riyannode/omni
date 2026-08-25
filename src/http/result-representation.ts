import type { Response } from "express";
import { renderRiskMarkdown } from "./risk-markdown.ts";

export type ResultRepresentation = "json" | "markdown";

export function representationFromAccept(accepted: string | false): ResultRepresentation | undefined {
  if (accepted === false) return undefined;
  return accepted === "markdown" ? "markdown" : "json";
}

export function sendResult(res: Response, status: number, result: unknown, representation: ResultRepresentation): void {
  res.vary("Accept");
  if (representation === "markdown") {
    res.status(status).type("text/markdown").send(renderRiskMarkdown(result));
    return;
  }
  res.status(status).json(result);
}
