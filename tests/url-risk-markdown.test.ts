import { expect, test } from "bun:test";
import { renderRiskMarkdown } from "../src/http/risk-markdown.ts";

test("renders URL risk dimensions in addition to legacy dimensions", () => {
  const markdown = renderRiskMarkdown({
    subject: { type: "url", id: "https://example.com/" },
    dimensions: { maliciousInfrastructure: "low", serviceIdentity: "low" },
    urlDimensions: { threatReputation: "critical", domainIdentity: "unknown", transportSecurity: "low", networkBehavior: "low" },
    signals: [], evidence: [], sourceErrors: []
  });
  expect(markdown).toContain("## Risk Dimensions");
  expect(markdown).toContain("## URL Risk Dimensions");
  expect(markdown).toContain("- threatReputation: `critical`");
  expect(markdown).toContain("- domainIdentity: `unknown`");
  expect(markdown).toContain("- transportSecurity: `low`");
  expect(markdown).toContain("- networkBehavior: `low`");
});
