import { describe, expect, test } from "bun:test";
import { parsePhishingDatabaseSnapshot } from "../src/providers/phishing-database.ts";

const URL_SOURCE = "https://phish.co.za/latest/phishing-links-ACTIVE.txt";
const HOSTNAME_SOURCE = "https://phish.co.za/latest/phishing-domains-ACTIVE.txt";

describe("Phishing.Database snapshot parser", () => {
  test("URL scope emits URL indicators only and never promotes a hostname", () => {
    const rows = parsePhishingDatabaseSnapshot("# comment\nhttps://Phish.Example/login#fragment\nhttps://Phish.Example/login#fragment\n", URL_SOURCE, "url");
    expect(rows).toEqual([
      { indicatorType: "url", indicator: "https://phish.example/login", threatType: "phishing", severity: "critical", source: "phishing_database", reference: URL_SOURCE }
    ]);
  });

  test("hostname scope emits hostname indicators only", () => {
    const rows = parsePhishingDatabaseSnapshot("phish.example\n", HOSTNAME_SOURCE, "hostname");
    expect(rows).toEqual([
      { indicatorType: "hostname", indicator: "phish.example", threatType: "phishing", severity: "critical", source: "phishing_database", reference: HOSTNAME_SOURCE }
    ]);
  });

  test("hostname scope preserves URL hostname canonical form for IPv6 literals", () => {
    expect(parsePhishingDatabaseSnapshot("[2001:1::1]\n", HOSTNAME_SOURCE, "hostname")[0]?.indicator).toBe("[2001:1::1]");
  });

  test("rejects mixed rows and mismatched source scope", () => {
    expect(() => parsePhishingDatabaseSnapshot("phish.example\n", URL_SOURCE, "url")).toThrow("scope");
    expect(() => parsePhishingDatabaseSnapshot("https://phish.example/\n", HOSTNAME_SOURCE, "hostname")).toThrow("scope");
    expect(() => parsePhishingDatabaseSnapshot("phish.example\n", URL_SOURCE, "hostname")).toThrow("scope");
  });

  test("rejects inactive, historical, arbitrary, and malformed source references", () => {
    expect(() => parsePhishingDatabaseSnapshot("phish.example\n", "https://phish.co.za/latest/phishing-domains-INACTIVE.txt", "hostname")).toThrow("not official");
    expect(() => parsePhishingDatabaseSnapshot("phish.example\n", "https://phish.co.za/latest/ALL-phishing-domains.lst", "hostname")).toThrow("not official");
    expect(() => parsePhishingDatabaseSnapshot("phish.example\n", "https://attacker.example/feed.txt", "hostname")).toThrow("not official");
    expect(() => parsePhishingDatabaseSnapshot("https://user:pass@phish.example/\n", URL_SOURCE, "url")).toThrow("credentials");
  });

  test("rejects an empty authoritative snapshot before reconciliation", () => {
    expect(() => parsePhishingDatabaseSnapshot("# only a comment\n", HOSTNAME_SOURCE, "hostname")).toThrow("snapshot_empty");
  });
});
