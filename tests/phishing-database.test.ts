import { describe, expect, test } from "bun:test";
import { parsePhishingDatabaseSnapshot } from "../src/providers/phishing-database.ts";

describe("Phishing.Database snapshot parser", () => {
  test("normalizes URL and hostname indicators with authoritative provenance", () => {
    const rows = parsePhishingDatabaseSnapshot("# comment\nhttps://Phish.Example/login#fragment\nphish.example\nhttps://Phish.Example/login#fragment\n", "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE-NOW.txt");
    expect(rows).toEqual([
      { indicatorType: "hostname", indicator: "phish.example", threatType: "phishing", severity: "critical", source: "phishing_database", reference: "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE-NOW.txt" },
      { indicatorType: "url", indicator: "https://phish.example/login", threatType: "phishing", severity: "critical", source: "phishing_database", reference: "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE-NOW.txt" }
    ]);
  });

  test("rejects non-official source references and malformed entries", () => {
    expect(() => parsePhishingDatabaseSnapshot("phish.example\n", "https://attacker.example/feed.txt")).toThrow("not official");
    expect(() => parsePhishingDatabaseSnapshot("https://user:pass@phish.example/\n", "https://phish.co.za/latest/feed.txt")).toThrow("credentials");
  });
});
