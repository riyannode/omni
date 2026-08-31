import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { parseSha256Checksum, validatePhishingMaxAgeHours, verifySha256 } from "../src/providers/phishing-database-sync.ts";

const bytes = new TextEncoder().encode("fixture\n");
const digest = createHash("sha256").update(bytes).digest("hex");

test("verifies raw feed bytes against an official exact SHA-256 checksum", () => {
  const checksum = new TextEncoder().encode(`${digest.toUpperCase()} *phishing-links-ACTIVE.txt\n`);
  expect(parseSha256Checksum(checksum, "phishing-links-ACTIVE.txt", "https://raw.githubusercontent.com/Phishing-Database/checksums/master/phishing-links-ACTIVE.txt.sha256", "url")).toBe(digest);
  expect(() => verifySha256(bytes, checksum, "phishing-links-ACTIVE.txt", "https://raw.githubusercontent.com/Phishing-Database/checksums/master/phishing-links-ACTIVE.txt.sha256", "url")).not.toThrow();
});

test("rejects malformed, wrong-file, non-official, and mismatched checksums", () => {
  const source = "https://raw.githubusercontent.com/Phishing-Database/checksums/master/phishing-links-ACTIVE.txt.sha256";
  expect(() => parseSha256Checksum(new TextEncoder().encode("not-a-checksum"), "phishing-links-ACTIVE.txt", source, "url")).toThrow("format invalid");
  expect(() => parseSha256Checksum(new TextEncoder().encode(`${digest} *phishing-domains-ACTIVE.txt`), "phishing-links-ACTIVE.txt", source, "url")).toThrow("format invalid");
  expect(() => parseSha256Checksum(new TextEncoder().encode(`${digest} *phishing-links-ACTIVE.txt`), "phishing-links-ACTIVE.txt", "https://raw.githubusercontent.com/other/checksums/master/phishing-links-ACTIVE.txt.sha256", "url")).toThrow("not official");
  expect(() => verifySha256(new TextEncoder().encode("different\n"), new TextEncoder().encode(`${digest} *phishing-links-ACTIVE.txt`), "phishing-links-ACTIVE.txt", source, "url")).toThrow("checksum mismatch");
});

test("accepts only finite positive freshness ages", () => {
  expect(validatePhishingMaxAgeHours(6)).toBe(6);
  expect(() => validatePhishingMaxAgeHours(0)).toThrow();
  expect(() => validatePhishingMaxAgeHours(1.5)).toThrow();
  expect(() => validatePhishingMaxAgeHours(Number.POSITIVE_INFINITY)).toThrow();
});

test("rejects an invalid checksum before opening a database connection", async () => {
  const feed = new TextEncoder().encode("https://phish.example/login\n");
  const checksum = new TextEncoder().encode(`${"0".repeat(64)} *phishing-links-ACTIVE.txt\n`);
  const responses = new Map<string, Uint8Array>([
    ["https://phish.co.za/latest/phishing-links-ACTIVE.txt", feed],
    ["https://raw.githubusercontent.com/Phishing-Database/checksums/master/phishing-links-ACTIVE.txt.sha256", checksum],
    ["https://phish.co.za/latest/phishing-domains-ACTIVE.txt", new TextEncoder().encode("phish.example\n")],
    ["https://raw.githubusercontent.com/Phishing-Database/checksums/master/phishing-domains-ACTIVE.txt.sha256", new TextEncoder().encode(`${"0".repeat(64)} *phishing-domains-ACTIVE.txt\n`)]
  ]);
  await expect(import("../src/providers/phishing-database-sync.ts").then(({ syncPhishingDatabase }) => syncPhishingDatabase("postgres://invalid", { fetchBytes: async url => responses.get(url)! }))).rejects.toThrow("checksum mismatch");
});
