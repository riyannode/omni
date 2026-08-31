# Phishing.Database operational model

OMNI consumes two independent, active-only feeds from the MIT-licensed Phishing.Database project:

- URL indicators: `https://phish.co.za/latest/phishing-links-ACTIVE.txt`
- Hostname indicators: `https://phish.co.za/latest/phishing-domains-ACTIVE.txt`
- SHA-256 checksums: the matching files in `https://raw.githubusercontent.com/Phishing-Database/checksums/master/`

The URL feed never creates hostname indicators. The hostname feed is the only Phishing.Database input that creates hostname indicators. Reconciliation identity is `(source, indicator_type, indicator, threat_type)`, so refreshing one scope cannot retract the other.

## Freshness

`PHISHING_DATABASE_MAX_AGE_HOURS` defaults to 6 and must be an integer from 1 through 720. The default is based on the upstream checksum repository history reviewed on 2026-08-31: consecutive checksum commits observed on 2026-08-23/24 were approximately two hours apart (`Phishing-Database/checksums`, commits titled `Update Checksums [skip ci]`). Six hours permits two missed two-hour refreshes while remaining finite. If the refresh stops, imported rows expire and are ignored by threat lookups.

A successful dual-feed sync computes one expiry timestamp for both scopes and commits both reconciliations in one PostgreSQL transaction. Any download, official-source, checksum, parser, non-empty, or transaction failure leaves the previous snapshot and expiry untouched.

## Sync

```bash
bun run threats:phishing:sync
```

The command downloads both feeds and both official SHA-256 files before opening a database transaction. It hashes raw feed bytes before UTF-8 parsing and rejects MD5/SHA-1 or malformed checksum files. It prints counts and the shared expiry timestamp only; it never prints `DATABASE_URL` or credentials.

The feed is evidence, not a verdict. Public URL evidence is labeled `OMNI threat intelligence`; each matched finding retains its actual stored source.

## Authoritative references

- Feed project: https://github.com/Phishing-Database/Phishing.Database
- Feed project license: https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/LICENSE
- Checksum repository: https://github.com/Phishing-Database/checksums
- Active feed list and checksum links: https://github.com/Phishing-Database/Phishing.Database/blob/master/README.md
