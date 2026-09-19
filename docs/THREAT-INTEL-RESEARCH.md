# OMNI threat-intelligence source research

Status: evidence-first review; no runtime integration approved.

Research date: 2026-09-02 UTC.

Scope: `riyannode/omni` only. This note does not grant a source any rights; source terms must be re-reviewed before production use.

## Decision

**NO SAFE FREE SOURCE FOUND.**

Keep Threat Intelligence `UNAVAILABLE` when no licensed feed is loaded. Do not turn an unavailable source into `ABSENT`, and do not use an unchecked mirror or a source with unclear redistribution rights in the paid API.

No production code, database migration, OpenAPI contract, frontend file, payment behavior, deployment, or paid request was changed for this review.

## Current OMNI semantics

- Exact package intelligence is a package-coordinate or package-artifact/hash observation.
- URL/domain intelligence is infrastructure evidence. A URL/domain match against a package homepage, repository URL, tarball URL, or publisher host must not be represented as an exact `ecosystem:name@version` match.
- PR #24 already consumes OSV `MAL-*` observations and preserves their OpenSSF malicious-packages origins. Adding OpenSSF malicious-packages directly would duplicate the same underlying observation.
- `ThreatIntelStore` is already vendor-neutral. Current package and endpoint lookups return `checked: false` when no licensed feed is loaded.

## PR #23 Phishing.Database live recheck

### Read-only results

| Artifact | Status | Bytes | Raw SHA-256 / checksum body |
|---|---:|---:|---|
| `https://phish.co.za/latest/phishing-links-ACTIVE.txt` | 503 | 107 | `839488eb...7834d2d79` (HTML error) |
| `https://phish.co.za/latest/phishing-domains-ACTIVE.txt` | 403 | 93 | `0d3e98ca...283e8b34` (HTML error) |
| URL checksum on GitHub | 200 | 92 | claims `bf2c0c1c...11473cb0` |
| Hostname checksum on GitHub | 200 | 94 | claims `5c982897...8a373df` |
| First-party raw GitHub URL feed | 200 | 65,823,890 | `be4a179b...40a7a67c6` |
| First-party raw GitHub hostname feed | 200 | 11,015,665 | `5c982897...8a373df` |

The HTTP error bodies are respectively `No server is available to handle this request` and `Request forbidden by administrative rules`. The same results were returned for GET and HEAD with `curl/8.0`, `Mozilla/5.0`, and `OMNI/0.2 threat-intel-sync`. This proves the current behavior is not explained by the User-Agent alone. The exact IP/CDN policy cause is not proven from the public response, so it must not be described as a confirmed IP block or permanent deprecation.

### GitHub provenance and integrity

First-party repository metadata:

- `Phishing-Database/Phishing.Database` master: commit `81e4c4db830766896c59c82f4488573ee0810626`, `2026-08-23T07:30:29Z`.
- `Phishing-Database/checksums` master: commit `72f97884c46327188b97530ca96a48071463e9c8`, `2026-08-24T01:30:26Z`.
- The README links the phish.co.za files as **Official Source** and links the checksums repository. It does not establish that raw GitHub artifacts are the supported production distribution path.
- Raw GitHub feed responses exposed ETags but no trustworthy common snapshot identifier or `Last-Modified` value tying the feed and checksum together.

The URL mismatch is reproducible without normalization:

- Current raw GitHub URL bytes: `be4a179b3ac92b7135595b459c2c9867fe681c12209489dd99517db8407a67c6`.
- Official URL checksum body claims: `bf2c0c1c663fe27820d9dc296a2ca8f544fca21e6fa9d1cbe5d3d04211473cb0`.
- The raw URL artifact is byte-for-byte identical to the raw artifact at source commit `06f6e92c1085cc5202f2d5b7018bd2aabed1f95b`, so this is not a transient CDN read difference in the tested path.
- The top-level URL file history reports its latest update as `bd042bbfc9c8f902c3a398d963c4cd3ba17b6e54` on `2025-12-22T20:39:14Z`; the current top-level blob is unchanged from that history tip.
- The active URL checksum was changed in checksum commit `35cb988811587e6a9f1f9395df51655c3a47ed3d` on `2026-08-23T01:30:40Z`.
- The hostname top-level feed was changed in source commit `81e4c4...` at `07:30:29Z`; the active hostname checksum was changed in checksum commit `59c0503ed75b552086ee76ebcacd89a62f338390` at `07:30:39Z`, and its raw bytes match.

The proven explanation is **non-atomic, independently published artifacts**: the URL root feed and URL checksum do not represent the same byte generation, while the hostname pair currently does. The directory manifests also expose sharded active files, but upstream does not provide a public contract proving that the current top-level URL, shard assembly, and checksum are one immutable snapshot. Possible causes such as stale mirror output, different generation pipelines, or publication timing remain hypotheses; none justifies bypassing the checksum.

### PR #23 safety conclusion

PR #23's current importer correctly rejects the URL mismatch and requires both URL and hostname scopes to validate before a shared transaction. Do not replace `phish.co.za` with raw GitHub, do not accept the mismatching URL checksum, and do not import only the hostname side as an atomic dual-feed snapshot.

**Current option ranking:**

1. **Option D — selected now:** keep the feed disabled and report URL threat intelligence as partial/unavailable.
2. **Option A — conditional future option:** upstream must repair the official distribution and publish a verifiable same-generation URL/hostname/checksum contract. Re-run the exact-byte checks before enabling.
3. **Option B — not currently available:** no independently licensed replacement passed the rights gate.
4. **Option C — not justified:** no replacement was demonstrated to be both more reliable and legally redistributable for paid OMNI evidence.

## Candidate acceptance matrix

`UNCLEAR` is a hold/reject under OMNI's rule. `Data license` is separate from software/repository license.

| Source | Data / subject | Role | Update / auth / free limit | Automation | Commercial | Redistribution / cache / derived decisions | Attribution / integrity | Provenance / reliability | Package relevance | URL relevance | Duplication | Recommendation |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Phishing.Database | Verified/active phishing URLs, domains, also IPs in project | Primary project, with first-party GitHub artifacts and checksum repo | README says files updated regularly; current live official paths failed; no auth documented for phish.co.za | Intended for feed consumers, but current supported path is not reliable | UNCLEAR for data use; project MIT repository license is not a clear data-rights contract | UNCLEAR for paid API evidence, cache, and derived output; no same-generation integrity for URL feed | Project attribution required by MIT if applicable; SHA-256 files exist but URL mismatch is fatal | Community/Safekeepers plus PyFunceble; current URL artifact stale/desynchronized | URL/domain only; not exact package | Strong semantic fit when verified | Not a mirror of OSV, but unsafe snapshot | HOLD operationally and legally; do not enable |
| PhishTank | Verified-online phishing URL records; exact URL, phish ID, verification/online timestamps | Primary Cisco/Talos-operated service | Official developer page says downloadable feeds are hourly; app key for automated fetches; without key only a few downloads/day; API limits return HTTP 509; lookup API requires app key for useful limits | API automation expressly described; descriptive User-Agent required | FAQ currently says “Yes, it is OK” for commercial and non-commercial API use | Current terms page sends users to Cisco General Terms; permissive commercial/data and CC BY-SA language is explicitly under **Archived Terms**. Current General Terms restrict transfer/sale/monetization of Cisco Offers and do not give a clear right to redistribute PhishTank evidence from a paid third-party API. Cache/storage and derived-output rights are not explicit | Attribution should include PhishTank/Cisco and record references; no checksum/signature contract for downloaded feed; ETag available for HEAD | Community-verified, hourly feed, but current terms and operational limits need direct written clarification | Exact URL only; no package coordinate/hash | Strong URL fit | Independent from OSV MAL | HOLD pending current written permission covering paid use, cache, derived decisions, and redistribution |
| The Block List Project | Domain-only phishing/malware/scam lists | Aggregator | README says daily/community updates; GitHub commit can pin a snapshot; no API auth | Automated upstream monitoring and normalization documented | NO for the current aggregate: its transitive malware chain includes Zach's list, which includes Phishing Army CC BY-NC 4.0 | Top-level LICENSE is Unlicense, but no per-record source-rights manifest; cache/paid redistribution/derived decisions are not established | Attribution not defined per source; immutable commit is available | Daily pipeline, but source provenance is incomplete; `phishing` currently has no declared upstream sources in `config/lists.yml` | Domain only; cannot prove package coordinate | URL/domain infrastructure only | Aggregates community lists; may overlap other feeds | REJECT for paid OMNI evidence |
| CERT Polska Warning List | Active phishing/dangerous domains; Polish-targeted domain semantics | Primary national CERT/NASK list | v2 TXT/CSV/JSON/XML; page says update every 5 minutes; no auth; live feed 200 with Last-Modified/ETag; six-month retention | Official page explicitly supports automated integrators | UNCLEAR | No explicit current commercial-use, cache, or redistribution grant on page/spec; helper repo BSD license is software-only and not a data license | Feed has ETag/Last-Modified; attribution/record-link expectations are documented, but redistribution rights are not | Strong authority and current availability; geographic/Polish-targeting bias | Domain only; not exact package | Strong domain fit, not exact URL unless caller does hostname mapping | Independent of OSV; possible overlap with phishing feeds unknown | HOLD; do not integrate without explicit data permission |
| URLhaus | Malware-distribution URLs and derived hostnames | Primary abuse.ch/Spamhaus platform | Community API requires Auth-Key; dumps/RPZ/rules generated as often as 5 min; free tier subject to fair use | API automation documented, but commercial/high-volume use directed to enhanced paid API | NO for free community path: current abuse.ch Terms limit authenticated free access to not-for-profit; commercial/for-profit may require paid subscription | Paid API/data rights are separate; free path does not establish OMNI cache/redistribution rights | Source attribution available; API/auth and freshness are documented | Strong malware URL collection but not phishing; availability subject to fair-use access | No package-coordinate semantics; payload/hash data could be artifact context but not npm package identity | URL/domain infrastructure fit for malware, not phishing-only | May be reused by community aggregators | REJECT free tier |
| ThreatFox | Malware IOC: IP/domain/URL/hash; explicitly excludes phishing | Primary abuse.ch/Spamhaus platform | Auth-Key required; API/export; IOCs older than six months expire from API/export | API automation documented | NO/UNCLEAR for free commercial use under same current abuse.ch not-for-profit terms | No free paid-API redistribution/cache grant | Source/API references; no accepted OMNI license contract | Human/trusted reporter workflow, six-month expiry; malware-only semantics | Hash/package artifact possible only as malware IOC, not package coordinate | URL/domain fit for malware, not phishing | Could overlap abuse.ch sources; not OSV MAL by default | REJECT free tier and semantically reject phishing use |
| MalwareBazaar | Malware sample/hash metadata | Primary abuse.ch/Spamhaus platform | Auth-Key required; community API; download/query limits | API automation documented | NO/UNCLEAR for free commercial use under current abuse.ch Terms | No free commercial paid-product redistribution rights | Source references; sample API has operational limits | Useful hash source, but not package-coordinate intelligence; samples carry their own risks | Potential artifact/hash only; not exact npm coordinate | Not URL-risk source | Not OSV MAL by default, but not relevant to package coordinate | REJECT free tier |
| OpenPhish Community | Phishing URLs | Primary commercial provider | Community text feed, 12-hour update; free; no key shown | Terms allow only permitted interface/use | NO: current terms prohibit commercial purposes including threat intelligence, automation, product development, customer protection | NO: terms prohibit making information available to third parties without written permission | Attribution required for academic program; no commercial rights | Feed is current but legal gate fails | URL only | URL fit | Independent but unusable | REJECT |
| VirusTotal Public API | Multi-engine URL/file/domain/hash reports | Aggregator | Public API free; official docs say default max four requests/minute; public key/account | API exists | NO: official API overview says public API must not be used in commercial products/services | Redistribution/cache/derived paid API use therefore unavailable on public tier | VT attribution does not cure commercial restriction | Broad aggregator, not independent primary evidence | Hash/package possible only if exact artifact supplied, but public tier barred | URL/domain fit but barred | Aggregates many sources; double-counting risk | REJECT |
| Google Web Risk / Safe Browsing | Google unsafe URL response | Primary/aggregated Google result | API-specific quotas and freshness constraints | API | Not accepted for OMNI; current terms restrict commercial Safe Browsing use and route commercial users to Web Risk | Returned information is not a redistributable OMNI evidence source; cannot turn unavailable into absent | Google attribution rules are specific and do not grant redistribution | Strong provider but incompatible with OMNI contract | No package semantics | URL fit but explicitly excluded | Aggregator/opaque | REJECT |
| AlienVault OTX | Community pulses and indicator reputation | Aggregator/community platform | API key; DirectConnect/TAXII docs; no explicit current paid redistribution grant found | Automation supported | UNCLEAR | Redistribution/cache/derived-decision rights UNCLEAR; ambiguity is a hold | Source/pulse attribution possible; integrity not a source-native signed snapshot | Community aggregation and variable pulse provenance | Hash/package coordinate not established | URL/domain/IP fit | Aggregator and potential duplicate feeds | HOLD/REJECT until written terms |
| AbuseIPDB | Reported abusive IPs | Aggregator/community IP reputation | API key; official docs say free accounts 1,000 checks/reports/day | Automation supported | UNCLEAR for paid OMNI evidence | Official docs do not establish redistribution/cache/derived-decision rights | No source snapshot checksum/signature contract | IP-only, report-quality variability | Not exact package; only possible publisher-IP infrastructure | Only IP infrastructure, not URL/hostname in current OMNI store | Aggregated community reports | HOLD; not a package/URL source for this task |
| PhishStats | Verified phishing URLs, domains, IPs and score | Primary independent project | Anonymous 50/day; free key 150/day; 90-minute updates; full download paid | API automation allowed within quotas | UNCLEAR for paid use; Terms allow limited access for security research but do not grant paid API redistribution | Explicitly prohibits sharing/reselling/redistributing raw data without written permission; no OMNI evidence redistribution right | API records have IDs/timestamps; no signed bulk snapshot contract | Active and documented, but legal gate fails | URL/domain only | Strong URL fit | Claims unique community contributions, but no OMNI license | REJECT without written permission |
| CIRCL hashlookup | Known-file hash context from NSRL/OS distributions and other databases | Aggregator/public service | Free best-effort API; offline Bloom filter | API and offline use documented | Data terms vary by included dataset | CC-BY is shown by the API, but included data rights need source-by-source review | No malicious verdict; API metadata | Useful known-file context, not malicious intelligence | Not exact malicious package evidence | Not URL risk | No OSV MAL duplication, but wrong semantic class | REJECT for threat-positive coverage |
| Spamhaus DROP | Malicious/hijacked IP netblocks | Primary Spamhaus dataset | Free JSON; daily; no more than hourly fetch; product credit/date required | Automated use described | YES for any business type according to DROP page | Product-use permission and attribution are explicit, but raw evidence redistribution/paid API response rights are not fully specified | Attribution/date/copyright; JSON has timestamps; no URL/hostname | High-confidence IP infrastructure, but wrong indicator type for current store | Only publisher-IP infrastructure if model extended | IP-only URL attribution, not current URL/hostname | Independent but not package exact | HOLD for a separate IP-infrastructure product; not this scope |
| OpenSSF malicious-packages | Malicious package reports in OSV format | Primary dataset, but already surfaced through OSV | Apache-2.0 repository; mutable GitHub branch unless pinned | Repository automation possible | License permits code/data work as applicable, but this is already OSV-backed in OMNI | Direct addition would duplicate OSV `MAL-*` observations and can double-count | Commit pinning possible; OMNI already keeps OSV origins | Strong exact-package semantics, but not independent from existing OSV path | Exact package | Not URL risk | **Duplicate of existing OSV MAL path** | REJECT as a second adapter |

## License and semantic verdicts

### PhishTank

The official API page documents automated API use, app keys, rate-limit headers, and a recommendation to download a local database for many lookups. The current FAQ says commercial and non-commercial API use is okay. However, the current Terms page explicitly directs users to current Cisco terms and labels the older permissive data/commercial and CC BY-SA provisions as archived. The current Cisco General Terms grant direct-use rights and prohibit transfer/sale/monetization of Cisco Offers, without a PhishTank-specific paid redistribution grant. The exact OMNI use—store/cache, deterministic decisions, and return source-attributed evidence to paying API users—is therefore not defensible from current public terms alone. Hold for written permission.

### The Block List Project

The repository LICENSE is Unlicense and the README describes automated upstream monitoring, but the current configuration has no upstream sources for the phishing list and only source URLs plus a `trusted` flag for selected malware/scam lists. More importantly, Zach's current first-party `blocklists.conf` includes `https://phishing.army/download/phishing_army_blocklist_extended.txt`; that feed declares **CC BY-NC 4.0** in its own header. This makes the current aggregate unsuitable for commercial OMNI use even before considering its incomplete per-entry provenance. The aggregator does not attach a per-entry license/provenance chain. A repository/software license cannot be treated as a license for every upstream data record. Reject for paid OMNI evidence until complete source-level rights and provenance are published.

### CERT Polska

The official Warning List page and v2 specification define domain semantics, six-month active retention, update behavior, feed formats, and integration/attribution behavior. The live feed is reliable in this review. Neither the authoritative page nor the linked specification provides an explicit commercial redistribution/caching grant. The BSD license on `warning-list-tools` licenses helper software, not the feed data. Hold.

## Package threat-intelligence gap

Current exact-package coverage is:

- OSV vulnerability query and OSV `MAL-*` observation path.
- CISA KEV correlation for CVE-bearing OSV findings.
- npm registry metadata for npm packages.
- Generic `ThreatIntelStore.lookupPackage`, currently unavailable unless an operator imports a licensed package indicator feed.

No independently licensed free exact-package feed passed all gates. OpenSSF malicious-packages is already represented as OSV `MAL-*` origins and must not be added again. Generic URL/domain intelligence cannot be counted as exact package coverage.

A future package-attributed-infrastructure class could separately inspect package metadata URLs (repository/homepage/tarball host) against a licensed URL/domain source. It must use a distinct evidence class and denominator, retain the matched URL/domain, and state that the package was not directly evaluated. No such source or implementation is approved by this review.

## Minimal architecture if a source later passes

1. Keep `ThreatIntelStore` as the vendor-neutral external interface.
2. Add one source adapter per genuinely independent source, with an explicit scope declaration: `package`, `package_artifact`, `url`, `hostname`, or `ip`.
3. Maintain a source-rights manifest outside request input containing the current terms URL, data license, commercial/paid-use permission, cache/storage permission, derived-decision permission, redistribution permission, attribution text, and review date.
4. For bulk sources, stage and validate the complete source snapshot before a transaction. Record source version, retrieval time, expiry, ETag/Last-Modified, immutable commit or source checksum where available, and raw-byte hash.
5. Reject malformed records, empty destructive snapshots, stale snapshots, incomplete dual scopes, and mismatched checksums. Reconcile atomically per source contract; never mix generations.
6. Keep exact package findings and package-attributed infrastructure findings separate in types, coverage, evidence kind, signals, and source attribution.
7. Preserve `checked: false`/`UNAVAILABLE` and source errors when an adapter is unavailable. A successful negative lookup alone may be `ABSENT`; an unavailable adapter may not.

## Files that would change after approval

None in this review. A future Phishing.Database repair would be limited to the PR #23 adapter/sync tests and source-specific configuration only after upstream integrity is repaired. A future package source would use a separate adapter and evidence class; it must not be coupled to URL-risk retrieval.

## DB / migration impact

None now. The existing `threat_indicators` table is vendor-neutral but does not retain a source snapshot/generation identifier, raw-byte hash, ETag, immutable commit, or rights-review record. A production bulk-feed implementation would likely need a source snapshot ledger and staging metadata migration rather than overloading `source_reference`.

## OpenAPI impact

None now. Existing public semantics already expose source-attributed evidence and `sourceErrors`; no new evidence class is justified without an accepted source and schema design.

## Focused future test plan

If a source is later accepted, test through module interfaces:

- positive match; valid negative lookup; provider unavailable; malformed response; stale snapshot; empty snapshot;
- checksum/integrity mismatch; partial dual-feed state; source attribution; source-specific freshness;
- exact package versus package-attributed URL/domain applicability;
- unrelated indicators cannot increase package coverage;
- duplicate evidence does not increase logical risk twice;
- unavailable never becomes `ABSENT`;
- old persisted evidence remains version-safe; deterministic replay;
- destructive reconciliation is not performed on incomplete or unverified snapshots;
- raw bytes are hashed before parsing and no line-ending normalization is performed unless the upstream contract says so.

## Primary sources

- OMNI PR #23: https://github.com/riyannode/omni/pull/23
- OMNI PR #24: https://github.com/riyannode/omni/pull/24
- Discovery index (candidate discovery only): https://github.com/public-apis/public-apis
- Phishing.Database README/LICENSE: https://github.com/Phishing-Database/Phishing.Database
- Phishing.Database source repository: https://github.com/Phishing-Database/phishing
- Phishing.Database checksums: https://github.com/Phishing-Database/checksums
- PhishTank API/developer/FAQ/current terms: https://phishtank.org/api_info.php, https://phishtank.org/developer_info.php, https://phishtank.org/faq.php, https://phishtank.org/terms.php
- Cisco current General Terms: https://www.cisco.com/c/en/us/about/legal/cloud-and-software/end_user_license_agreement.html
- The Block List Project: https://github.com/blocklistproject/Lists, https://raw.githubusercontent.com/blocklistproject/Lists/main/config/lists.yml, https://raw.githubusercontent.com/blocklistproject/Lists/main/UPSTREAM_MONITORING.md, https://raw.githubusercontent.com/blocklistproject/Lists/main/LICENSE
- BLP transitive source evidence: https://raw.githubusercontent.com/zachlagden/Pi-hole-Optimized-Blocklists/main/blocklists.conf, https://phishing.army/download/phishing_army_blocklist.txt
- CERT Polska Warning List/specification: https://cert.pl/en/warning-list, https://hole.cert.pl/schema/certpl_lista_ostrzezen_api_v2.pdf, https://hole.cert.pl/domains/v2/domains.txt
- URLhaus/ThreatFox/MalwareBazaar/abuse.ch terms: https://urlhaus.abuse.ch/api, https://threatfox.abuse.ch/faq, https://bazaar.abuse.ch/api, https://abuse.ch/terms-of-use/
- OpenPhish terms/feeds: https://www.openphish.com/terms.html, https://www.openphish.com/phishing_feeds.html
- VirusTotal API overview: https://docs.virustotal.com/docs/api-overview
- Google Safe Browsing terms: https://developers.google.com/safe-browsing/terms
- PhishStats terms/docs: https://phishstats.info/terms, https://phishstats.info/api-docs, https://phishstats.info/pricing
- CIRCL hashlookup: https://www.circl.lu/services/hashlookup/
- Spamhaus DROP: https://www.spamhaus.org/drop/
- OpenSSF malicious packages: https://github.com/ossf/malicious-packages
