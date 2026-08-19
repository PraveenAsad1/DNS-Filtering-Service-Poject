# DNS Filtering Proxy

A DNS filtering service that intercepts UDP DNS queries, checks them against a blocklist, and applies heuristic risk scoring to unknown domains before deciding whether to forward or block them.

Two-service polyglot system, fully containerized, with unit tests and measured performance benchmarks.

---

## What This Is

1. **Java Spring Boot DNS proxy** — listens for raw UDP DNS queries, parses them with `dnsjava`, checks a blocklist, and either forwards clean queries upstream or returns a sinkholed (blocked) response. Logs every query to SQLite.
2. **Python FastAPI heuristic scoring service** — for domains not on the static blocklist, scores them using deterministic heuristics (string length, hyphen density, digit ratio, Shannon entropy, suspicious TLDs) and returns a threat score between 0 and 1.
3. **Live dashboard** — real-time stats, a score-timeline chart with the block threshold visualized, and a query log, served directly by the Java backend.

**This is heuristic scoring, not machine learning.** There is no trained model, no labeled dataset, no learning involved — it's a hand-written scoring formula based on known suspicious-domain characteristics. This distinction is intentional: calling it "ML" would be inaccurate.

---

## Architecture

```
Client (dig / any DNS resolver)
        │  UDP query, port 1053
        ▼
┌─────────────────────────────────┐
│  Java Spring Boot DNS Proxy      │
│  - DatagramSocket UDP listener   │
│  - dnsjava wire-format parsing   │
│  - Static blocklist check        │
│  - Sinkhole response builder     │
│  - SQLite query logging (WAL)    │
│  - REST API + live dashboard     │
└───────────────┬───────────────────┘
                │  HTTP GET /analyze?domain=...  (unknown domains only)
                ▼
┌─────────────────────────────────┐
│  Python FastAPI Scoring Service  │
│  - Shannon entropy               │
│  - Length / hyphen / digit ratio │
│  - Suspicious TLD check          │
│  - Returns threat_score (0-1)    │
└─────────────────────────────────┘
```

Both services run in separate Docker containers, networked together via Docker Compose. The Java service resolves the Python service by container name (`python-ml`), not `localhost` — configured via an environment-variable override so the same build works both locally and containerized.

---

## Tech Stack

- **Proxy / Backend:** Java 17, Spring Boot 3.3.4, Gradle, `dnsjava`, Java `HttpClient`, Spring Data JPA
- **Persistence:** SQLite (WAL mode, tuned after benchmarking revealed write contention under concurrent load)
- **Scoring Service:** Python 3, FastAPI, Uvicorn
- **Frontend:** Vanilla HTML/CSS/JS, Canvas API for the live score chart — no framework, no build step
- **Containerization:** Docker, Docker Compose, multi-stage build for the Java image
- **Testing:** JUnit 5 (9 tests, Java), pytest (10 tests, Python)
- **Config:** Externalized via `application.yml` and environment variables — no hardcoded URLs or thresholds

---

## Verified, End to End

- ✅ UDP listener on port 1053, wire-format parsing, upstream forwarding to `8.8.8.8`
- ✅ Static blocklist with sinkhole response (`0.0.0.0`)
- ✅ Java → Python HTTP integration for heuristic scoring, with graceful fallback if the scoring service is unreachable
- ✅ SQLite persistence — queries survive a full restart
- ✅ REST API (`/api/stats`, `/api/queries`) and live-updating dashboard
- ✅ Full stack containerized and tested via Docker Compose, including container-to-container networking
- ✅ 19 unit tests across both services (Java: parsing, blocklist matching, threshold logic, response construction; Python: entropy calculation, scoring heuristics, boundary cases)
- ✅ Load-tested with a custom benchmarking tool

## Benchmark Results

Measured with a dedicated load-testing script (`benchmark/benchmark.py`, using `dnspython` to fire real concurrent DNS queries), 200 requests at 20 concurrent workers, realistic mixed traffic (clean/blocklisted/heuristic-triggering domains):

| Metric | Result |
|---|---|
| Throughput | 61.5 queries/sec |
| Median latency (p50) | 33.20 ms |
| p95 latency | 169.89 ms |
| p99 latency | 214.02 ms |
| Success rate | 99% (198/200) |

**Note on methodology:** initial benchmarking (blocklist-only path, isolating out network/scoring-service variance) revealed SQLite write contention under concurrent load — p99 latency around 1.1 seconds despite a reasonable median, the classic signature of lock contention rather than raw compute cost. Enabling SQLite's WAL (Write-Ahead Logging) mode improved throughput by ~50% and cut p99 latency by ~44% on the same isolated benchmark. The numbers above reflect the post-fix, mixed-traffic state.

---

## Running It Locally

**Via Docker Compose (recommended):**
```bash
docker-compose up --build
```

**Or run each service manually:**
```bash
# Terminal 1 — Python scoring service
cd python-ml
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8001 --reload

# Terminal 2 — Java DNS proxy
./gradlew bootRun
```

**Test it:**
```bash
dig @127.0.0.1 -p 1053 google.com          # clean domain, forwards normally
dig @127.0.0.1 -p 1053 badguy.com          # hardcoded blocklist, sinkholed
dig @127.0.0.1 -p 1053 <suspicious-domain> # scored by Python heuristic service
```

**Dashboard:** `http://localhost:8080`

**Run tests:**
```bash
./gradlew test                              # Java: 9 tests
cd python-ml && python -m pytest -v         # Python: 10 tests
```

**Run the benchmark:**
```bash
cd benchmark
source venv/bin/activate
python benchmark.py --requests 200 --concurrency 20 --mode mixed
```

---

## Design Notes / Known Decisions

- **Separate sockets for listening vs. upstream forwarding** — UDP is connectionless, so a single socket's `receive()` can't distinguish an upstream reply from a new client query, and would serialize all traffic while waiting on a response.
- **Configurable threat threshold and scoring-service URL** (via `application.yml` / environment variables), not hardcoded — supports both local development and containerized deployment without code changes.
- **Graceful degradation on scoring-service failure** — if Python is unreachable, Java returns a neutral fallback score rather than crashing the DNS proxy. A scoring sidecar outage should degrade, not take down DNS resolution.
- **Package-private methods in `DNSServer` for testability** — pure decision logic (domain cleaning, blocklist checks, response construction) is separated from I/O (socket operations), so it can be unit tested directly without spinning up real sockets.
- **SQLite WAL mode** — a targeted fix applied after benchmarking identified write contention as the actual bottleneck under concurrent load, not guessed at upfront.

## Real-World Evaluation

Two separate evaluations were run against real published threat intelligence, using increasingly rigorous methodology.

### Evaluation 1: Full feed, mixed layers

100 sampled active malicious domains from [URLhaus](https://urlhaus.abuse.ch/) and 100 sampled domains from the Cisco Umbrella top-1M popularity list, tested against the system as a whole (blocklist + typosquat + heuristic).

| Metric | Result |
|---|---|
| Detection rate | 0% (before live blocklist ingestion was added) |
| False positive rate | 0% |

This result led directly to adding **live blocklist ingestion** (the app now fetches the current URLhaus feed at startup, replacing a 3-domain hardcoded list) and **typosquat detection** (Levenshtein distance against a curated set of high-value brand domains) as two additional detection layers — see Design Notes below.

### Evaluation 2: Held-out test, pattern-matching layers only

A blocklist is a lookup table — anything in it will always be "detected," which isn't a meaningful test of the system's ability to catch **novel** threats. To measure that honestly, a fresh URLhaus snapshot was split 70/30: the 70% split was ingested into the blocklist (simulating "known threats"), and the **30% held-out split was never ingested** and used only for testing. Any detection on the held-out set is attributable specifically to the typosquat or heuristic layers, not blocklist lookup.

| Metric | Result |
|---|---|
| Detection rate (held-out, unseen domains) | 0% (0/107 tested) |
| False positive rate (real popular domains) | 1% (1/99 tested) |

**Analysis:** the 0% held-out detection rate confirms the structural finding from Evaluation 1 with a rigorous methodology: pattern-based detection (whether entropy-based DGA detection or typosquat distance against a small brand list) only catches domains matching its specific target pattern. Real URLhaus domains are overwhelmingly compromised legitimate sites or deliberately unremarkable registrations — neither DGA-random nor near-misses of the 10 brands in the typosquat list. This is the well-documented structural ceiling of signature/pattern-based detection generally, not a defect specific to this implementation; it's the reason the security industry has moved toward live reputation feeds and behavioral signals as primary defenses, with pattern heuristics as a supplementary layer.

The single false positive was `ves-io-<uuid>.ac.vh.ves.io` — a legitimate F5/Volterra cloud-routing subdomain flagged by the entropy heuristic. This illustrates a real, known tension in entropy-based detection: legitimate CDN/cloud infrastructure often uses randomized UUID subdomains for edge routing, which are structurally indistinguishable from DGA-style randomness under pure entropy analysis.

**What closes this gap in a production system:** the live blocklist ingestion already closes it for *known* threats (any URLhaus-listed domain is now caught deterministically). For *novel* threats, meaningful improvement would require domain reputation feeds, WHOIS/registration-age signals, hosting infrastructure reputation, and likely a trained classifier over these richer features — the point at which "heuristic scoring" would become legitimate ML with labeled data and measurable precision/recall.

## Known Limitations

- Blocklist now ingests the live URLhaus feed at startup (~250-370 domains typically), with a small hardcoded fallback list if the fetch fails — still a single-source, startup-time snapshot rather than a continuously refreshing feed
- Typosquat detection covers only 10 curated high-value brand domains — easily expanded, but demonstrates the technique rather than providing comprehensive brand coverage
- Held-out evaluation showed 0% detection on genuinely novel (unseen) malicious domains via the typosquat/heuristic layers — see Real-World Evaluation above for full analysis
- Entropy-based heuristic scoring can false-positive on legitimate infrastructure using randomized subdomains (e.g. CDN edge routing)
- No authentication on the dashboard or REST endpoints
- SQLite is appropriate for this scale; a production system with real concurrent load would likely move to Postgres
- Heuristic scoring is intentionally simple and will have false positives/negatives — it's a demonstration of the pattern, not a production-grade threat detection engine