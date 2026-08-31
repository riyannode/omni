# Scale model

The capacity objective is 100k simultaneous client requests across the **service fleet**. This repository does not claim verified 100k paid-settlement throughput; that must be established by load testing the deployed fleet, Circle Gateway behavior, network limits, and upstream-provider quotas.

## Request path rules

1. Admission control runs before payment middleware, so an overloaded replica does not intentionally accept more paid work.
2. No LLM inference in the synchronous paid request path.
3. Cache frequently requested evidence in Valkey; duplicate cache misses inside one replica reuse one in-flight loader per cache key.
4. One `UpstreamHttp` deep module owns the shared `UpstreamAdmission` primitive. Existing HTTP calls, URL-risk DNS/CNAME resolution, and pinned HTTPS/TLS operations acquire that same configured capacity; requests beyond the queue limit are rejected. Dependency batches are also evaluated in waves of 16.
5. PostgreSQL stores historical observations and is not required on every paid response. `/ready` remains HTTP 200 when only history storage is unavailable because core paid assessments can still run; the response reports `dependencies.historyStore: degraded` so operators can alert on the loss of history persistence without removing an otherwise serving replica.
6. Circle marketplace crawling runs in a separate worker.
7. Upstream calls have strict timeouts and produce explicit source errors rather than unbounded waits.

## Deployment shape

Start load tests around 250–1000 active requests per replica depending on CPU/memory/network and raise only from measured data. Scale replicas horizontally behind an L7 load balancer. `MAX_IN_FLIGHT=512` is the shipped protective ceiling, not a recommended steady-state concurrency.

For a 100k-connection target, size replicas from measured per-replica concurrency and p95/p99 latency, retain explicit headroom, and validate Circle Gateway seller-settlement throughput with Circle. Gateway is an external dependency and can become the dominant bottleneck regardless of OMNI application performance.

## Load-test gates before claiming capacity

- 402-only path: 100k open connections fleet-wide, p99 response < 500ms, no 5xx from OMNI.
- paid path: non-mocked Circle testnet settlement; ramp 100 → 1k → 10k concurrent requests only while Circle testnet and deployment limits permit.
- hot cached package assessment: target application p99 < 250ms, measured separately from external payment-settlement latency.
- cold upstream path: enforce finite queue limits and request timeouts; reject excess work instead of growing an unbounded queue.

## Kubernetes deployment baseline

`deploy/kubernetes.yaml` allows up to 300 API replicas. That ceiling is capacity headroom, not a throughput claim. Size replicas from measured paid-path latency and Circle Gateway throughput. PostgreSQL and Valkey should be external HA services in production.

Run the free 402 path load probe with `CONCURRENCY=100 REQUESTS=10000 bun run load:unpaid`, then perform paid testnet ramps separately with real Circle settlement.
