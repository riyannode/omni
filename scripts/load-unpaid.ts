export {};

const base = process.env.OMNI_BASE_URL ?? "http://localhost:3000";
const concurrency = Number(process.env.CONCURRENCY ?? "100");
const requests = Number(process.env.REQUESTS ?? "1000");
const url = `${base}/v1/package/risk?ecosystem=npm&name=express&version=5.2.1`;

let cursor = 0;
let passed = 0;
let failed = 0;
const latencies: number[] = [];

async function worker() {
  while (true) {
    const id = cursor++;
    if (id >= requests) return;
    const started = performance.now();
    try {
      const response = await fetch(url);
      latencies.push(performance.now() - started);
      if (response.status === 402 && response.headers.has("payment-required")) passed += 1;
      else failed += 1;
      await response.body?.cancel();
    } catch {
      failed += 1;
    }
  }
}

await Promise.all(Array.from({ length: concurrency }, () => worker()));
latencies.sort((a, b) => a - b);
const percentile = (p: number) => latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * p))] ?? 0;
console.log(JSON.stringify({ requests, concurrency, passed, failed, p50Ms: Math.round(percentile(0.5)), p95Ms: Math.round(percentile(0.95)), p99Ms: Math.round(percentile(0.99)) }));
if (failed > 0) process.exitCode = 1;
