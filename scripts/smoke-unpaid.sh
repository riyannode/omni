#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${1:-http://localhost:3000}"

health_status="$(curl -sS -o /tmp/omni-health.json -w '%{http_code}' "$BASE_URL/health")"
[[ "$health_status" == "200" ]] || { echo "expected /health 200, got $health_status"; exit 1; }
grep -q '"status":"healthy"' /tmp/omni-health.json || { echo "unexpected /health response"; exit 1; }

ready_status="$(curl -sS -o /tmp/omni-ready.json -w '%{http_code}' "$BASE_URL/ready")"
[[ "$ready_status" == "200" ]] || { echo "expected /ready 200, got $ready_status"; exit 1; }
grep -q '"status":"ready"' /tmp/omni-ready.json || { echo "unexpected /ready response"; exit 1; }


URL="$BASE_URL/v1/package/risk?ecosystem=npm&name=express&version=5.2.1"
headers="$(mktemp)"
trap 'rm -f "$headers" /tmp/omni-health.json /tmp/omni-ready.json' EXIT
status="$(curl -sS -D "$headers" -o /dev/null -w '%{http_code}' "$URL")"
[[ "$status" == "402" ]] || { echo "expected protected route to return 402, got $status"; exit 1; }
grep -qi '^payment-required:' "$headers" || { echo "missing PAYMENT-REQUIRED header"; exit 1; }
echo "PASS health/readiness routes and unpaid x402 handshake"
