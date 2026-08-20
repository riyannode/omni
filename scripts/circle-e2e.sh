#!/usr/bin/env bash
set -euo pipefail

: "${OMNI_URL:?set OMNI_URL to a public paid OMNI endpoint}"
: "${BUYER_ADDRESS:?set BUYER_ADDRESS to the Circle agent wallet address}"
: "${CHAIN:?set CHAIN to an accepted chain from circle services inspect}"

MAX_AMOUNT="${MAX_AMOUNT:-0.005}"

circle services inspect "$OMNI_URL" -X GET --output json

circle services pay "$OMNI_URL" \
  -X GET \
  --address "$BUYER_ADDRESS" \
  --chain "$CHAIN" \
  --max-amount "$MAX_AMOUNT" \
  --estimate \
  --output json

if [[ "${RUN_PAID:-0}" == "1" ]]; then
  circle services pay "$OMNI_URL" \
    -X GET \
    --address "$BUYER_ADDRESS" \
    --chain "$CHAIN" \
    --max-amount "$MAX_AMOUNT" \
    --output json
else
  printf '\nEstimate only. Set RUN_PAID=1 after reviewing it to execute the paid request.\n'
fi
