# OMNI agent instructions

Keep changes surgical. Prefer a deep module over many shallow helpers. New abstractions need at least two implemented adapters or a concrete replacement use case. Do not put LLM inference, wallet secrets, OTPs, private keys, or user-controlled shell execution in the synchronous paid request path.

Success criteria: strict types; tests at module interfaces; unpaid protected routes return HTTP 402; paid handlers delegate x402 payment verification/settlement to the official Circle middleware; and endpoint probes reject loopback, link-local, private, and otherwise policy-disallowed targets.

Read `CONTEXT.md` and `docs/adr/` before architecture changes.
