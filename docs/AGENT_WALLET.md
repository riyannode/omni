# Circle CLI agent wallet for OMNI buyer tests

The buyer agent wallet is separate from the OMNI seller process. OMNI only needs the seller payout address. Buyer/test payments are signed through Circle CLI; no buyer private key belongs in the OMNI server.

## Mainnet login and wallet (production)

```bash
npm install -g @circle-fin/cli@latest
circle --version

# Interactive mainnet login. Mainnet and testnet sessions are separate.
circle wallet login <email>

# Login provisions agent wallets automatically; inspect before creating anything else.
circle wallet list --chain ARC --type agent --output json
```

For a non-interactive agent flow:

```bash
circle wallet login --init
circle wallet login --request <REQUEST_ID> --otp <OTP>
```

Never write OTPs, Circle session files, private keys, or mnemonics into the repository.
Mainnet payments move real funds: keep Agent Wallet spending policies enabled and never fund more than the test budget.

## Testnet login and wallet (isolated development only)

```bash
npm install -g @circle-fin/cli@latest
circle --version

# Interactive testnet login. Testnet and mainnet sessions are separate.
circle wallet login <email> --testnet

# Login provisions agent wallets automatically; inspect before creating anything else.
circle wallet list --chain ARC-TESTNET --type agent --output json

# Arc Testnet faucet: omit --method and --amount.
circle wallet fund --address <AGENT_WALLET> --chain ARC-TESTNET
```

For a non-interactive agent flow:

```bash
circle wallet login <email> --testnet --init
circle wallet login <email> --testnet --request <REQUEST_ID> --otp <OTP>
```

Never write OTPs, Circle session files, private keys, or mnemonics into the repository.

## Inspect, estimate, then pay

```bash
circle services inspect "https://<host>/v1/package/risk?ecosystem=npm&name=express&version=5.2.1" --output json

circle services pay "https://<host>/v1/package/risk?ecosystem=npm&name=express&version=5.2.1" \
  -X GET \
  --address <AGENT_WALLET> \
  --chain <CHAIN-FROM-INSPECT> \
  --max-amount 0.005 \
  --estimate \
  --output json
```

After reviewing the estimate, repeat the same command without `--estimate` for a paid end-to-end test. On production, the OMNI seller facilitator is Circle mainnet (https://gateway-api.circle.com) and payments settle in USDC over the networks the challenge advertises; testnet examples above are for isolated development only. For production autonomous wallets, configure appropriate Circle Agent Wallet spending policies and test them separately from the seller service.

## Using a Circle Agent Wallet as OMNI's seller payout address

If you want OMNI's seller identity to use a Circle Agent Wallet, set that wallet's EVM/SCA address as `SELLER_ADDRESS`. The server still stores no signing key; Circle's seller middleware only needs the payout address. Inspect accumulated Gateway earnings with:

```bash
circle gateway balance --address <SELLER_ADDRESS> --chain <CHAIN> --all
```

For an Agent Wallet SCA, same-chain withdrawal is available through Circle CLI:

```bash
circle gateway withdraw --amount <USDC> --address <SELLER_ADDRESS> --chain <CHAIN>
```

Keep buyer-wallet automation and seller deployment credentials operationally separate even if they are managed from the same Circle account.
