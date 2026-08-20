import { createGatewayMiddleware } from "@circle-fin/x402-batching/server";

export function createCircleGateway(sellerAddress: `0x${string}`, facilitatorUrl?: string) {
  return createGatewayMiddleware({
    sellerAddress,
    ...(facilitatorUrl ? { facilitatorUrl } : {})
  });
}
