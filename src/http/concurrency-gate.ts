import type { NextFunction, Request, Response } from "express";

export function concurrencyGate(limit: number) {
  let active = 0;
  return (_req: Request, res: Response, next: NextFunction) => {
    if (active >= limit) {
      res.setHeader("retry-after", "1");
      res.status(503).json({ error: "over_capacity", retryable: true });
      return;
    }
    active += 1;
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      active -= 1;
    };
    res.once("finish", release);
    res.once("close", release);
    next();
  };
}
