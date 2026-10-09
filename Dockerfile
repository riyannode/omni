FROM oven/bun:1.3.14-alpine AS base
WORKDIR /app

FROM base AS install
COPY package.json bun.lock ./
RUN bun install --production --frozen-lockfile

FROM base AS runtime
ENV NODE_ENV=production
COPY --from=install /app/node_modules ./node_modules
COPY . .
USER bun
EXPOSE 3000
CMD ["bun", "--sql-preconnect", "src/index.ts"]
