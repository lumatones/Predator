# ── Predator Server Dockerfile ──
# Multi-stage: TypeScript compile → minimal Node.js runtime
#
# Build:  docker build -f docker/server.Dockerfile -t predator-server .
# Run:    docker run -p 3001:3001 --env-file .env.docker predator-server

# ═══ Stage 1: Build ═══
FROM node:22-alpine AS builder
WORKDIR /app

# Install deps (TypeScript is in dependencies)
COPY server/package.json server/package-lock.json* ./
RUN npm install --ignore-scripts

# Copy source + tsconfig
COPY server/tsconfig.json ./
COPY server/src/ ./src/

# Compile TypeScript → dist/
RUN npx tsc --outDir dist

# ═══ Stage 2: Production ═══
FROM node:22-alpine

# Create non-root user
RUN addgroup -g 1001 -S predator && \
    adduser -S predator -u 1001 -G predator

WORKDIR /app

# Copy compiled output
COPY --from=builder /app/dist ./dist

# Copy package.json + production deps
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules

# Copy drizzle migrations (needed for db:init)
COPY server/drizzle/ ./drizzle/

# Security: run as non-root
USER predator

EXPOSE 3001

# Health check — uses Node.js HTTP (no wget dependency)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/api/health',r=>{process.exit(r.statusCode===200?0:1)})"

# Start
CMD ["node", "dist/index.js"]
