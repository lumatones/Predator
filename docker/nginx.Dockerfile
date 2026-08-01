# ── Predator Nginx Dockerfile ──
# Multi-stage: build admin SPA + website SPA → nginx:alpine
#
# Build:  docker build -f docker/nginx.Dockerfile -t predator-nginx .
# Run:    docker run -p 80:80 predator-nginx

# ═══ Stage 1: Build Admin SPA ═══
FROM node:22-alpine AS admin-builder
WORKDIR /app
# Install deps
COPY admin/package.json admin/package-lock.json* ./
RUN npm install
COPY admin/ ./
RUN npx vite build --base=/admin/

# ═══ Stage 2: Build Website SPA ═══
FROM node:22-alpine AS website-builder
WORKDIR /app
# Install deps
COPY website/package.json website/package-lock.json* ./
RUN npm install
COPY website/ ./
RUN npx vite build

# ═══ Stage 3: Nginx ═══
FROM nginx:1.27-alpine

# Copy nginx config
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

# Copy built SPAs
COPY --from=admin-builder /app/dist /usr/share/nginx/html/admin
COPY --from=website-builder /app/dist /usr/share/nginx/html

# Static site health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost/ || exit 1

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
