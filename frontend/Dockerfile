# =====================================================================
# FragChain frontend image — production-grade static SPA server.
#
# Posture (F-006 + production-ready follow-up):
#
#   * Build stage uses node:20-alpine, builds the React/Vite bundle to
#     `./dist`, and throws itself away.
#   * Runtime stage uses `nginxinc/nginx-unprivileged` — the official
#     non-root NGINX image (uid 101). No Node, no npm, no Vite preview
#     server at runtime. Smallest reasonable attack surface for serving
#     static assets in v1.
#   * The image listens on port 8080 (unprivileged). The reverse-proxy
#     nginx in `nginx/conf.d/fragchain.conf` is the only public-facing
#     server; it proxies to `fragchain-ui:8080`.
#   * `nginx-spa.conf` handles SPA routing (`try_files ... /index.html`)
#     so React Router deep links don't 404, plus long cache for hashed
#     asset paths and no-cache for `index.html`.
#
# Operators that want even tighter posture can swap the runtime stage
# for a CDN-fronted deployment; the `./dist` artifact is portable.
# =====================================================================

FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime
# The image's default user is `nginx` (uid 101) and it listens on 8080.
# Copy in our SPA-aware vhost and the built bundle, both owned by the
# nginx user so reloads can read them.
COPY --chown=101:101 nginx-spa.conf /etc/nginx/conf.d/default.conf
COPY --from=build --chown=101:101 /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --retries=10 --start-period=10s \
    CMD wget -q --spider http://localhost:8080/ || exit 1
