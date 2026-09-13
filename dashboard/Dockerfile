# syntax=docker/dockerfile:1
FROM node:22-alpine AS build
WORKDIR /app

# Baked in at build time — Vite inlines VITE_* vars into the JS bundle,
# there's no runtime env for a static SPA. Override with
# `docker compose build --build-arg VITE_API_BASE_URL=...` for a
# non-localhost API.
ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
RUN npm run build


FROM nginx:1.27-alpine AS runtime
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
# 127.0.0.1, not localhost: resolving "localhost" here can try ::1 first,
# nginx only listens on 0.0.0.0:80 (IPv4), and busybox wget doesn't fall
# back to IPv4 after an IPv6 refusal — confirmed the hard way, this
# container reported `unhealthy` in `docker compose ps` indefinitely
# despite the site serving every request from outside just fine.
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1/ || exit 1
