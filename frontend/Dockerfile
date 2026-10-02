FROM node:22-alpine@sha256:b6f26b36c8ff49624cfdac716b8ea1138d606df02586a77d364bb5536a634f85 AS build-stage

WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json ./

RUN npm ci --workspaces=false --engine-strict=true

COPY frontend ./

ARG VITE_API_URL=
ARG NODE_ENV=production
ENV VITE_API_URL=$VITE_API_URL
ENV NODE_ENV=$NODE_ENV

RUN npm --workspaces=false --engine-strict=true run build

FROM nginxinc/nginx-unprivileged:1.31-alpine@sha256:26b0bf6fbf07297983cb341998d79c831508787de26627dd2a112321b9c3a4af

USER root
RUN apk upgrade --no-cache \
    && apk del --no-network curl libcurl nginx-module-image-filter
USER 101

COPY --from=build-stage /app/frontend/dist/ /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY frontend/nginx-backend-not-found.conf /etc/nginx/extra-conf.d/backend-not-found.conf
