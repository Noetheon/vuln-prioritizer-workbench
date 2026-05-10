FROM node:22-alpine@sha256:8ea2348b068a9544dae7317b4f3aafcdc032df1647bb7d768a05a5cad1a7683f AS build-stage

WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json ./

RUN npm ci --workspaces=false

COPY frontend ./

ARG VITE_API_URL=
ARG NODE_ENV=production
ENV VITE_API_URL=$VITE_API_URL
ENV NODE_ENV=$NODE_ENV

RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0

USER root
RUN apk upgrade --no-cache
USER 101

COPY --from=build-stage /app/frontend/dist/ /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY frontend/nginx-backend-not-found.conf /etc/nginx/extra-conf.d/backend-not-found.conf
