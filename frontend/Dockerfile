FROM node:22-alpine AS build-stage

WORKDIR /app

COPY package.json bun.lock /app/
COPY frontend/package.json /app/frontend/

RUN npm --prefix frontend install --no-package-lock

COPY frontend /app/frontend

ARG VITE_API_URL=http://localhost:8000
ARG NODE_ENV=production
ENV VITE_API_URL=$VITE_API_URL
ENV NODE_ENV=$NODE_ENV

RUN npm --prefix frontend run build

FROM nginx:1.27-alpine

COPY --from=build-stage /app/frontend/dist/ /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY frontend/nginx-backend-not-found.conf /etc/nginx/extra-conf.d/backend-not-found.conf
