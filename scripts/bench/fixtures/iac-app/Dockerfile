FROM node:20-slim@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://get.example.test/install.sh | sh
COPY --from=build /app/dist /srv/app
USER root
CMD ["/srv/app/start"]
