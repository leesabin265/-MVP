FROM node:22-alpine AS build
WORKDIR /src
COPY console/package.json console/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY console/ ./
RUN npm run build

FROM nginx:1.29-alpine AS base
RUN rm -f /etc/nginx/conf.d/default.conf
COPY deploy/nginx/console.conf /etc/nginx/conf.d/console.conf

# 기본: 소스에서 빌드
FROM base AS from-source
COPY --from=build /src/dist /usr/share/nginx/html

# 오프라인: 호스트에서 미리 빌드한 console/dist 사용 (npm 레지스트리에 닿지 않는 환경)
FROM base AS prebuilt
COPY console/dist /usr/share/nginx/html
