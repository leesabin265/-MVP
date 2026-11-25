#!/bin/sh
# 최초 기동(빈 볼륨)에서만 실행된다. 앱 계정은 테이블 소유자가 아니다 — 스키마는 이 다음 20-schema.sql이 superuser로 만든다.
set -eu
ADMIN_PW=$(cat /run/secrets/pg_admin_password)
GW_PW=$(cat /run/secrets/pg_gateway_password)
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v admin_pw="$ADMIN_PW" -v gw_pw="$GW_PW" -v DBNAME="$POSTGRES_DB" <<'SQL'
CREATE ROLE mpg_admin LOGIN PASSWORD :'admin_pw' CONNECTION LIMIT 30;
CREATE ROLE mpg_gateway LOGIN PASSWORD :'gw_pw' CONNECTION LIMIT 20;
REVOKE ALL ON DATABASE :"DBNAME" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"DBNAME" TO mpg_admin, mpg_gateway;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO mpg_admin, mpg_gateway;
SQL
