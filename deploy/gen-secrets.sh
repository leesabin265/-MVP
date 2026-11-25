#!/bin/sh
# 개발·데모용 비밀값과 자체 서명 TLS 인증서를 만든다. 이미 있으면 건드리지 않는다.
# 운영에서는 TLS를 Let's Encrypt 인증서로 바꾸고(README 참고) 이 디렉터리를 저장소에 커밋하지 않는다.
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p secrets certs
chmod 700 secrets certs
gen() { [ -s "secrets/$1" ] || openssl rand -base64 33 | tr -d '/+=\n' | head -c 40 > "secrets/$1"; }
for s in pg_superuser_password pg_admin_password pg_gateway_password \
         redis_admin_password redis_gateway_password initial_admin_password; do
  gen "$s"
done
GW=$(cat secrets/redis_gateway_password)
AD=$(cat secrets/redis_admin_password)
cat > secrets/redis_users.acl <<ACL
user default off
user healthcheck on nopass -@all +ping
user mpg-gateway on >$GW resetkeys ~gateway.events ~gateway:stats:* resetchannels &policy.updated -@all +ping +hello +client|setinfo +client|setname +select +xadd +set +subscribe +unsubscribe
user mpg-admin on >$AD resetkeys ~gateway.events ~gateway:stats:* ~sess:* ~loginfail:* resetchannels &policy.updated +@all -@admin -@dangerous +info
ACL
if [ ! -s certs/server.key ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 90 \
    -keyout certs/server.key -out certs/server.crt -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:gateway,IP:127.0.0.1" 2>/dev/null
fi
# 컨테이너는 비루트(uid 10001)로 돌기 때문에 파일은 읽기 가능하게, 디렉터리는 소유자만 들어갈 수 있게 둔다.
chmod 644 secrets/* certs/*
echo "secrets in deploy/secrets, TLS cert in deploy/certs"
echo "initial admin password: deploy/secrets/initial_admin_password"
