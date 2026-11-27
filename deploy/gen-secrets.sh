#!/bin/sh
# 개발·데모용 비밀값과 자체 서명 TLS 인증서를 만든다. 이미 있으면 건드리지 않는다.
# 운영에서는 TLS를 Let's Encrypt 인증서로 바꾸고(README 참고) 이 디렉터리를 저장소에 커밋하지 않는다.
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p secrets certs
chmod 700 secrets certs
# Windows의 openssl은 줄 끝이 CRLF라 \r까지 지운다(전에는 \r이 비밀번호에 섞일 수 있었다).
gen() { [ -s "secrets/$1" ] || openssl rand -base64 33 | tr -d '/+=\r\n' | head -c 40 > "secrets/$1"; }
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
  # OpenSSL·LibreSSL(macOS 기본) 모두에서 되도록 RSA + 설정 파일 방식으로 SAN을 넣는다.
  cnf=$(mktemp)
  cat > "$cnf" <<CNF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = localhost
[ext]
subjectAltName = DNS:localhost,DNS:gateway,IP:127.0.0.1
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
CNF
  openssl req -x509 -newkey rsa:2048 -nodes -days 90 -keyout certs/server.key -out certs/server.crt \
    -config "$cnf" 2>/dev/null
  rm -f "$cnf"
fi
# HAProxy(외부 TLS 종료)는 인증서와 키를 한 파일로 받는다.
cat certs/server.crt certs/server.key > certs/server.pem

# ── 내부망 TLS: 사설 CA와 서비스별 인증서 ──
# CA 키는 어떤 컨테이너에도 넣지 않는다(secrets/internal-ca.key). 인증서 SAN은 compose 서비스 이름.
if [ ! -s secrets/internal-ca.key ]; then
  cnf=$(mktemp)
  cat > "$cnf" <<CNF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = MPG internal CA
[ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
CNF
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -config "$cnf" \
    -keyout secrets/internal-ca.key -out certs/internal-ca.crt 2>/dev/null
  rm -f "$cnf"
fi
for svc in gateway backend admin-api postgres redis; do
  [ -s "certs/$svc.key" ] && [ -s "certs/$svc.crt" ] && continue
  # 주체는 -subj 대신 설정 파일로 준다(Windows Git Bash는 '/CN=…' 인자를 경로로 바꿔 버린다).
  cnf=$(mktemp)
  cat > "$cnf" <<CNF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = $svc
[ext]
subjectAltName = DNS:$svc,DNS:localhost,IP:127.0.0.1
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
CNF
  openssl req -new -newkey rsa:2048 -nodes -config "$cnf" -keyout "certs/$svc.key" -out "certs/$svc.csr" 2>/dev/null
  openssl x509 -req -in "certs/$svc.csr" -CA certs/internal-ca.crt -CAkey secrets/internal-ca.key \
    -CAcreateserial -days 397 -extfile "$cnf" -extensions ext -out "certs/$svc.crt" 2>/dev/null
  rm -f "$cnf" "certs/$svc.csr"
done
rm -f certs/internal-ca.srl

# 컨테이너는 비루트(uid 10001)로 돌기 때문에 파일은 읽기 가능하게, 디렉터리는 소유자만 들어갈 수 있게 둔다.
chmod 644 secrets/* certs/*
chmod 600 secrets/internal-ca.key  # CA 키는 어느 컨테이너에도 넣지 않는다
echo "secrets in deploy/secrets, TLS cert in deploy/certs"
echo "initial admin password: deploy/secrets/initial_admin_password"
