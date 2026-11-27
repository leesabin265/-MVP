#!/bin/sh
# 로컬 서버 한 번에 띄우기 (macOS · Linux · Windows의 WSL2/Git Bash, Docker Desktop 또는 Docker Engine 필요)
#
#   ./deploy/local-up.sh            기동(처음이면 비밀값·인증서 생성, 이미지 빌드)
#   ./deploy/local-up.sh stop       중지(데이터 유지)
#   ./deploy/local-up.sh reset      중지 + 데이터 삭제(DB·Redis·정책 캐시)
#
# 포트를 바꾸려면: GATEWAY_PORT=8443 CONSOLE_PORT=9443 ./deploy/local-up.sh
set -eu
cd "$(dirname "$0")/.."

GATEWAY_PORT=${GATEWAY_PORT:-443}
CONSOLE_PORT=${CONSOLE_PORT:-9443}
export GATEWAY_PORT CONSOLE_PORT

die() { echo "오류: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker가 없습니다. Docker Desktop(https://docs.docker.com/get-docker/)을 설치하세요."
docker info >/dev/null 2>&1 || die "Docker 데몬에 연결할 수 없습니다. Docker Desktop을 실행하세요."
docker compose version >/dev/null 2>&1 || die "docker compose v2가 필요합니다."
command -v openssl >/dev/null 2>&1 || die "openssl이 없습니다(macOS·Linux 기본 포함, Windows는 Git Bash 또는 WSL2 사용)."

case "${1:-up}" in
  stop)
    docker compose stop
    exit 0 ;;
  reset)
    printf "DB·Redis 데이터를 모두 지웁니다. 계속할까요? [y/N] "
    read -r ans
    [ "$ans" = "y" ] || exit 1
    docker compose down -v
    exit 0 ;;
  up) ;;
  *) die "사용법: $0 [up|stop|reset]" ;;
esac

./deploy/gen-secrets.sh >/dev/null

echo "이미지 빌드 및 기동 중… (처음에는 몇 분 걸립니다)"
docker compose up -d --build

echo "상태 확인 중…"
i=0
while :; do
  bad=$(docker compose ps --format '{{.Service}} {{.Health}}' gateway admin-api admin-console 2>/dev/null \
        | awk '$2 != "healthy"' | wc -l | tr -d ' ')
  [ "$bad" = "0" ] && break
  i=$((i + 1))
  if [ "$i" -gt 90 ]; then
    docker compose ps
    die "3분 안에 정상 상태가 되지 않았습니다. 'docker compose logs init admin-api gateway' 로 원인을 확인하세요."
  fi
  sleep 2
done

if command -v curl >/dev/null 2>&1; then
  ok=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:${GATEWAY_PORT}/api/products?id=1" || true)
  atk=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:${GATEWAY_PORT}/api/login?username=admin%2527%20OR%201%3D1--" || true)
  echo "점검: 정상 요청 ${ok} (기대 200), 공격 요청 ${atk} (기대 403)"
fi

cat <<EOF

로컬 서버가 준비됐습니다.
  게이트웨이     https://localhost:${GATEWAY_PORT}/      (뒤에 데모 백엔드)
  관리자 콘솔    https://localhost:${CONSOLE_PORT}/
  아이디         admin
  비밀번호       deploy/secrets/initial_admin_password 파일 내용
자체 서명 인증서라 브라우저 경고가 뜹니다(로컬 전용). curl은 -k 옵션을 쓰세요.
중지: ./deploy/local-up.sh stop
EOF
