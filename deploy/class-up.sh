#!/bin/sh
# 수업 발표용 실시간 참여 페이지 띄우기/내리기
#
#   ./deploy/class-up.sh          띄우기(게이트웨이 스택이 떠 있어야 함: ./deploy/local-up.sh)
#   ./deploy/class-up.sh down     내리기(발표가 끝나면)
#   CLASS_HOST=192.168.0.23 ./deploy/class-up.sh   QR에 넣을 이 PC 주소를 직접 지정
#
# 학생 휴대폰은 이 PC와 같은 Wi-Fi에 있어야 한다. 주소는 이 PC의 사설 IP(같은 네트워크 안에서만 닿음).
set -eu
cd "$(dirname "$0")/.."
CLASS_PORT=${CLASS_PORT:-8080}
export CLASS_PORT

if [ "${1:-up}" = "down" ]; then
  docker compose --profile class stop classroom
  docker compose --profile class rm -f classroom
  exit 0
fi

detect_ip() {
  if command -v powershell.exe >/dev/null 2>&1; then
    # Windows: 기본 경로(인터넷으로 나가는) 인터페이스의 IPv4
    powershell.exe -NoProfile -Command "(Get-NetIPConfiguration | Where-Object { \$_.IPv4DefaultGateway -ne \$null -and \$_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1).IPv4Address.IPAddress" 2>/dev/null | tr -d '\r'
  elif command -v ipconfig >/dev/null 2>&1 && ipconfig getifaddr en0 >/dev/null 2>&1; then
    ipconfig getifaddr en0
  elif command -v hostname >/dev/null 2>&1; then
    hostname -I 2>/dev/null | awk '{print $1}'
  fi
}

HOST=${CLASS_HOST:-$(detect_ip)}
[ -n "$HOST" ] || { echo "이 PC의 IP를 찾지 못했습니다. CLASS_HOST=192.168.x.x 로 지정하세요." >&2; exit 1; }
MPG_CLASS_URL="http://${HOST}:${CLASS_PORT}/"
export MPG_CLASS_URL

./deploy/gen-secrets.sh >/dev/null
docker compose --profile class up -d --build classroom

i=0
until [ "$(docker compose --profile class ps --format '{{.Health}}' classroom 2>/dev/null)" = "healthy" ]; do
  i=$((i + 1)); [ "$i" -gt 60 ] && { docker compose --profile class logs --tail 20 classroom; exit 1; }
  sleep 2
done

KEY=$(cat deploy/secrets/class_presenter_key)
cat <<EOF

수업 참여 페이지가 준비됐습니다.
  학생 접속(QR에 들어감)  ${MPG_CLASS_URL}
  발표자 화면(프로젝터)    http://localhost:${CLASS_PORT}/presenter?key=${KEY}
발표자 주소는 학생에게 보여 주지 마세요(진행 버튼이 있습니다).
학생 휴대폰에서 안 열리면: 같은 Wi-Fi인지, Windows 방화벽이 포트 ${CLASS_PORT}를 막는지 확인하세요.
끝나면: ./deploy/class-up.sh down
EOF
