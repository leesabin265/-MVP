# MPG — Malicious Pattern Gateway

웹 요청이 백엔드에 닿기 전에 SQL Injection·XSS·악성 스크립트 패턴을 우회 변형까지 공통 기준으로 걸러내는 API 게이트웨이.
기획서: 「악성 패턴 차단 API 게이트웨이 시스템 — 개발 기획서」(2026-11-25). 측정 결과와 설계 판단은 [`docs/report.md`](docs/report.md).

```
클라이언트 ──HTTPS 443──▶ gateway ──HTTP(gw-net, 내부)──▶ 백엔드 API
                           │  ▲
               XADD 이벤트 │  │ SUBSCRIBE policy.updated / SELECT 활성 정책(읽기 전용)
                           ▼  │
                         redis · postgres  (data-net, 내부)
                           ▲  │
                           │  ▼
관리자 ──HTTPS 9443(허용 IP)──▶ admin-console(nginx) ──▶ admin-api (mgmt-net, 내부)
```

## 로컬 서버로 실행

필요한 것: Docker Desktop(macOS·Windows) 또는 Docker Engine + Compose v2(Linux), git, openssl.
Windows는 WSL2 또는 Git Bash에서 실행한다. Apple Silicon(arm64)도 그대로 빌드된다.

```bash
git clone https://github.com/leesabin265/-mvp.git mpg && cd mpg
```

```bash
./deploy/local-up.sh
```

처음 실행하면 비밀값·자체 서명 인증서를 만들고, 이미지를 빌드하고(몇 분), 관리자 계정과 룰(게시판 차단 임계값 8 포함)을 넣어 v1을 발행한 뒤,
정상 요청 200 / 공격 요청 403 을 직접 확인하고 접속 정보를 출력한다.

- 게이트웨이: `https://localhost/` (뒤에 데모 백엔드). 자체 서명 인증서라 브라우저 경고가 뜨고, curl은 `-k`.
- 관리자 콘솔: `https://localhost:9443/` — 아이디 `admin`, 비밀번호는 `deploy/secrets/initial_admin_password`.
- 443 포트가 이미 쓰이면: `GATEWAY_PORT=8443 ./deploy/local-up.sh`
- 중지(데이터 유지): `./deploy/local-up.sh stop` · 데이터까지 삭제: `./deploy/local-up.sh reset`
- 계정 추가: `docker compose exec -T admin-api mpgctl create-admin --id op1 --role OPERATOR` (비밀번호는 표준 입력)

```bash
curl -k "https://localhost/api/login?username=admin%2527%20OR%201%3D1--"
```

npm·PyPI에 닿지 않는 환경: 호스트에서 `pip wheel '.[server]' -w deploy/wheels` 와 `cd console && npm ci && npm run build` 를 한 뒤
`CONSOLE_BUILD_TARGET=prebuilt ./deploy/local-up.sh`.

## 구성

| 컨테이너 | 역할 | 네트워크 |
|---|---|---|
| gateway | FastAPI + Uvicorn(워커 2), TLS 종료, 파싱 → 정규화 → 프리필터 → 정밀 분석 → 점수 판정 → 전달 | edge, gw-net, data-net |
| admin-api | REST `/admin/api`, 인증·RBAC·CSRF·감사, 회귀 게이트 발행, 이벤트 소비자, 보존 배치 | data-net, mgmt-net |
| admin-console | React 19 정적 파일 + nginx(TLS, CSP, `/admin/api` 프록시) | edge, mgmt-net |
| postgres | PostgreSQL 18 — 테이블 9개, 앱 계정 분리(gateway는 `policy_versions` 읽기만) | data-net |
| redis | Redis 8 — 이벤트 스트림, 정책 알림, 세션. ACL로 계정별 키·채널 제한 | data-net |
| backend | 데모용 "기존 서비스" (Prepared Statement·출력 이스케이프 갖춤) | gw-net(내부 전용) |
| init | 1회성: 최초 관리자 생성 + 룰 적재·v1 발행 | data-net |

## 디렉터리

```
src/mpg/detection/   탐지 엔진 (프레임워크 독립): normalizer, prefilter, detectors, scorer, pipeline, regress
src/mpg/gateway/     extract(요청→필드), app(프록시), policy_manager(핫 리로드), events(버퍼→Streams), metrics
src/mpg/admin/       app(REST), auth, policy_service(작업본·회귀 게이트·발행·롤백), consumer, alerts, schema.sql
src/mpg/cli.py       mpgctl
console/             관리자 콘솔 (Vite 8 + React 19 + TypeScript)
rules/rules.yaml     룰 51개 (SQLI 18 · XSS 16 · SCR 9 · ENC 8) — 정규식 41 · 신호 9 · 토큰 분석기 1
datasets/            attack 2,081 · normal 1,000 · normal_hard 40 (튜닝에 쓰지 않은 기술 Q&A)
tools/               gen_datasets · threshold_sweep · replay · reload_probe · outage_drill
loadtest/load.js     k6 (직접 vs 게이트웨이, 300 RPS)
deploy/              Dockerfile, nginx, postgres 초기화, 비밀값·인증서 생성
docs/                report.md, 측정 원자료(JSON), 스크린샷
```

## 판정 규칙

- 필드마다 점수를 계산하고 요청 점수는 필드 점수의 최댓값.
- `BLOCK` 모드 룰 점수 합 ≥ 6 → **BLOCK(403)** / 전체 합 ≥ 6 → **DETECT_ONLY(전달 + 기록)** / 그 외 **ALLOW**.
- 우회 신호(다중 인코딩·전각·주석·제어문자 등)도 ENC 룰이라 예외·모드·가중치를 똑같이 다룬다.
- 예외는 `룰 1개 · 경로 · 파라미터 · 만료일(최대 180일)` 필수, 와일드카드 금지.
- **경로별 차단 임계값**: 경로(·파라미터)마다 차단 기준만 3 ~ 전역+4 로 바꿀 수 있다(ADMIN). 탐지 기준은 전역값 그대로라
  올리더라도 그 사이 점수는 DETECT_ONLY로 기록된다. 예: 기술 게시판 `/api/qna/posts`·`content` = 8 (근거는 `docs/report.md` 4장).
- 정책 변경은 작업본에 쌓이고, 발행 때 회귀 테스트를 다시 돌려 탐지율이 떨어지거나 차단 오탐이 늘면 422로 거부한다.

## 운영 명령 (`mpgctl`, admin-api 컨테이너 안)

| 명령 | 용도 |
|---|---|
| `mpgctl create-admin --id lee --role ADMIN [--if-missing]` | 관리자 계정 (비밀번호는 표준 입력) |
| `mpgctl seed-rules /app/rules/rules.yaml` | 룰 적재 + 발행(변경 없으면 그대로) |
| `mpgctl regress --rules ... --attack ... --normal ...` | 회귀 테스트 단독 실행 |
| `mpgctl rollback 12` | 콘솔이 안 될 때 비상 롤백 |
| `mpgctl migrate` | 스키마 갱신(superuser 계정으로 실행) |

## 테스트

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[server,dev]'
```

```bash
.venv/bin/pytest --ignore=tests/e2e
```

```bash
MPG_E2E_GATEWAY=https://localhost MPG_E2E_ADMIN=https://localhost:9443 MPG_E2E_VERIFY=0 .venv/bin/pytest tests/e2e
```

e2e는 `lee`(ADMIN)·`op1`(OPERATOR)·`viewer1`(VIEWER) 계정이 필요하다(`tests/e2e/test_e2e.py` 상단의 환경 변수로 비밀번호 지정).
게이트웨이의 `/__mpg/health` 는 내부 대역에서만 열리므로 호스트에서 e2e를 돌릴 때는
`GATEWAY_INTERNAL_CIDRS=127.0.0.0/8,172.28.30.0/24,172.28.40.1/32` 로 기동한다(172.28.40.1은 호스트 로컬 접속만 해당).

## 기존 배포 업그레이드

스키마는 멱등이라 새 버전을 받은 뒤 superuser로 한 번 적용하고 다시 띄우면 된다(이번 버전은 `path_thresholds` 테이블 추가).

```bash
docker compose up -d postgres && docker compose exec -T postgres psql -U postgres -d mpg < src/mpg/admin/schema.sql
```

```bash
docker compose up -d --build
```

## 운영 배포 시 바꿀 것

- **TLS**: `deploy/certs/server.{crt,key}` 를 Let's Encrypt 인증서로 교체(예: `certbot certonly --standalone -d gw.example.com` 후 `fullchain.pem`·`privkey.pem` 연결). 갱신 후 `docker compose restart gateway admin-console`.
- **관리자 허용 IP**: `ADMIN_ALLOW_CIDRS=203.0.113.10/32 docker compose up -d`.
- **알림 웹훅**: `ALERT_WEBHOOK=https://hooks.slack.com/...` (치명 알림만, 같은 알림은 1시간에 1번).
- **비밀값**: `deploy/secrets` 는 저장소에 커밋하지 않는다(.gitignore). 파일은 컨테이너의 비루트 사용자가 읽을 수 있도록 0644, 디렉터리는 0700.

## 참고·라이선스

공격 페이로드 유형은 PayloadsAllTheThings(MIT), OWASP XSS Filter Evasion Cheat Sheet, OWASP CRS(Apache-2.0)를 참고해 직접 작성했다.
점수 합산 구조는 OWASP CRS의 Anomaly Scoring, 토큰 분석은 libinjection의 아이디어를 참고했다.
