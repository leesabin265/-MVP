# MPG — Malicious Pattern Gateway

웹 요청이 백엔드에 닿기 전에 SQL Injection·XSS·악성 스크립트·OS 명령어 삽입·경로 조작·악성 업로드를 우회 변형까지 공통 기준으로 걸러내고,
백엔드 응답의 정보 유출(DB 오류·시스템 파일·키)도 막는 API 게이트웨이.
기획서: 「악성 패턴 차단 API 게이트웨이 시스템 — 개발 기획서」(2026-11-25). 측정 결과와 설계 판단은 [`docs/report.md`](docs/report.md).

```
클라이언트 ──HTTPS 443──▶ edge-lb(HAProxy) ──TLS──▶ gateway ×N ──TLS(gw-net, 내부)──▶ 백엔드 API
                                                   │  ▲
                                       XADD 이벤트 │  │ SUBSCRIBE policy.updated / SELECT 활성 정책(읽기 전용)
                                                   ▼  │      (TLS, 사설 CA 검증)
                                                 redis · postgres  (data-net, 내부)
                                                   ▲  │
                                                   │  ▼
관리자 ──HTTPS 9443(허용 IP)──▶ admin-console(nginx) ──TLS──▶ admin-api (mgmt-net, 내부)
```
내부망의 모든 연결은 TLS다(`deploy/gen-secrets.sh` 가 만드는 사설 CA로 서로 검증). PostgreSQL은 평문 접속을 거부하고, Redis는 평문 포트를 닫는다.

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

- 게이트웨이: `https://localhost/` (로드밸런서 → 게이트웨이 2대 → 데모 백엔드). 자체 서명 인증서라 브라우저 경고가 뜨고, curl은 `-k`.
- 게이트웨이 대수: `GATEWAY_REPLICAS=3 ./deploy/local-up.sh` (기본 2)
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
| edge-lb | HAProxy: 외부 TLS 종료, 게이트웨이 복제본에 라운드로빈(Docker DNS·헬스체크), X-Forwarded-For 재작성 | edge, lb-net |
| gateway ×N | FastAPI + Uvicorn(워커 2), 파싱 → 정규화 → 프리필터 → 정밀 분석 → 점수 판정 → 전달 → 응답 검사 | lb-net, gw-net, data-net |
| admin-api | REST `/admin/api`, 인증·RBAC·CSRF·감사, 회귀 게이트 발행, 이벤트 소비자, 보존 배치 | data-net, mgmt-net |
| admin-console | React 19 정적 파일 + nginx(TLS, CSP, `/admin/api` 프록시) | edge, mgmt-net |
| postgres | PostgreSQL 18 — 테이블 10개, 앱 계정 분리(gateway는 `policy_versions` 읽기만), TLS 전용 | data-net |
| redis | Redis 8 — 이벤트 스트림, 정책 알림, 세션. ACL로 계정별 키·채널 제한 | data-net |
| backend | 데모용 "기존 서비스" (Prepared Statement·출력 이스케이프 갖춤) | gw-net(내부 전용) |
| init | 1회성: 최초 관리자 생성 + 룰 적재·v1 발행 | data-net |

## 디렉터리

```
src/mpg/detection/   탐지 엔진 (프레임워크 독립): normalizer, prefilter, detectors, scorer, pipeline, regress
src/mpg/gateway/     extract(요청→필드), uploads(업로드 파일 판정), response_body(응답 검사용 읽기), app(프록시),
                     policy_manager(핫 리로드), events(버퍼→Streams), metrics
src/mpg/admin/       app(REST), auth, policy_service(작업본·회귀 게이트·발행·롤백), consumer, alerts, schema.sql
src/mpg/cli.py       mpgctl
console/             관리자 콘솔 (Vite 8 + React 19 + TypeScript)
rules/rules.yaml     룰 74개 (SQLI 18 · XSS 16 · SCR 9 · CMD 6 · PATH 5 · FILE 5 · RESP 7 · ENC 8)
                     + 경로별 임계값·경로별 룰 모드(게시판 본문: 임계값 8, XSS-004 차단)
datasets/            attack 2,286 · normal 1,068 · normal_hard 40 (튜닝에 쓰지 않은 기술 Q&A)
tools/               gen_datasets · threshold_sweep · replay · reload_probe · outage_drill
                     · crs_eval(OWASP CRS로 외부 측정) · traffic_eval(운영 로그 재측정)
loadtest/load.js     k6 (직접 vs 게이트웨이, 300 RPS)
deploy/              Dockerfile, nginx, haproxy, postgres 초기화·pg_hba, 비밀값·인증서(사설 CA 포함) 생성
docs/                report.md, 측정 원자료(JSON), 스크린샷
```

## 판정 규칙

- 필드마다 점수를 계산하고 요청 점수는 필드 점수의 최댓값.
- `BLOCK` 모드 룰 점수 합 ≥ 6 → **BLOCK(403)** / 전체 합 ≥ 6 → **DETECT_ONLY(전달 + 기록)** / 그 외 **ALLOW**.
- 우회 신호(다중 인코딩·전각·주석·제어문자 등)도 ENC 룰이라 예외·모드·가중치를 똑같이 다룬다.
- 예외는 `룰 1개 · 경로 · 파라미터 · 만료일(최대 180일)` 필수, 와일드카드 금지.
- **경로별 차단 임계값**: 경로(·파라미터)마다 차단 기준만 3 ~ 전역+4 로 바꿀 수 있다(ADMIN). 탐지 기준은 전역값 그대로라
  올리더라도 그 사이 점수는 DETECT_ONLY로 기록된다. 예: 기술 게시판 `/api/qna/posts`·`content` = 8 (근거는 `docs/report.md` 4장).
- **경로별 룰 모드**: 경로(·파라미터)에서만 룰 하나를 탐지(DETECT)로 낮추거나 차단(BLOCK)으로 올린다(ADMIN).
- **업로드**: 파일 내용은 매직 넘버로 판정하고, 텍스트 파일은 내용도 다른 룰로 검사한다(`이름#content`).
- **응답 검사**: 텍스트 응답 앞 256 KB를 RESP 룰로 본다. 파라미터 이름 `$response` 로 경로별 설정·예외를 건다. 차단 시 502.
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
`GATEWAY_INTERNAL_CIDRS=127.0.0.0/8,172.28.30.0/24,172.28.50.10/32,172.28.40.1/32` 로 기동한다
(172.28.50.10은 로드밸런서 헬스체크, 172.28.40.1은 호스트 로컬 접속). 게이트웨이 대수가 2가 아니면 `MPG_E2E_GATEWAYS` 도 맞춘다.

## 기존 배포 업그레이드

스키마는 멱등이라 새 버전을 받은 뒤 superuser로 한 번 적용하고 다시 띄우면 된다
(2차: `path_rule_overrides` 테이블, 룰 분류 CMD·PATH·FILE·RESP 추가). 2차부터는 내부망 TLS 인증서가 필요하므로 `gen-secrets.sh` 를 먼저 다시 돌린다
(이미 있는 비밀값은 그대로 두고 없는 인증서만 만든다).

```bash
./deploy/gen-secrets.sh
```

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
- **내부망 TLS 인증서**: `deploy/certs/*.crt` 는 397일, 사설 CA는 825일. 만료 전에 `deploy/certs/<서비스>.{crt,key}` 를 지우고 `gen-secrets.sh` 를 다시 돌린 뒤 재시작.
- **조정값**: `GATEWAY_REPLICAS`(게이트웨이 대수), `GATEWAY_MAX_PCT_ESCAPES`(요청당 '%' 상한, 기본 100000), `GATEWAY_RESPONSE_INSPECT_BYTES`(응답 검사 크기, 0이면 끔).
- **비밀값**: `deploy/secrets` 는 저장소에 커밋하지 않는다(.gitignore). 파일은 컨테이너의 비루트 사용자가 읽을 수 있도록 0644, 디렉터리는 0700.

## 측정

- 직접 만든 셋: `mpgctl regress` 또는 `python -m mpg.detection.regress` — 탐지 100%, 차단 99.30%, 오탐 0.37%(전부 기록만).
- **외부 데이터(OWASP CRS, 튜닝에 쓰지 않음)**: `python tools/crs_eval.py <coreruleset 클론>` — PL1 탐지 SQLi 25%, XSS 34%. 차이와 원인은 `docs/report.md` 10장.
- 운영 트래픽: `python tools/traffic_eval.py --format combined access.log --review review.jsonl` → 라벨을 달아 다시 넣으면 탐지율·오탐률.

## 참고·라이선스

공격 페이로드 유형은 PayloadsAllTheThings(MIT), OWASP XSS Filter Evasion Cheat Sheet, OWASP CRS(Apache-2.0)를 참고해 직접 작성했다.
점수 합산 구조는 OWASP CRS의 Anomaly Scoring, 토큰 분석은 libinjection의 아이디어를 참고했다.
