// k6 부하 테스트 — 같은 요청을 백엔드 직접(direct) / 게이트웨이 경유(gateway)로 보내 차이를 잰다.
// docker run --rm --network mpg_gw-net -v $PWD/loadtest:/s grafana/k6 run /s/load.js
//   -e TARGET=direct|gateway|both  -e RATE=300  -e DURATION=10m  -e DIRECT_DURATION=3m
import http from "k6/http";
import { check } from "k6";

const RATE = Number(__ENV.RATE || 300);
const DURATION = __ENV.DURATION || "10m";
const DIRECT_DURATION = __ENV.DIRECT_DURATION || "3m";
const TARGET = __ENV.TARGET || "both";
const DIRECT = __ENV.DIRECT_URL || "https://backend:9443";
const GATEWAY = __ENV.GATEWAY_URL || "https://gateway:8443";

function scenario(name, base, duration, startTime) {
  return {
    executor: "constant-arrival-rate",
    rate: RATE,
    timeUnit: "1s",
    duration,
    startTime,
    preAllocatedVUs: 60,
    maxVUs: 300,
    exec: "hit",
    env: { BASE: base },
    tags: { target: name },
  };
}

const scenarios = {};
if (TARGET === "direct" || TARGET === "both") scenarios.direct = scenario("direct", DIRECT, DIRECT_DURATION, "0s");
if (TARGET === "gateway" || TARGET === "both")
  scenarios.gateway = scenario("gateway", GATEWAY, DURATION, TARGET === "both" ? DIRECT_DURATION : "0s");

export const options = {
  scenarios,
  insecureSkipTLSVerify: true,
  discardResponseBodies: true,
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
  thresholds: {
    "http_req_failed{target:gateway}": ["rate<0.001"],
    "http_req_duration{target:gateway}": ["p(95)<50"],
    "http_req_failed{target:direct}": ["rate<0.001"],
    "http_req_duration{target:direct}": ["p(95)<50"],
  },
};

const POST = JSON.stringify({
  title: "질문 있어요",
  content:
    "SQL에서 JOIN과 서브쿼리 중 뭐가 빠른가요? 인덱스를 걸었는데도 느려요. ".repeat(12) +
    "O'Brien 님이 알려준 방법도 해봤습니다.",
});
const SEARCH = ["%EB%85%B8%ED%8A%B8%EB%B6%81", "keyboard", "%EB%AC%B4%EC%84%A0+%EC%9D%B4%EC%96%B4%ED%8F%B0", "c%2B%2B"];

export function hit() {
  const base = __ENV.BASE;
  const r = Math.random();
  let res;
  if (r < 0.7) {
    res = http.get(`${base}/api/products?id=${1 + Math.floor(Math.random() * 3)}`, { tags: { name: "products" } });
  } else if (r < 0.9) {
    res = http.get(`${base}/api/search?q=${SEARCH[Math.floor(Math.random() * SEARCH.length)]}`, { tags: { name: "search" } });
  } else {
    res = http.post(`${base}/api/qna/posts`, POST, { headers: { "Content-Type": "application/json" }, tags: { name: "post" } });
  }
  check(res, { "2xx": (x) => x.status >= 200 && x.status < 300 });
}
