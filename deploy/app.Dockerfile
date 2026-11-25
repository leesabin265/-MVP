# gateway · admin-api · demo-backend 공용 이미지
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MPG_HOME=/app PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin mpg
COPY deploy/wheels /wheels
COPY pyproject.toml README.md /build/
COPY src /build/src
# deploy/wheels 에 휠이 있으면 오프라인 설치, 없으면 PyPI에서 설치
RUN if ls /wheels/*.whl >/dev/null 2>&1; then \
        pip install --no-cache-dir --no-index --find-links /wheels "mpg[server]"; \
    else \
        pip install --no-cache-dir "/build[server]"; \
    fi && rm -rf /wheels /build
WORKDIR /app
COPY rules ./rules
COPY datasets ./datasets
COPY deploy/healthcheck.py /usr/local/bin/mpg-healthcheck
RUN chmod 0755 /usr/local/bin/mpg-healthcheck && mkdir -p /var/lib/mpg && chown mpg /var/lib/mpg
USER mpg
