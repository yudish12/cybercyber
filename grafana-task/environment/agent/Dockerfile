FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/*.sources /etc/apt/sources.list 2>/dev/null; \
    apt-get update && apt-get install -y --no-install-recommends \
    curl dnsutils jq tmux asciinema procps ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY vendor-wheels /tmp/vendor-wheels
RUN pip install --no-cache-dir --no-index --find-links=/tmp/vendor-wheels harbor-rewardkit==0.1.7 requests==2.34.2 \
    && python3 -c "import rewardkit, requests" \
    && rm -rf /tmp/vendor-wheels

RUN useradd -m -u 1001 agent && mkdir -p /logs/verifier /work && chown -R agent:agent /logs /work

WORKDIR /work
USER agent

CMD ["sh", "-c", "i=0; while [ $i -lt 60 ]; do getent hosts web >/dev/null 2>&1 && break; sleep 2; i=$((i+1)); done; exec sleep infinity"]
