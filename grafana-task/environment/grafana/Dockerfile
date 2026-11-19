FROM golang:1.27.3-bookworm@sha256:a5406f41680f17b4aa0b49de641e00f116215f5c8829d548d29cb44c4f85aa4f AS gbuilder
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://github.com/grafana/grafana/archive/refs/tags/v13.3.1.tar.gz -o /tmp/g.tgz \
 && tar xzf /tmp/g.tgz --strip-components=1 -C /src \
 && rm /tmp/g.tgz
ARG DSPROXY_EXACT_HOST_MATCH=0
COPY ds_proxy.go /tmp/ds_proxy.default.go
COPY ds_proxy_stock.go /tmp/ds_proxy.exact.go
RUN if [ "$DSPROXY_EXACT_HOST_MATCH" = "1" ]; then \
      cp /tmp/ds_proxy.exact.go /src/pkg/api/pluginproxy/ds_proxy.go; \
    else \
      cp /tmp/ds_proxy.default.go /src/pkg/api/pluginproxy/ds_proxy.go; \
    fi
ENV GOFLAGS=-buildvcs=false CGO_ENABLED=0 GOPATH=/go GOCACHE=/root/.cache/go-build
RUN mkdir -p /out \
 && go build -trimpath -o /out/grafana ./pkg/cmd/grafana \
 && test -x /out/grafana

FROM grafana/grafana:13.3.1@sha256:0615ec4fbd4072004b7d86b46ded63013a74b7d6eb1119273dd89e8fa25c13cf

COPY --from=gbuilder /out/grafana /usr/share/grafana/bin/grafana
COPY provisioning/ /etc/grafana/provisioning/
COPY dashboards/ /etc/grafana/dashboards/
COPY entrypoint.sh /custom-entrypoint.sh

USER root
RUN chmod +x /custom-entrypoint.sh /usr/share/grafana/bin/grafana \
 && chown -R 472:0 /etc/grafana/provisioning /etc/grafana/dashboards \
 && chown 472:0 /usr/share/grafana/bin/grafana
USER 472

ENTRYPOINT ["/custom-entrypoint.sh"]
