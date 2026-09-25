FROM golang:1.27-alpine AS builder
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go generate ./... && \
    CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o /coraza-waf-mod .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /coraza-waf-mod /coraza-waf-mod
ENV TMPDIR=/data
VOLUME ["/data"]
EXPOSE 8080
# Probes 127.0.0.1:8080; pass --url to the healthcheck subcommand if --listen changes.
HEALTHCHECK --interval=30s --timeout=6s --start-period=30s CMD ["/coraza-waf-mod", "healthcheck"]
ENTRYPOINT ["/coraza-waf-mod"]
# No cron in a container, so prune old request logs in-process.
CMD ["--db", "/data/waf.db", "--certs", "/data/certs", "--prune-interval", "24h"]
