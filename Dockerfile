FROM golang:1.26-alpine AS builder
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
ENTRYPOINT ["/coraza-waf-mod"]
CMD ["--db", "/data/waf.db", "--certs", "/data/certs"]
