FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go generate ./... && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /coraza-waf-mod .

FROM scratch
COPY --from=builder /coraza-waf-mod /coraza-waf-mod
ENTRYPOINT ["/coraza-waf-mod"]
