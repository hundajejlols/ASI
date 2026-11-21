FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod go.sum* ./
COPY . .
RUN go mod tidy && go test ./... && CGO_ENABLED=0 GOOS=linux go build -o /out/asi-scanner ./cmd/worker

FROM alpine:3.20

RUN apk add --no-cache nmap nmap-scripts ca-certificates tzdata libcap \
    && adduser -D -u 10001 scanner \
    && setcap cap_net_raw=ep /usr/bin/nmap

WORKDIR /app
COPY --from=builder /out/asi-scanner /usr/local/bin/asi-scanner

USER scanner

ENTRYPOINT ["/usr/local/bin/asi-scanner"]
