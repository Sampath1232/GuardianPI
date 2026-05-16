# Guardian Pi Edge Agent (Go)
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o guardian-agent ./cmd/agent

FROM alpine:3.19
RUN apk add --no-cache ca-certificates && \
    addgroup -S guardian && adduser -S guardian -G guardian
WORKDIR /opt/guardian
COPY --from=builder /build/guardian-agent .
RUN chown -R guardian:guardian /opt/guardian
USER guardian
ENTRYPOINT ["./guardian-agent"]
