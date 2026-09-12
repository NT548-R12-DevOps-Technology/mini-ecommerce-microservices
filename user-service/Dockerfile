# ===== Build stage =====
FROM golang:1.26.8-alpine3.24 AS builder

WORKDIR /app

# copy go mod trước để cache dependency
COPY go.mod go.sum ./
RUN go mod download

# copy source
COPY . .

# build binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o user-service ./cmd

# ===== Runtime stage =====
FROM gcr.io/distroless/base-debian12

WORKDIR /app

COPY --from=builder /app/user-service .
COPY --from=builder /app/migrations ./migrations

EXPOSE 8080

CMD ["./user-service"]
