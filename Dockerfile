# Build stage
FROM golang:1.25.7-alpine AS builder

WORKDIR /app

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the server and worker binaries
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/server ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/worker ./cmd/worker

# Final stage
FROM alpine:latest

WORKDIR /app

# Install CA certificates for TLS
RUN apk --no-cache add ca-certificates tzdata

# Copy binaries from builder
COPY --from=builder /app/bin/server /app/server
COPY --from=builder /app/bin/worker /app/worker
COPY --from=builder /app/.keys /app/.keys

# Expose port (default 8080)
EXPOSE 8000

# The default command will be overridden by docker-compose for the worker
CMD ["/app/server"]
