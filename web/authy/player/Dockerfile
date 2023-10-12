FROM golang:1.21.1 AS builder

WORKDIR /src
COPY . .
RUN go mod download
RUN CGO_ENABLED=1 GOOS=linux go build -o /app -a -ldflags '-linkmode external -extldflags "-static"' .

FROM pwn.red/jail
COPY --from=builder /app /app
COPY --from=builder /src/black.db /
ENTRYPOINT ["/app"]
