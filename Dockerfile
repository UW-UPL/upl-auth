FROM golang:1.24-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git
COPY go.mod* go.sum* ./
RUN go mod download || true
COPY . .
RUN go mod tidy

RUN CGO_ENABLED=0 go build -o server ./cmd/server
RUN CGO_ENABLED=0 go build -o bot ./cmd/discord-bot

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/server .
COPY --from=builder /app/bot .
COPY --from=builder /app/web ./web

EXPOSE 8080

CMD ["./server"]
