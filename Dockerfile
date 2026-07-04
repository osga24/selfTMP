# --- build stage ---
FROM golang:1.25-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath -ldflags="-s -w" \
      -o /out/selftmp .

# --- runtime stage ---
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata wget \
 && adduser -D -H -u 10001 selftmp \
 && mkdir -p /data && chown -R selftmp:selftmp /data

COPY --from=build /out/selftmp /usr/local/bin/selftmp

ENV DATA_DIR=/data \
    PORT=8080

VOLUME ["/data"]
EXPOSE 8080
USER selftmp

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget --quiet --tries=1 --spider http://localhost:8080/ || exit 1

ENTRYPOINT ["/usr/local/bin/selftmp"]
