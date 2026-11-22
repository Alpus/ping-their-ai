FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /ping ./cmd/ping && mkdir /state

FROM scratch
COPY LICENSE NOTICE /usr/share/doc/ping/
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build --chown=65532:65532 /state /data
COPY --from=build /ping /ping
USER 65532:65532
ENV DATA_DIR=/data LISTEN_ADDR=:8787
EXPOSE 8787
ENTRYPOINT ["/ping"]
