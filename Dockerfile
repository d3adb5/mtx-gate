FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY watch ./watch
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mtx-gate .

# No shell, no package manager, uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /mtx-gate /mtx-gate
ENTRYPOINT ["/mtx-gate"]
