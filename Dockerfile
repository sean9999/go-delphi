FROM golang:1.24 AS builder

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN rm -f go.work go.work.sum

RUN [ "go", "test", "-v", "./..." ]
RUN go build -o /usr/bin/delphi ./cmd/delphi

FROM debian:bookworm-slim
COPY --from=builder /usr/bin/delphi /bin/delphi

ENTRYPOINT ["/bin/delphi"]
