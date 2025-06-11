FROM golang:alpine AS builder

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN rm -f go.work go.work.sum

RUN [ "go", "test", "-v", "./..." ]
ENV GOOS=linux
ENV CGO_ENABLED=0
RUN go build -o /usr/bin/delphi ./cmd/delphi

FROM alpine
COPY --from=builder /usr/bin/delphi /bin/delphi

ENTRYPOINT ["/bin/delphi"]
