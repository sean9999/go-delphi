FROM golang:1.24

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN rm -f go.work go.work.sum

RUN [ "go", "test", "-v", "./..." ]
RUN go build -o /usr/bin/delphi ./cmd/delphi

FROM scratch
COPY --from=0 /usr/bin/delphi /bin/delphi

CMD ["delphi"]

