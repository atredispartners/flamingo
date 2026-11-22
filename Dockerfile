FROM golang:1.27 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /flamingo .

FROM gcr.io/distroless/static-debian12
COPY --from=build /flamingo /flamingo
ENTRYPOINT ["/flamingo"]
