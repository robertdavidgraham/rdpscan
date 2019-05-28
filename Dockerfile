FROM debian:latest as builder

COPY . /app
WORKDIR /app
RUN apt-get update && apt-get -y upgrade && apt-get install -y libssl-dev build-essential && gcc *.c -lssl -lcrypto -o rdpscan && make

FROM debian:stretch-slim
RUN apt-get update && apt-get -y upgrade && apt-get install -y libssl-dev
COPY --from=builder /app/rdpscan /app/rdpscan
ENTRYPOINT ["/app/rdpscan"]
