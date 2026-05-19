FROM golang:1.26.3
COPY . /app
WORKDIR /app/cmd/coraza-wasm-registry
RUN CGO_ENABLED=0 go build
RUN git clone https://github.com/corazawaf/coraza-proxy-wasm.git /tmp/coraza-proxy-wasm

FROM golang:1.26

FROM tinygo/tinygo:0.41.1

FROM scratch

COPY --from=1 /usr/local/go /usr/local/go
COPY --from=0 /app/cmd/coraza-wasm-registry/coraza-wasm-registry /coraza-wasm-registry
COPY --from=0 /tmp/coraza-proxy-wasm /tmp/coraza-proxy-wasm
COPY --from=1 /usr/share/ /usr/share/
COPY --from=1 /etc/ssl/ /etc/ssl
COPY --from=2 /usr/local/tinygo /usr/local/tinygo

ENV PATH=/usr/local/go/bin/:/usr/local/tinygo/bin/
VOLUME /tmp/builds/ /tmp/wasmlib/
CMD ["/coraza-wasm-registry"]
