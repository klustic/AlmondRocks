FROM        alpine:latest AS builder
RUN         apk add --no-cache openssl
COPY        . /opt/arox
WORKDIR     /opt/arox
RUN         /bin/sh /opt/arox/bin/cert.sh

FROM        python:2.7.15-alpine
LABEL       maintainer="klustic@gmail.com"
COPY        --from=builder /opt/arox /opt/arox/
WORKDIR     /opt/arox
ENTRYPOINT  ["python", "arox.py", "-v", "server", "--cert", "/opt/arox/ssl/cert.pem", "--key", "/opt/arox/ssl/key.pem"]
