FROM        python:2.7.15-alpine3.6
MAINTAINER  "klustic"
RUN         apk add --no-cache openssl
COPY        . /opt/arox/
WORKDIR     /opt/arox
RUN         /bin/sh /opt/arox/bin/cert.sh
ENTRYPOINT  ["python", "arox.py", "-v", "server", "--cert", "/opt/arox/ssl/cert.pem", "--key", "/opt/arox/ssl/key.pem"]
