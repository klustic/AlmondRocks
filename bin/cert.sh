#!/bin/bash
ROOT=$(cd $(dirname $0) && pwd -P)
SSL=${ROOT}/../ssl

mkdir ${SSL} 2>/dev/null
openssl req -x509 -newkey rsa:2048 -keyout ${SSL}/key.pem -out ${SSL}/cert.pem -nodes -subj '/CN=AlmondRocks'
