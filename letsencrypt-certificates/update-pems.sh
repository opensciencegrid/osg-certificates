#!/bin/bash
set -e

# the Makefile for https://github.com/cilogon/letsencrypt-certificates
# downloads the following pem files.  We provide them here to avoid an
# external download dependency at build-time.

curl -O https://letsencrypt.org/certs/isrgrootx1.pem
curl -O https://letsencrypt.org/certs/letsencryptauthorityx3.pem
curl -O https://letsencrypt.org/certs/letsencryptauthorityx4.pem
curl -O https://letsencrypt.org/certs/trustid-x3-root.pem
