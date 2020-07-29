#!/bin/bash
set -ex

# expects from environment:
#   CADIST, IGTF_CERTS_VERSION, OSG_CERTS_VERSION, OUR_CERTS_VERSION, PKG_NAME

mkdir "$CADIST"
cp CHANGES "$CADIST"
cd igtf-policy-installation-bundle-"$IGTF_CERTS_VERSION"

./configure --prefix="$CADIST" --with-profile=classic \
              --with-profile=mics --with-profile=slcs --with-profile=iota

make install

if [[ $PKG_NAME = osg-ca-certs ]]; then
  # OSG Specific stuff
  cd ../letsencrypt-certificates
  sed -i 's/\.txt//g' Makefile
  for x in *.txt; do mv "$x" "${x%.txt}"; done
  make check
  mv *.0 *.signing_policy *.pem *.crl_url "$CADIST"
fi

../mk-index.pl --version "$OUR_CERTS_VERSION" --dir "$CADIST" \
               --out "$CADIST/INDEX" -format 1 --style new    \
               --igtf_version "${IGTF_CERTS_VERSION}IGTFNEW"  \
               --osg_version  "${OSG_CERTS_VERSION}NEW"

cd "$CADIST"
sha256sum *.0 *.pem > cacerts_sha256sum.txt
chmod 644 *

