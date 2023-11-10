# Helper script to facilitate generating two packages out of the certificate directory, one with
# the certs as-is ($ORIG_SUFFIX) and one with all sha1 certs replaced by trusted certs ($TRUST_SUFFIX)

# For each sha1-signed cert, create a duplicate trusted version to comply with EL9 default security policies
# Give the original and trusted versions separate file suffixes, and also generate a separate set of
# sha256sums for each set of certs

# Directory to modify certs in
CERT_DIR=$1
# File suffix to apply to unmodified sha1 certs
TRUST_SUFFIX=$2
# File suffix to apply to modified sha1 certs
ORIG_SUFFIX=$3

# util function to find every sha1-signed cert
find_sha1_certs() {
    for f in $(find $1 -name "*.pem"); do 
        if openssl x509 -noout -text < $f | grep -q "Signature Algorithm.*sha1"; then 
            echo $f
        fi
    done
}

pushd $CERT_DIR

# Rename the original sha256sum file that will be included with the package containing unmodified certs
mv cacerts_sha256sum.txt cacerts_sha256sum.txt.$ORIG_SUFFIX

# Then, find every sha1 certificate that will need to be changed to a trusted certificate
TO_CHANGE=$(find_sha1_certs .)

# change the certificate header/footer of SHA1-signed certificates to mark them as trusted
echo $TO_CHANGE | xargs sed -r -i.orig -e 's/(BEGIN|END) CERTIFICATE/\1 TRUSTED CERTIFICATE/'
# then append the originals to the certificate files so the files will contain both
for orig in *.orig; do
    new=${orig%.orig}
    (echo; cat "$orig" ) >> "$new"
    # Rename the original versions of each sha1 cert so they'll be included in the unmodified package
    mv "$orig" "$new.$ORIG_SUFFIX"
done

# Create a new sha256sum file for the package containing updated certs
sha256sum *.0 *.pem  > cacerts_sha256sum.txt.$TRUST_SUFFIX

# Rename the modified versions of each sha1 cert so they'll be included in the trusted package
for new in $TO_CHANGE; do
    mv "$new" "$new.$TRUST_SUFFIX"
done

popd
