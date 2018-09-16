#!/bin/bash
set -e
val=$(dnssec-keygen -r /dev/urandom -a hmac-sha512 -b 512 -n USER -K . autonginx)
mkdir -p /etc/bind/keys/
cat > /etc/bind/keys/update.key <<EOF
key "update" {
    algorithm hmac-sha512;
    secret "$(awk '/^Key/{print $2}' $val.private)";
};
EOF
rm -f $val.{private,key}

echo "vars:"
echo 'export NSUPDATE_SERVER="localhost"'
echo 'export NSUPDATE_KEY="/etc/bind/keys/update.key"'
echo
echo "add to bind config:"
echo 'include "/etc/bind/keys/update.key";'
echo "add to zone config:"
echo 'update-policy {
        grant update subdomain example.com.;
      };'
echo
echo 'more on https://github.com/Neilpang/acme.sh/blob/master/dnsapi/README.md'
