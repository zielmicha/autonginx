import argparse
import autonginx
import autonginx.certs
import subprocess
import glob
import collections

def renew(misc_dir, reload_cmd):
    hostnames = set(open(misc_dir + '/hostnames.txt', 'r').read().splitlines())
    bad_certs = set()
    for hostname in hostnames:
        cert = autonginx.certs.load_cert(misc_dir + '/certs/' + hostname + '.crt')
        if not autonginx._is_expiration_ok(cert) or not autonginx.certs.matches(cert, hostname):
            bad_certs.add(hostname)

    if not bad_certs:
        print('No expiring or incorrent certificates.')

    print('Incorrect or expiring certificates: %s' % ', '.join(bad_certs))
    os.makedirs(misc_dir + '/challenges')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--misc-dir', default='/etc/nginx/misc')
    parser.add_argument('--reload-cmd', default='nginx -s reload')
    ns = parser.parse_args()
    renew(ns.misc_dir, ns.reload_cmd)
