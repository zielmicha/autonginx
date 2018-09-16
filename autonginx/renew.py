import argparse
import autonginx
import autonginx.certs
import subprocess
import glob
import collections
import os
import sys
import binascii
from typing import List

misc_dir = ''
reload_cmd = ''
auto_certificates = [] # type: List[autonginx.certs.Certificate]

ACME_SH = os.path.dirname(__file__) + '/../acme.sh/acme.sh'

def _find_auto_cert(hostname):
    for cert in auto_certificates:
        if autonginx._is_expiration_ok(cert) and autonginx.certs.matches(cert, hostname):
            return cert

    return None

def _try_fix_cert(hostname):
    cert_path = misc_dir + '/certs/' + hostname + '.crt'
    key_path = misc_dir + '/certs/' + hostname + '.key'
    cert = autonginx.certs.load_cert(cert_path)
    if autonginx._is_expiration_ok(cert) and autonginx.certs.matches(cert, hostname):
        return True

    ok_cert = _find_auto_cert(hostname)
    if not ok_cert:
        return False

    print('Found good automatic certificate for %s: %s' % (hostname, ok_cert.path), file=sys.stderr)
    ok_cert_path = ok_cert.path
    ok_key_path = ok_cert_path.rsplit('.', 1)[0] + '.key'

    autonginx._abs_symlink_force(ok_cert_path, cert_path)
    autonginx._abs_symlink_force(ok_key_path, key_path)
    return True

def _acme_make_cert(hostnames):
    print('Requesting certs for', hostnames)
    id = binascii.hexlify(os.urandom(8)).decode()
    key_path = misc_dir + '/autocerts/' + id + '.key'
    cert_path = misc_dir + '/autocerts/' + id + '.crt'

    challenge_dir = misc_dir + '/challenges'
    if not os.path.exists(challenge_dir): os.mkdir(challenge_dir)
    os.chmod(misc_dir, 0o755)
    os.chmod(challenge_dir, 0o755)

    cmd = [ACME_SH, '--issue']
    for hostname in hostnames: cmd += ['-d', hostname]
    cmd += ['-w', challenge_dir]

    subprocess.check_call(cmd)

    cmd = [ACME_SH, '--install-cert']
    for hostname in hostnames: cmd += ['-d', hostname]

    cmd += [
        '--key-file', key_path,
        '--fullchain-file', cert_path,
        '--reloadcmd', reload_cmd,
    ]
    subprocess.check_call(cmd)

def renew():
    auto_certs_dir = misc_dir + '/autocerts'

    # first, renew existing certificates with acme.sh
    subprocess.check_call([ACME_SH, '--cron'])

    if not os.path.exists(auto_certs_dir):
        os.mkdir(auto_certs_dir)

    os.chmod(auto_certs_dir, 0o700)

    def load_auto_certs():
        for name in os.listdir(auto_certs_dir):
            if name.endswith('.crt'):
                auto_certificates.append(autonginx.certs.load_cert(auto_certs_dir + '/' + name))

    load_auto_certs()

    hostnames = set(open(misc_dir + '/hostnames.txt', 'r').read().splitlines())
    bad_certs = list()
    for hostname in hostnames:
        if not _try_fix_cert(hostname) and '*' not in hostname:
            bad_certs.append(hostname)

    if not bad_certs:
        #print('No expiring or incorrent certificates.')
        return

    bad_certs.sort(key=autonginx.hostname_sort_order)

    print('Incorrect or expiring certificates: %s' % ', '.join(bad_certs), file=sys.stderr)

    _acme_make_cert(bad_certs)

    load_auto_certs()
    for hostname in hostnames:
        _try_fix_cert(hostname)

    subprocess.check_call(reload_cmd, shell=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--misc-dir', default='/etc/nginx/misc')
    parser.add_argument('--reload-cmd', default='killall -HUP nginx')
    ns = parser.parse_args()
    misc_dir = ns.misc_dir
    reload_cmd = ns.reload_cmd
    renew()
