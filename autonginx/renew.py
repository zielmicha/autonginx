import argparse
import autonginx
import autonginx.certs
import subprocess
import glob
import collections
import os
import sys
import binascii

misc_dir = None
challenge_dir = None
auto_certificates = []

def _gen_key(path):
    out = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    subprocess.check_call(['openssl', 'genrsa', '4096'], stdout=out)
    os.close(out)

def _setup_acme():
    global challenge_dir

    challenge_dir = misc_dir + '/challenges'
    if not os.path.exists(challenge_dir): os.mkdir(challenge_dir)
    os.chmod(misc_dir, 0o755)
    os.chmod(challenge_dir, 0o755)

    account_key = misc_dir + '/autocerts/account.key'

    if not os.path.exists(account_key):
        print('Generating ACME account key...', file=sys.stderr)
        _gen_key(account_key)

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
    csr_path = misc_dir + '/autocerts/' + id + '.csr'
    config_path = misc_dir + '/autocerts/' + id + '.config'

    _gen_key(key_path)

    cn = hostnames[0]
    cert_config = open('/etc/ssl/openssl.cnf').read()
    cert_config += '\n[SAN]\nsubjectAltName=%s' % ','.join( 'DNS:%s' % hostname for hostname in hostnames )
    with open(config_path, 'w') as f:
        f.write(cert_config)

    cmd = ['openssl', 'req', '-new', '-sha256', '-key', key_path, '-subj', '/CN=%s' % cn, '-reqexts', 'SAN', '-config', config_path]

    f = open(csr_path, 'w')
    subprocess.check_call(cmd, stdout=f)
    f.close()
    os.unlink(config_path)

    intermediate = open('letsencrypt-x3-crosssigned.pem').read()
    account_key = misc_dir + '/autocerts/account.key'
    out = open(cert_path + '_tmp', 'w')
    subprocess.check_call(
        ['python', 'acme_tiny.py', '--account-key', account_key, '--csr', csr_path, '--acme-dir', misc_dir + '/challenges'],
        stdout=out)
    out.write('\n' + intermediate)
    out.close()
    os.rename(cert_path + '_tmp', cert_path)
    print('Certificate ready!')

def renew(misc_dir_, reload_cmd):
    global misc_dir
    misc_dir = misc_dir_

    auto_certs_dir = misc_dir + '/autocerts'

    if not os.path.exists(auto_certs_dir):
        os.mkdir(auto_certs_dir)

    os.chmod(auto_certs_dir, 0o700)

    def load_auto_certs():
        for name in os.listdir(auto_certs_dir):
            if name.endswith('.crt'):
                auto_certificates.append(autonginx.certs.load_cert(auto_certs_dir + '/' + name))

    load_auto_certs()

    hostnames = set(open(misc_dir + '/hostnames.txt', 'r').read().splitlines())
    bad_certs = set()
    for hostname in hostnames:
        if not _try_fix_cert(hostname):
            bad_certs.add(hostname)

    if not bad_certs:
        #print('No expiring or incorrent certificates.')
        return

    bad_certs = list(sorted(bad_certs, key=autonginx.hostname_sort_order))

    print('Incorrect or expiring certificates: %s' % ', '.join(bad_certs), file=sys.stderr)

    _setup_acme()
    _acme_make_cert(bad_certs)

    load_auto_certs()
    for hostname in hostnames:
        _try_fix_cert(hostname)

    subprocess.check_call(reload_cmd, shell=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--misc-dir', default='/etc/nginx/misc')
    parser.add_argument('--reload-cmd', default='nginx -s reload')
    ns = parser.parse_args()
    renew(ns.misc_dir, ns.reload_cmd)
