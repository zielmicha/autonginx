from . import certs
from . import fragments
import glob
import os
import datetime
import sys
import io

_certificates = []
_certificate_keys = {}
_certificate_by_hostname = {}
_sites = []
_misc_dir = None

def load_certificate(path, key=None):
    crt = certs.load_cert(path)
    if not key:
        key = path.rsplit('.', 1)[0] + '.key'
    if not os.path.exists(key):
        print('Warning: key file for %r not found (tried %r)' % (path, key))
        return

    _certificates.append(crt)
    _certificate_keys[path] = key

def find_certificates(pattern):
    matches = glob.glob(pattern)
    if not matches:
        print('Warning: no certificates found (%r)' % pattern, file=sys.stderr)
    for path in matches:
        load_certificate(path)

class Location:
    def __init__(self, prefix):
        self.location = prefix
        self.lines = []

    def proxy(self, *, location='/', to):
        self.lines += fragments.proxy.splitlines()
        self.lines.append('proxy_pass %s;' % q(to))

    def _generate(self):
        lines = [ 'location %s {' % q(self.location) ]
        lines += [ '    ' + line for line in self.lines ]
        lines.append('}')
        return lines

def q(s):
    if ' ' in s or '\n' in s:
        raise ValueError('whitespace in %r!' % s)
    return s

class Site:
    def __init__(self, name, aliases=[], no_tls=False, auto_tls=True, hsts=False):
        self.rewrites = []
        self.locations = []

        self.name = name
        self.no_tls = no_tls
        self.auto_tls = auto_tls
        self.hsts = hsts

        for alias in aliases:
            redirect(alias, self.base_url, no_tls=no_tls)

        if self.auto_tls and not self.no_tls:
            redirect(name, self.base_url, no_tls=True, permanent=True)

        _sites.append(self)

    def rewrite(self, *, regex, to, permanent=False):
        s = 'rewrite %s %s' % (q(regex), q(to))
        if permanent:
            s += ' permanent'
        self.rewrites.append(s + ';')

    def proxy(self, *, location='/', **kwargs):
        self.location(location).proxy(**kwargs)

    def redirect(self, *, to, strip_path=False, permanent=False):
        self.rewrite(regex='^', to=to.rstrip('/') + '$request_uri?', permanent=permanent)

    def location(self, *args, **kwargs):
        l = Location(*args, **kwargs)
        self.locations.append(l)
        return l

    def _generate(self):
        lines = ['server_name %s;' % q(self.name)]
        if self.no_tls:
            lines.append('listen 80;')
        else:
            lines.append('listen 443 ssl;')
            crt, key = _certificate_by_hostname[self.name]
            lines.append('ssl_certificate %s;' % q(crt))
            lines.append('ssl_certificate_key %s;' % q(key))

        lines += self.rewrites
        for location in self.locations:
            lines += location._generate()

        return '    server {\n        %s\n    }' % '\n        '.join(lines)

    @property
    def base_url(self):
        if self.no_tls:
            return 'http://%s/' % self.name
        else:
            return 'https://%s/' % self.name

def redirect(hostname, target_url, *, no_tls=False, permanent=False):
    site = Site(hostname, no_tls=no_tls)
    site.redirect(to=target_url, permanent=permanent)

def _find_cert(hostname):
    matching = [ cert for cert in _certificates
                 if certs.matches(cert, hostname) ]

    matching.sort(key=lambda cert: cert.expiration)
    if not matching:
        return False, None

    cert = matching[-1]
    good = (cert.expiration - datetime.datetime.now()) > datetime.timedelta(days=30)
    return good, cert

def _abs_symlink_force(src, dst):
    if os.path.islink(dst):
        os.unlink(dst)
    os.symlink(os.path.abspath(src), dst)

def _assign_certs():
    hostnames = []
    for site in _sites:
        if not site.no_tls:
            hostnames.append(site.name)

    certs_dir = _misc_dir + '/certs'
    if not os.path.exists(certs_dir):
        os.mkdir(certs_dir)

    bad_hostnames = set()

    for hostname in hostnames:
        good, cert = _find_cert(hostname)
        print(hostname, '->', cert.path if cert else None, 'ok' if good else 'not ok')
        if not good:
            bad_hostnames.add(hostname)

        if not cert:
            if not _certificates:
                raise ValueError('no certificates found at all, but TLS requested')

            cert = _certificates[0]

        if '/' in hostname:
            raise ValueError('bad hostname %r' % hostname)

        path = cert.path
        key_path = os.path.abspath(certs_dir + '/' + hostname + '.key')
        crt_path = os.path.abspath(certs_dir + '/' + hostname + '.crt')
        _abs_symlink_force(path, crt_path)
        _abs_symlink_force(_certificate_keys[path], key_path)

        _certificate_by_hostname[hostname] = (crt_path, key_path)

def _gen_config():
    config = io.StringIO()
    _sites.sort(key=lambda s: s.name)

    print(fragments.preamble, file=config)

    for site in _sites:
        print(site._generate(), file=config)
        print(file=config)

    print('}', file=config)

    return config.getvalue()

def target_simple_file(filename, misc_dir):
    global _misc_dir
    _misc_dir = misc_dir
    if not os.path.exists(_misc_dir):
        os.mkdir(_misc_dir, 0o700)

    _assign_certs()
    value = _gen_config()
    with open(filename, 'w') as f:
        f.write(value)
