from . import certs
from . import fragments
import glob
import os
import datetime
import sys
import io
import subprocess

_certificates = []
_certificate_keys = {}
_certificate_by_hostname = {}
_sites = []
_misc_dir = None
_collisions = set()
_bad_hostnames = set()

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

def _check_collision(addr):
    if addr in _collisions:
        raise ValueError('address %s used twice' % (addr, ))
    _collisions.add(addr)

class Location:
    def __init__(self, prefix):
        self.location = prefix
        self.lines = []

    def proxy(self, *, location='/', to, headers=None, proxy_redirect=None):
        self.lines += fragments.proxy.splitlines()
        for k, v in (headers or {}).items():
            self.lines.append('proxy_set_header %s %s;' % (q(k), qval(v)))
        if proxy_redirect:
            self.lines.append('proxy_redirect %s %s;' % (q(proxy_redirect[0]), q(proxy_redirect[1])))

        self.lines.append('proxy_pass %s;' % q(to))

    def set_header(self, k, v):
        self.lines.append('add_header %s %s;' % (q(k), qval(v)))

    def return_code(self, code):
        self.lines.append('return %d;' % code)

    def files(self, path):
        self.lines.append('alias %s;' % q(path))

    def _generate(self):
        lines = [ 'location %s {' % q(self.location) ]
        lines += [ '    ' + line for line in self.lines ]
        lines.append('}')
        return lines

def q(s):
    if ' ' in s or '\n' in s:
        raise ValueError('whitespace in %r!' % s)
    return s

def qval(s):
    if ' ' in s:
        if '"' in s:
            raise ValueError('" in %r!' % s)
        return '"%s"' % s
    else:
        return s

class Site:
    def __init__(self, name, aliases=[], no_tls=False, auto_tls=True, tls_only=False,hsts=False):
        self.rewrites = []
        self.locations = []

        if type(name) is list:
            self.all_names = list(name)
            name = name[0]
        else:
            self.all_names = [name]

        self.name = name
        self.no_tls = no_tls
        self.auto_tls = auto_tls and not no_tls and not tls_only
        self.tls_only = tls_only
        self.hsts = hsts
        self.default_site = False

        assert not (self.tls_only and self.no_tls)

        for alias in aliases:
            redirect(alias, self.base_url, no_tls=no_tls, auto_tls=auto_tls, permanent=True)

        if self.auto_tls:
            redirect(name, self.base_url, no_tls=True, permanent=True)

        _sites.append(self)

    def rewrite(self, *, regex, to, permanent=False):
        s = 'rewrite %s %s' % (q(regex), q(to))
        if permanent:
            s += ' permanent'
        self.rewrites.append(s + ';')

    def proxy(self, *, location='/', **kwargs):
        self.location(location).proxy(**kwargs)

    def return_code(self, *, location='/', code):
        self.location(location).return_code(code)

    def redirect(self, *, to, strip_path=False, permanent=False):
        self.rewrite(regex='^', to=to.rstrip('/') + '$request_uri?', permanent=permanent)

    def location(self, *args, **kwargs):
        l = Location(*args, **kwargs)
        self.locations.append(l)
        return l

    def _generate(self):
        return '\n'.join(self._generate_one(name) for name in self.all_names )

    def _generate_one(self, name):
        lines = ['server_name %s;' % q(name)]
        if (self.no_tls or not self.auto_tls) and not self.tls_only:
            _check_collision((80, name))
            lines.append('listen 80;')
            lines += [
                'location /.well-known/acme-challenge/ {',
                '    alias %s/challenges/;' % q(_misc_dir),
                '}'
            ]

        if not self.no_tls:
            _check_collision((443, name))
            lines.append('listen 443 ssl;')
            crt, key = _certificate_by_hostname[name]
            lines.append('ssl_certificate %s;' % q(crt))
            lines.append('ssl_certificate_key %s;' % q(key))

        lines += self.rewrites
        for location in self.locations:
            lines += location._generate()

        return _make_server(lines)

    @property
    def base_url(self):
        if self.no_tls:
            return 'http://%s/' % self.name
        else:
            return 'https://%s/' % self.name

def _make_server(lines):
    return '    server {\n        %s\n    }' % '\n        '.join(lines)

class DefaultSite(Site):
    def __init__(self, certificate_for):
        Site.__init__(self, [certificate_for], auto_tls=False)

    def _generate(self):
        lines = ['listen 80 default_server;', 'listen 443 default_server;']

        try:
            crt, key = _certificate_by_hostname[self.name]
        except KeyError:
            pass
        else:
            lines.append('ssl_certificate %s;' % q(crt))
            lines.append('ssl_certificate_key %s;' % q(key))

        lines += self.rewrites
        for location in self.locations:
            lines += location._generate()

        return _make_server(lines)

def redirect(hostname, target_url, *, no_tls=False, permanent=False, auto_tls=True, tls_only=False):
    site = Site(hostname, no_tls=no_tls, auto_tls=auto_tls, tls_only=tls_only)
    site.redirect(to=target_url, permanent=permanent)

def _find_cert(hostname):
    matching = [ cert for cert in _certificates
                 if certs.matches(cert, hostname) ]

    matching.sort(key=lambda cert: cert.expiration)
    if not matching:
        return False, None

    cert = matching[-1]
    good = _is_expiration_ok(cert)
    return good, cert

def _is_expiration_ok(cert):
    return (cert.expiration - datetime.datetime.now()) > datetime.timedelta(days=30)

def _abs_symlink_force(src, dst):
    if os.path.islink(dst):
        os.unlink(dst)
    os.symlink(os.path.abspath(src), dst)

def _assign_certs(hostnames):
    certs_dir = _misc_dir + '/certs'
    if not os.path.exists(certs_dir):
        os.mkdir(certs_dir)

    global _bad_hostnames
    _bad_hostnames = set()

    for hostname in hostnames:
        good, cert = _find_cert(hostname)
        print(hostname, '->', cert.path if cert else None, 'ok' if good else 'not ok')
        if not good:
            _bad_hostnames.add(hostname)

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
    #_sites.sort(key=lambda s: reversed(s.name.split('.')))

    print(fragments.preamble, file=config)

    for site in _sites:
        print(site._generate(), file=config)
        print(file=config)

    print('}', file=config)

    return config.getvalue()

def _get_hostnames():
    hostnames = []
    for site in _sites:
        if not site.no_tls:
            hostnames += site.all_names

    return hostnames

def target_simple_file(filename, misc_dir):
    global _misc_dir
    _misc_dir = misc_dir
    if not os.path.exists(_misc_dir):
        os.mkdir(_misc_dir, 0o700)

    hostnames = _get_hostnames()
    _assign_certs(hostnames)
    value = _gen_config()
    with open(filename, 'w') as f:
        f.write(value)

    with open(_misc_dir + '/hostnames.txt', 'w') as f:
        f.write('\n'.join(hostnames) + '\n')

def target_debian():
    target_simple_file('/etc/nginx/nginx.conf', misc_dir='/etc/nginx/misc')
    subprocess.check_call('nginx -s reload', shell=True)
