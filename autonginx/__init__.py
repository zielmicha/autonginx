from . import certs
from . import fragments
import glob
import os
import datetime
import sys
import io
import subprocess
from typing import List, Dict, Set

_certificates = [] # type: List[certs.Certificate]
_certificate_keys = {}
_certificate_by_hostname = {} # type: Dict[str, certs.Certificate]
_sites = []
_misc_dir = None
_collisions = set() # type: Set
_bad_hostnames = set() # type: Set[str]

separate_logs = True

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

def find_acmesh_certificates():
    keys = glob.glob(os.path.expanduser('~/.acme.sh/*/*.key'))
    for key in keys:
        crt = os.path.dirname(key) + '/fullchain.cer'
        if os.path.exists(crt):
            load_certificate(crt, key=key)

def _check_collision(addr):
    if addr in _collisions:
        raise ValueError('address %s used twice' % (addr, ))
    _collisions.add(addr)

class Location:
    def __init__(self, prefix):
        self.location = prefix
        self.lines = [] # type: List[str]
        self.raw = [] # type: List[str]

    def proxy(self, *, location='/', to, headers=None, proxy_redirect=None):
        self.lines += fragments.proxy.splitlines()
        for k, v in (headers or {}).items():
            self.lines.append('proxy_set_header %s %s;' % (q(k), qval(v)))

        self.lines.append('proxy_pass %s;' % q(to))

        if proxy_redirect:
            if proxy_redirect is True:
                self.lines.append('proxy_redirect default;')
            else:
                self.lines.append('proxy_redirect %s %s;' % (q(proxy_redirect[0]), q(proxy_redirect[1])))

    def set_header(self, k, v):
        self.lines.append('add_header %s %s;' % (q(k), qval(v)))

    def return_code(self, code):
        self.lines.append('return %d;' % code)

    def files(self, path, allow_index=False):
        self.lines.append('alias %s;' % q(path))
        if allow_index:
            self.lines.append('autoindex on;')

    def _generate(self):
        lines = [ 'location %s {' % q(self.location) ]
        lines += [ '    ' + line for line in self.lines + self.raw ]
        lines.append('}')
        return lines

    def rewrite(self, *, regex, to, permanent=False, redirect=False):
        s = 'rewrite %s %s' % (q(regex), q(to))
        if permanent:
            s += ' permanent'
        if redirect: s += ' redirect'
        self.lines.append(s + ';')

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
    def __init__(self, name, aliases=[], no_tls=False, auto_tls=True, tls_only=False, hsts=False, auto_cert=True, log_name=None):
        self.rewrites = []
        self.locations = []
        self.locations_by_key = {}
        self.raw = []

        if type(name) is list:
            self.all_names = list(name)
            name = name[0]
        else:
            self.all_names = [name]

        self.name = name
        self.log_name = log_name or name
        self.no_tls = no_tls
        self.auto_tls = auto_tls and not no_tls and not tls_only
        self.tls_only = tls_only
        self.hsts = hsts
        self.default_site = False
        self.auto_cert = auto_cert

        assert not (self.tls_only and self.no_tls)

        for alias in aliases:
            redirect(alias, self.base_url, log_name=name, no_tls=no_tls, auto_tls=auto_tls, permanent=True, auto_cert=auto_cert)

        if self.auto_tls:
            redirect(name, self.base_url, log_name=name, no_tls=True, permanent=True, auto_cert=auto_cert)

        _sites.append(self)

    def rewrite(self, *, location='/', **kwargs):
        self.location(location).rewrite(**kwargs)

    def proxy(self, *, location='/', **kwargs):
        self.location(location).proxy(**kwargs)

    def return_code(self, *, location='/', code):
        self.location(location).return_code(code)

    def redirect(self, *, to, strip_path=False, permanent=False):
        self.rewrite(regex='^', to=to.rstrip('/') + '$request_uri?', permanent=permanent)

    def location(self, prefix):
        key = (prefix, )
        if key not in self.locations_by_key:
            l = Location(prefix=prefix)
            self.locations.append(l)
            self.locations_by_key[key] = l

        return self.locations_by_key[key]

    def _generate(self):
        return '\n'.join(self._generate_one(name) for name in self.all_names )

    def _generate_one(self, name):
        lines = ['server_name %s;' % q(name)]
        lines += self.raw
        if (self.no_tls or not self.auto_tls) and not self.tls_only:
            _check_collision((80, name))
            lines.append('listen 80;')

            lines += [
                'location /.well-known/acme-challenge/ {',
                '    root %s/challenges/;' % q(_misc_dir),
                '}'
             ]

        if separate_logs:
            lines += [
                'access_log /var/log/nginx/%s_access.log main;' % q(self.log_name),
                'error_log /var/log/nginx/%s_error.log;' % q(self.log_name),
            ]

        if not self.no_tls:
            _check_collision((443, name))
            lines.append('listen 443 ssl;')
            crt, key = _certificate_by_hostname[name]
            lines.append('ssl_certificate %s;' % q(crt))
            lines.append('ssl_certificate_key %s;' % q(key))

        if self.hsts:
            lines.append('add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";')

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

def redirect(hostname, target_url, *, log_name=None, no_tls=False, permanent=False, auto_tls=True, tls_only=False, auto_cert=True):
    site = Site(hostname, no_tls=no_tls, auto_tls=auto_tls, tls_only=tls_only, auto_cert=auto_cert, log_name=log_name)
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
        #print(hostname, '->', cert.path if cert else None, 'ok' if good else 'not ok')
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

def _get_hostnames(need_auto_cert=False):
    hostnames = []
    for site in _sites:
        if need_auto_cert and not site.auto_cert:
            continue
        if not site.no_tls:
            hostnames += site.all_names

    return hostnames

def hostname_sort_order(k):
    return (k.count('.'), list(reversed(k.split('.'))))

def target_simple_file(filename, misc_dir):
    global _misc_dir
    _misc_dir = misc_dir
    if not os.path.exists(_misc_dir):
        os.mkdir(_misc_dir, 0o700)

    find_acmesh_certificates()
    find_certificates(_misc_dir + '/autocerts/*.crt')

    hostnames = _get_hostnames()
    _assign_certs(hostnames)
    value = _gen_config()
    with open(filename, 'w') as f:
        f.write(value)

    auto_cert_hostnames = _get_hostnames(need_auto_cert=True)
    auto_cert_bad_hostnames = [ hostname for hostname in _bad_hostnames if hostname in auto_cert_hostnames ]

    with open(_misc_dir + '/hostnames.txt', 'w') as f:
        f.write('\n'.join(auto_cert_hostnames) + '\n')

    if auto_cert_bad_hostnames:
        print('You have several domains without TLS certificates configured for them:', file=sys.stderr)
        print('\t', ' '.join(sorted(auto_cert_bad_hostnames, key=hostname_sort_order)), file=sys.stderr)
        print('Run ./renew.sh to request Let\'s Encrypt certificates for them.', file=sys.stderr)

def target_debian():
    target_simple_file('/etc/nginx/nginx.conf', misc_dir='/etc/nginx/misc')
    subprocess.check_call('nginx -s reload', shell=True)
