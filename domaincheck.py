#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2009-2020 Andrew Kershaw

# This file is part of sitecheck.

# Sitecheck is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Sitecheck is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with sitecheck. If not, see <http://www.gnu.org/licenses/>.

import socket
import sys
import re
import ssl
import datetime
import ipaddress
import subprocess

try:
    from dns.resolver import query, NoAnswer, NoMetaqueries
except:
    _dns_available = False
else:
    _dns_available = True

_RELAY_TESTS = [
    ('<{user}@{domain}>', '<{user}@{domain}>'),
    ('<{user}>', '<{user}@{domain}>'),
    ('<>', '<{user}@{domain}>'),
    ('<{user}@{hostname}>', '<{user}@{domain}>'),
    ('<{user}@[{address}]>', '<{user}@{domain}>'),
    ('<{user}@{hostname}>', '<{user}%{domain}@{hostname}>'),
    ('<{user}@{hostname}>', '<{user}%{domain}@[{address}]>'),
    ('<{user}@{hostname}>', '<"{user}@{domain}">'),
    ('<{user}@{hostname}>', '<"{user}%{domain}">'),
    ('<{user}@{hostname}>', '<{user}@{domain}@{hostname}>'),
    ('<{user}@{hostname}>', '<"{user}@{domain}"@{hostname}>'),
    ('<{user}@{hostname}>', '<{user}@{domain}@[{address}]>'),
    ('<{user}@{hostname}>', '<@{hostname}:{user}@{domain}>'),
    ('<{user}@{hostname}>', '<@[{address}]:{user}@{domain}>'),
    ('<{user}@{domain}>', '<{domain}!{user}>'),
    ('<{user}@{domain}>', '<{domain}!{user}@{hostname}>'),
    ('<{user}@{domain}>', '<{domain}!{user}@[{address}]>')
]

_COMMON_NAMES = [
    'www',
    'ftp',
    'mail',
    'pop',
    'pop3',
    'smtp'
]

_INSECURE_CERT_VERSIONS = [
    'SSLv2', 'SSLv3'
]

_PROTOCOLS = [
    ssl.TLSVersion.SSLv3,
    ssl.TLSVersion.TLSv1,
    ssl.TLSVersion.TLSv1_1,
    ssl.TLSVersion.TLSv1_2,
    ssl.TLSVersion.TLSv1_3,
]


def is_ip_address(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def name_and_address(host):
    if is_ip_address(host):
        addr = host
        try:
            name = socket.gethostbyaddr(host)[0]
        except socket.herror:
            name = None
    else:
        name = host
        try:
            addr = socket.getaddrinfo(host, None)[0][4][0]
        except socket.gaierror:
            addr = None
    return name, addr


class SocketHelper:
    def __init__(self, socket, end=None):
        self.buffer_size = 4096
        self.socket = socket
        self.end = end

    def receive_all(self):
        res = []

        while True:
            r = self.socket.recv(self.buffer_size)
            if not r:
                break
            else:
                res.append(r.decode('utf-8'))
                if self.end and r.endswith(self.end.encode()):
                    break

        return ''.join(res)

    def send_all(self, data):
        self.socket.send_all((data + '\r\n').encode('ascii'))

    def send_and_receive(self, data):
        self.send_all(data)
        return self.receive_all()


def get_certificate_details(host):
    def get_cert(protocol):
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.load_default_certs()
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.options &= ~ssl.OP_NO_SSLv3
        context.minimum_version = protocol
        context.maximum_version = protocol
        try:
            with socket.create_connection((host, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssl_sock:
                    cert = ssl_sock.getpeercert()
                    cert_version = ssl_sock.version()
                    cert_expiry = None
                    if 'notAfter' in cert:
                        cert_expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %X %Y %Z')
                    return cert_version, cert_expiry

        except (ConnectionRefusedError, ssl.SSLError):
            return None, None

    cert_version = None
    cert_expiry = None
    for p in _PROTOCOLS:
        try:
            v, e = get_cert(p)
            if e and not cert_expiry:
                cert_expiry = e
            if v and not cert_version:
                cert_version = v
            if cert_expiry and cert_version:
                break
        except (TimeoutError, socket.gaierror):
            break
    return cert_version, cert_expiry


class HostInfo:
    def __init__(self, host, record='A'):
        self.name, self.address = name_and_address(host)
        self.records = {record}
        v, e = get_certificate_details(host)
        if not v and not e:
            v, e = get_certificate_details(self.name)
        self.cert_version = v
        self.cert_expiry = e


class DomainInfo:
    def __init__(self, domain):
        self.domain = domain
        try:
            addresses = socket.getaddrinfo(domain, None)
            self.hosts = dict([(a[4][0], HostInfo(a[4][0])) for a in addresses])
        except socket.gaierror:
            self.hosts = dict()

        for n in _COMMON_NAMES:
            r = '{0}.{1}'.format(n, domain)
            try:
                addrs = socket.getaddrinfo(r, None)
            except socket.gaierror:
                pass
            else:
                for a in addrs:
                    addr = a[4][0]
                    if addr in self.hosts:
                        self.hosts[addr].records.add('A ({0})'.format(r))
                    else:
                        self.hosts[addr] = HostInfo(addr, record='A ({0})'.format(r))

        self.spf = None
        self.name_servers = []
        self.domain_expiry = None
        self.zone_transfer = False

        if _dns_available:
            try:
                query(domain, 'AXFR')
                self.zone_transfer = True
            except NoMetaqueries:
                pass

            try:
                ms = [m.exchange.to_text().rstrip('.') for m in query(domain, 'MX')]
            except NoAnswer:
                ms = []

            for m in ms:
                if len(m) > 0 and not m == '0':
                    name, addr = name_and_address(m)
                    if not addr:
                        self.hosts[m] = HostInfo(m, record='MX')
                    elif addr in self.hosts:
                        self.hosts[addr].records.add('MX')
                    else:
                        self.hosts[addr] = HostInfo(m, record='MX')

            try:
                res = query(domain, 'TXT')
            except NoAnswer:
                pass
            else:
                txt = [r.to_text() for r in res]
                for r in txt:
                    if r.startswith('v=spf'):
                        self.spf = r

        d = domain.split('.')
        while True:
            if _dns_available:
                try:
                    self.name_servers = [n.to_text().rstrip('.') for n in query('.'.join(d), 'NS')]
                except NoAnswer:
                    pass

            whois = self._whois_lookup('.'.join(d))
            if whois:
                # Expiry Date.......... 2012-09-09
                # Renewal date:  04-Sep-2012
                # Expiration Date:07-Mar-2013 05:00:00 UTC
                # Record expires on 08-Aug-2012.
                
                # Linux
                # Registry Expiry Date: 2020-08-07T23:59:59.0Z
                # Expiry date:  04-Apr-2021
                # Windows
                # Registry Expiry Date: 2023-02-28T05:00:00Z
                # Registrar Registration Expiration Date: 2023-02-28T05:00:00Z
                # Expiry date:  04-Apr-2021

                ed = re.search(r'(?:renew|expir).*?(?:(?P<alpha>\d{2}-\w{3}-\d{4})|(?P<numer>\d{4}-\d{2}-\d{2}))',
                               whois.decode('ascii'), re.IGNORECASE)
                if ed:
                    if ed.group('numer'):
                        self.domain_expiry = datetime.datetime.strptime(ed.group('numer'), '%Y-%m-%d').date()
                    elif ed.group('alpha'):
                        self.domain_expiry = datetime.datetime.strptime(ed.group('alpha'), '%d-%b-%Y').date()

                # whoisserver = re.search('whois: (.*)', self.whois_data)
                break
            else:
                d = d[1:]
                if len(d) == 1:
                    break

    def _whois_lookup(self, domain):
        try:
            result = subprocess.run(["whois", domain], capture_output=True)
            return result.stdout
        except FileNotFoundError:
            return None


# SMTP can be 25 or 587
def test_relay(host, port=25, mail_from='from@example.com', rcpt_to='to@example.com', send=False):
    name, addr = name_and_address(host)

    if not addr:
        raise Exception('No address found for {0}'.format(host))

    fr = mail_from.rsplit('@', 1)
    to = rcpt_to.rsplit('@', 1)

    if name.endswith(to[1]):
        # If address and host are same domain then delivery should succeed
        raise Exception('To address and host are on same domain')

    try:
        sock = socket.create_connection((addr, port))
    except:
        # raise Exception('Unable to connect to {0}:{1}'.format(host, port))
        return False, []
    else:
        s = SocketHelper(sock, end='\r\n')
        s.receive_all()
        s.send_and_receive('HELO {0}'.format(fr[1]))

        relay = False
        failed = []
        for tst in _RELAY_TESTS:
            mf = tst[0].format(user=fr[0], domain=fr[1], hostname=name, address=addr)
            rt = tst[1].format(user=to[0], domain=to[1], hostname=name, address=addr)

            # print('{0} -> {1}'.format(mf, rt))

            s.send_and_receive('RSET')
            s.send_and_receive('MAIL FROM:{0}'.format(mf))
            res = s.send_and_receive('RCPT TO:{0}'.format(rt))

            if int(res[:3]) == 250:
                relay = True
                failed.append((mf, rt))

            if send:
                s.send_and_receive('DATA')
                s.send_and_receive('.')

        s.send_and_receive('QUIT')
        sock.close()
        return relay, failed


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-r', '--relay', action='store_true', dest='relay', default=False)
    parser.add_argument('domain')
    args = parser.parse_args()

    today = datetime.date.today()

    if is_ip_address(args.domain):
        # IP address supplied instead of domain
        sys.exit('Please supply a domain')

    print('Checking: {0}'.format(args.domain))

    try:
        d = DomainInfo(args.domain)
    except socket.gaierror:
        sys.exit('Domain not found: {0}'.format(args.domain))

    print('Nameservers:')
    for ns in d.name_servers:
        print('\t{0}'.format(ns))

    if d.zone_transfer:
        print('Zone Transfer Permitted')

    if type(d.domain_expiry) == datetime.date:
        rem = (d.domain_expiry - today).days
        if rem < 0:
            print('Domain expired {0}'.format(d.domain_expiry))
        else:
            print('Domain expires in {0} days'.format(rem))
    elif d.domain_expiry:
        print('Domain expires on: {0}'.format(d.domain_expiry))
    else:
        print('Unable to determine domain expiry date')

    if d.spf:
        print('SPF: {0}'.format(d.spf))
    else:
        print('No SPF record found')

    print('Hosts:')
    for host in d.hosts:
        h = d.hosts[host]

        print('\t{0}'.format(h.address))

        if h.name:
            print('\t\tReverse DNS: {0}'.format(h.name))
        else:
            print('\t\t No reverse DNS')

        print('\t\tRecords: {0}'.format(', '.join(h.records)))

        if h.cert_expiry:
            rem = (h.cert_expiry - today).days
            if rem < 0:
                print('\t\tCertificate expired {0}'.format(h.cert_expiry))
            else:
                print('\t\tCertificate expires in {0} days'.format(rem))

        if h.cert_version in _INSECURE_CERT_VERSIONS:
            print('\t\tInsecure ciphers supported')

        if args.relay:
            relay, failed = test_relay(h.address, port=25)
            if relay:
                for f in failed:
                    print('\t\tPossible open relay (port 25): {0} -> {1}'.format(f[0], f[1]))

            relay, failed = test_relay(h.address, port=587)
            if relay:
                for f in failed:
                    print('\t\tPossible open relay (port 587): {0} -> {1}'.format(f[0], f[1]))
