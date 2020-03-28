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
import re
import ssl
import datetime
import ipaddress
import subprocess
from urllib.parse import urlparse

# TODO: DNSBL, DNSSEC

try:
    from dns.resolver import query, NoAnswer, NoMetaqueries, NXDOMAIN
except ModuleNotFoundError:
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


def get_host(value):
    # Parse as a URL to get the host.
    if re.match('^[a-z1-9]*://', value, re.IGNORECASE):
        url = value
    else:
        url = 'http://{0}'.format(value)

    return urlparse(url).netloc


def get_name_and_address(value):
    host = get_host(value)

    if is_ip_address(host):
        address = host
        try:
            name = socket.gethostbyaddr(host)[0]
        except socket.herror:
            name = None
    else:
        name = host
        try:
            address = socket.getaddrinfo(host, None)[0][4][0]
        except socket.gaierror:
            address = None

    return name, address


def find_soa(domain):
    if _dns_available:
        parts = domain.split('.')
        while True:
            n = '.'.join(parts)
            try:
                soa = query(n, 'SOA')
                cn = soa.canonical_name.to_text()
                if cn == n:
                    return n
                else:
                    return find_soa(cn)
            except NoAnswer:
                parts = parts[1:]
                if len(parts) == 1:
                    return None
            except NXDOMAIN:
                return None
    else:
        return domain


class Host:
    def __init__(self, name_or_address, test_open_relays=False):
        self.name, self.address = get_name_and_address(name_or_address)

        if self.name and self.address:
            self.certificate = Certificate(self.name)
            domain = find_soa(self.name)
            self.domain = Domain(domain, test_open_relays)

            reverse_name, reverse_address = get_name_and_address(self.address)
            self.reverse_dns = (reverse_name is not None)
        else:
            self.certificate = None
            self.domain = None
            self.reverse_dns = None


class Certificate:
    def __init__(self, domain):
        self.version, self.expiry = get_certificate_details(domain)


class Domain:
    def __init__(self, domain, test_open_relays=False):
        self.domain = domain
        self.zone_transfer_allowed = zone_transfer_allowed(domain)
        self.has_spf = spf_exists(domain)
        self.expiry_date = get_expiry_date(domain)

        if test_open_relays:
            self.open_relays = get_open_relays(domain)
        else:
            self.open_relays = None


class OpenRelay:
    def __init__(self, host, port, failed_tests):
        self.host = host
        self.port = port
        self.failed_tests = failed_tests


class SocketHelper:
    def __init__(self, socket_object, end=None):
        self.buffer_size = 4096
        self.socket = socket_object
        self.end = end

    def receive_all(self):
        response = []

        while True:
            received_bytes = self.socket.recv(self.buffer_size)
            if not received_bytes:
                break
            else:
                response.append(received_bytes.decode('utf-8'))
                if self.end and received_bytes.endswith(self.end.encode()):
                    break

        return ''.join(response)

    def send_all(self, data):
        self.socket.send_all((data + '\r\n').encode('ascii'))

    def send_and_receive(self, data):
        self.send_all(data)
        return self.receive_all()


def get_certificate_details(host, port=443):
    name, address = get_name_and_address(host)

    def get_cert(protocol):
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.load_default_certs()
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.options &= ~ssl.OP_NO_SSLv3
        context.minimum_version = protocol
        context.maximum_version = protocol
        try:
            with socket.create_connection((address, port)) as sock:
                with context.wrap_socket(sock, server_hostname=name) as ssl_sock:
                    cert = ssl_sock.getpeercert()
                    version = ssl_sock.version()
                    expiry = None
                    if 'notAfter' in cert:
                        expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %X %Y %Z').date()
                    return version, expiry
        except (ConnectionRefusedError, ssl.SSLError):
            return None, None

    cert_version = None
    cert_expiry = None
    for p in _PROTOCOLS:
        try:
            cv, ce = get_cert(p)
            if ce and not cert_expiry:
                cert_expiry = ce
            if cv and not cert_version:
                cert_version = cv
            if cert_expiry and cert_version:
                break
        except (TimeoutError, socket.gaierror):
            break

    if cert_expiry or cert_version:
        return cert_version, cert_expiry
    else:
        return None, None


def who_is(domain):
    try:
        result = subprocess.run(["whois", domain.rstrip('.')], capture_output=True, text=True)
    except FileNotFoundError:
        return None
    else:
        result.check_returncode()
        return result.stdout


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
def get_expiry_date(domain):
    response = who_is(domain)
    if response:
        ed = re.search(r'(?:renew|expir).*?(?:(?P<alpha>\d{2}-\w{3}-\d{4})|(?P<num>\d{4}-\d{2}-\d{2}))',
                       response, re.IGNORECASE)
        if ed:
            if ed.group('num'):
                return datetime.datetime.strptime(ed.group('num'), '%Y-%m-%d').date()
            elif ed.group('alpha'):
                return datetime.datetime.strptime(ed.group('alpha'), '%d-%b-%Y').date()
            else:
                # TODO: Return string value if we can't parse the date?
                pass
    return None


def spf_exists(domain):
    if _dns_available:
        try:
            res = query(domain, 'TXT')
        except NoAnswer:
            pass
        except NXDOMAIN:
            pass
        else:
            txt = [r.to_text() for r in res]
            for r in txt:
                if r.startswith('v=spf'):
                    return True
            return False
    return None


def zone_transfer_allowed(domain):
    if _dns_available:
        try:
            query(domain, 'AXFR')
            return True
        except NoMetaqueries:
            return False
        except NXDOMAIN:
            pass
    return None


def get_name_servers(domain):
    if _dns_available:
        try:
            name_servers = [n.to_text().rstrip('.') for n in query(domain, 'NS')]
            return list(filter(lambda ns: len(ns) > 0 and ns != '0', name_servers))
        except NoAnswer:
            pass
        except NXDOMAIN:
            pass
    return []


def get_mail_servers(domain):
    if _dns_available:
        try:
            return [m.exchange.to_text().rstrip('.') for m in query(domain, 'MX')]
        except NoAnswer:
            pass
        except NXDOMAIN:
            pass
    return []


def get_open_relays(domain):
    mail_servers = get_mail_servers(domain)
    open_relays = []
    for mail_server in mail_servers:
        port = 25
        failed_tests = test_open_relay(mail_server, port)
        if failed_tests:
            open_relays.append(OpenRelay(mail_server, port, failed_tests))
        port = 587
        failed_tests = test_open_relay(mail_server, port)
        if failed_tests:
            open_relays.append(OpenRelay(mail_server, port, failed_tests))

    return open_relays


# SMTP can be 25 or 587
def test_open_relay(host, port=25, mail_from='from@example.com', rcpt_to='to@example.com', send=False):
    name, address = get_name_and_address(host)

    if not address:
        raise Exception('No address found for {0}'.format(host))

    fr = mail_from.rsplit('@', 1)
    to = rcpt_to.rsplit('@', 1)

    if name.endswith(to[1]):
        # If address and host are same domain then delivery should succeed
        raise Exception('To address and host are on same domain')

    try:
        sock = socket.create_connection((address, port))
    except ConnectionRefusedError:
        raise Exception('Unable to connect to {0}:{1}'.format(host, port))
    else:
        s = SocketHelper(sock, end='\r\n')
        s.receive_all()
        s.send_and_receive('HELO {0}'.format(fr[1]))

        failed_tests = []
        for tst in _RELAY_TESTS:
            mf = tst[0].format(user=fr[0], domain=fr[1], hostname=name, address=address)
            rt = tst[1].format(user=to[0], domain=to[1], hostname=name, address=address)

            # print('{0} -> {1}'.format(mf, rt))

            s.send_and_receive('RSET')
            s.send_and_receive('MAIL FROM:{0}'.format(mf))
            res = s.send_and_receive('RCPT TO:{0}'.format(rt))

            if int(res[:3]) == 250:
                failed_tests.append((mf, rt))

            if send:
                s.send_and_receive('DATA')
                s.send_and_receive('.')

        s.send_and_receive('QUIT')
        sock.close()

        return failed_tests


def domain_report(host: Host, message=print, warning=print):
    today = datetime.date.today()

    if host.domain:
        if host.domain.domain != host.name:
            message('Domain: {0}'.format(host.domain.domain))

        if host.domain.zone_transfer_allowed:
            warning('Zone transfer permitted.')

        if type(host.domain.expiry_date) == datetime.date:
            days_remaining = (host.domain.expiry_date - today).days
            if days_remaining < 0:
                warning('Domain expired on {0}.'.format(host.domain.expiry_date))
            else:
                message('Domain expires in {0} days.'.format(days_remaining))
        elif host.domain.expiry_date:
            message('Domain expires on: {0}.'.format(host.domain.expiry_date))
        else:
            warning('Unable to determine domain expiry date.')

        if not host.domain.has_spf:
            warning('No SPF record found.')
    else:
        warning('Unable to get domain info.')

    if not host.reverse_dns:
        warning('No reverse DNS.')

    if host.certificate:
        if host.certificate.expiry:
            days_remaining = (host.certificate.expiry - today).days
            if days_remaining < 0:
                warning('Certificate expired on {0}.'.format(host.certificate.expiry))
            else:
                message('Certificate expires in {0} days.'.format(days_remaining))

        if host.certificate.version in _INSECURE_CERT_VERSIONS:
            warning('Insecure certificate: {0}'.format(host.certificate.version))
    else:
        message('No certificate found.')

    if host.domain.open_relays:
        for open_relay in host.domain.open_relays:
            warning('Possible open relay in host {0}:{1} -> {2}'.format(
                open_relay.host, open_relay.port, open_relay.failed_tests[0])
            )


def __main():
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-r', '--relay', action='store_true', dest='relay', default=False)
    parser.add_argument('domain')
    args = parser.parse_args()

    host = Host(args.domain, args.relay)
    domain_report(host)


if __name__ == '__main__':
    __main()
