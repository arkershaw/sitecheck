#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2009-2011 Andrew Kershaw

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
import os
import ssl
import datetime

try:
	#git clone https://github.com/rthalley/dnspython.git
	#git checkout -b python3 origin/python3
	#ln -s /opt/dnspython/dns /usr/lib/python3.2/site-packages/dns
	from dns.resolver import query, NoAnswer
except:
	_dns_available = False
else:
	_dns_available = True

try:
	from OpenSSL.crypto import load_certificate, FILETYPE_PEM
except:
	_ssl_available = False
else:
	_ssl_available = True

_relay_tests = [
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

_ipre = re.compile('(?:\d{1,3}\.){3}\d{1,3}')

class SocketHelper(object):
	BUFFER_SIZE = 4096

	def __init__(self, socket, end=None):
		self.socket = socket
		self.end = end

	def receiveall(self):
		res = []

		while True:
			r = self.socket.recv(SocketHelper.BUFFER_SIZE)
			if not r:
				break
			else:
				res.append(r.decode('ascii'))
				if self.end and r.endswith(self.end.encode()): break

		return ''.join(res)

	def sendall(self, data):
		self.socket.sendall((data + '\r\n').encode('ascii'))

	def sendandreceive(self, data):
		self.sendall(data)
		return self.receiveall()

class HostInfo(object):
	def __init__(self, address, record='A'):
		self.address = address

		try:
			self.name = socket.gethostbyaddr(address)[0]
		except socket.herror:
			self.name = None

		self.records = set(record)
		self.cert_expiry = None
		self.sslv2 = False

		try:
			cert = self._get_cert(ssl.PROTOCOL_SSLv2)
		except socket.error:
			# SSL not supported
			pass
		else:
			if cert: self.sslv2 = True
			if not cert: cert = self._get_cert(ssl.PROTOCOL_SSLv3)
			if not cert: cert = self._get_cert(ssl.PROTOCOL_TLSv1)
			if cert and _ssl_available:
				cert_data = load_certificate(FILETYPE_PEM, cert)
				expiry = cert_data.get_notAfter().decode('ascii')
				self.cert_expiry = datetime.datetime.strptime(expiry[:8], '%Y%m%d').date()

	def _get_cert(self, version):
		try:
			cert = ssl.get_server_certificate((self.address, 443), ssl_version=version)
		except ssl.SSLError:
			return None
		else:
			return cert

class DomainInfo(object):
	#Zone transfer
	#www record
	def __init__(self, domain):
		self.domain = domain
		#self._tld = domain.split('.')[-1]

		self.hosts = dict([(a[4][0], HostInfo(a[4][0])) for a in socket.getaddrinfo(domain, None)])

		self.spf = None
		self.name_servers = None
		self.domain_expiry = None

		if _dns_available:
			try:
				ms = [m.exchange.to_text().rstrip('.') for m in query(domain, 'MX')]
			except NoAnswer:
				ms = []

			for m in ms:
				if len(m) > 0 and not m == '0':
					for a in socket.getaddrinfo(m, None):
						ip = a[4][0]
						if ip in self.hosts:
							self.hosts[ip].records.update('MX')
						else:
							self.hosts[ip] = HostInfo(m, record='MX')

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
			whois = self._whois_lookup('.'.join(d))
			if whois:
				#Expiry Date.......... 2012-09-09
				#Renewal date:  04-Sep-2012
				#Expiration Date:07-Mar-2013 05:00:00 UTC
				#Record expires on 08-Aug-2012.

				ed = re.search('(?:renew|expir).*?(?P<alpha>\d{2}-\w{3}-\d{4})|(?P<numer>\d{4}-\d{2}-\d{2})', whois, re.IGNORECASE)
				if ed.group('numer'):
					self.domain_expiry = datetime.datetime.strptime(ed.group('numer'), '%Y-%m-%d').date()
				elif ed.group('alpha'):
					self.domain_expiry = datetime.datetime.strptime(ed.group('alpha'), '%d-%b-%Y').date()

				#nserver:      C.GTLD-SERVERS.NET 192.26.92.30
				#Name Server: NS.RACKSPACE.COM
				#Name Server:DNS1.USLEC.NET
				#Name Server: NS1.MSFT.NET

				#Name servers:
				#	dns0.easily.co.uk         212.53.77.27
				#	dns1.easily.co.uk         212.53.64.31

				#if self._tld == 'uk':
					#srv = re.search('name servers:\s*(.*)\n\n', whois, re.IGNORECASE | re.DOTALL)
					#if srv:
						#self.name_servers = [ns.group(1) for ns in re.finditer('\s*([^\s]+)\s*[^\s]+', srv.group(1), re.IGNORECASE)]
				#else:
					#self.name_servers = [ns.group(1) for ns in re.finditer('name server:\s*([^\s]+)', whois, re.IGNORECASE)]

				#whoisserver = re.search('whois: (.*)', self.whois_data)
				break
			else:
				d = d[1:]
				if len(d) == 1: break


	def _whois_lookup(self, domain):
		whois = None

		try:
			sock = socket.create_connection(('whois-servers.net', 43))
		except:
			raise
		else:
			s = SocketHelper(sock)
			whois = s.sendandreceive(domain)
			sock.close()

		if whois and not re.search(domain, whois, re.IGNORECASE):
			return None

		return whois

#SMTP can be 25 or 587
def test_relay(host, port=25, mail_from='from@example.com', rcpt_to='to@example.com', send=False):
	if _ipre.match(host):
		try:
			name = socket.gethostbyaddr(host)[0]
		except socket.herror:
			name = host
		addr = host
	else:
		name = host
		addr = socket.getaddrinfo(host, None)[0][4][0]

	fr = mail_from.rsplit('@', 1)
	to = rcpt_to.rsplit('@', 1)

	if name.endswith(to[1]):
		raise Exception('To address and host are on same domain')

	try:
		sock = socket.create_connection((host, port))
	except:
		raise Exception('Unable to connect to {}:{}'.format(host, port))
	else:
		s = SocketHelper(sock, end='\r\n')
		s.receiveall()
		s.sendandreceive('HELO {}'.format(fr[1]))

		relay = False
		failed = []
		for tst in _relay_tests:
			mf = tst[0].format(user=fr[0], domain=fr[1], hostname=name, address=addr)
			rt = tst[1].format(user=to[0], domain=to[1], hostname=name, address=addr)

			#print('{} -> {}'.format(mf, rt))

			s.sendandreceive('RSET')
			s.sendandreceive('MAIL FROM:{}'.format(mf))
			res = s.sendandreceive('RCPT TO:{}'.format(rt))

			if int(res[:3]) == 250:
				relay = True
				failed.append((mf, rt))

			if send:
				s.sendandreceive('DATA')
				s.sendandreceive('.')

		s.sendandreceive('QUIT')
		sock.close()
		return relay, failed

if __name__ == '__main__':
	from argparse import ArgumentParser
	parser = ArgumentParser()
	parser.add_argument('-r', '--relay', action='store_true', dest='relay', default=False)
	parser.add_argument('domain')
	args = parser.parse_args()

	today = datetime.date.today()

	if _ipre.match(args.domain):
		# IP address supplied instead of domain
		sys.exit('Please supply a domain')

	print('Checking: {}'.format(args.domain))

	d = DomainInfo(args.domain)

	if type(d.domain_expiry) == datetime.date:
		rem = (d.domain_expiry - today).days
		if rem < 0:
			print('Domain expired {}'.format(d.domain_expiry))
		else:
			print('Domain expires in {} days'.format(rem))
	elif d.domain_expiry:
		print('Domain expires on: {}'.format(d.domain_expiry))
	else:
		print('Unable to determine domain expiry date')

	if d.spf:
		print('SPF: {}'.format(d.spf))
	else:
		print('No SPF record found')

	print('Hosts:')
	for host in d.hosts:
		h = d.hosts[host]
		if h.name:
			print('\t{} ({})'.format(h.address, h.name))
		else:
			print('\t{} (No reverse DNS)'.format(h.address))

		if h.cert_expiry:
			rem = (h.cert_expiry - today).days
			if rem < 0:
				print('\t\tCertificate expired {}'.format(h.cert_expiry))
			else:
				print('\t\tCertificate expires in {} days'.format(rem))

		if h.sslv2:
			print('\t\tInsecure ciphers supported')

		if args.relay:
			relay, failed = test_relay(h.address)
			if relay:
				for f in failed:
					print('\t\tPossible open relay: {} -> {}'.format(f[0], f[1]))