# -*- coding: utf-8 -*-

# Copyright 2009 Andrew Kershaw

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

import threading, Queue, urlparse, urllib, os, re, time, sys
import sc_config
#from BeautifulSoup import BeautifulSoup, HTMLParseError
from hashlib import sha1

session = sc_config.sc_session()

class Request(object):
	def __init__(self, source, url, referrer):
		self.source = source
		self.referrer = referrer # Set before calling _set_url
		self._set_url(url)
		self.verb = ''
		self.redirects = 0
		self.timeouts = 0
		self.modules = {}
		self.postdata = []
		self.headers = {}

	def full_url(self, url, referrer):
		parts = urlparse.urlparse(url)
		full_url = url

		if len(parts.scheme) == 0:
			scheme = urlparse.urlparse(referrer).scheme
			if len(scheme) == 0:
				temp = urlparse.urljoin('%s://%s%s' % (session.scheme, session.domain, session.path), referrer)
			else:
				temp = referrer

			full_url = urlparse.urljoin(temp, url)

		#print url
		#print referrer
		#print full_url
		#print ''
		#if re.match('^http', parts.scheme, re.IGNORECASE) or len(parts.scheme) == 0:
			#temp = ''
			#if parts.netloc == '':
				#scheme = urlparse.urlparse(referrer).scheme
				#if len(scheme) == 0: scheme = session.scheme
				#temp += scheme + '://' + session.domain
				#if len(session.path) > 0: temp += session.path
				#full_url = urlparse.urljoin(temp, url)

		return full_url.replace(' ', '%20')

	def hash(self):
		m = sha1()
		qsin = urlparse.parse_qs(self.url.query)
		qsout = []
		keys = qsin.keys()
		keys.sort() # URL's with querystring parameters in different order are equivalent
		for k in keys:
			qsout.append((k, qsin[k][0]))
		hash_url = urlparse.urljoin(self.url_string, '?' + urllib.urlencode(qsout))
		m.update(hash_url.encode('utf-8'))

		if len(self.postdata) > 0:
			pdout = []
			keys = [x for x, y in self.postdata]
			keys.sort()
			for k in keys:
				for v in filter(lambda v: v[0] == k, self.postdata):
					pdout.append((k, v[1]))
			m.update(urllib.urlencode(pdout).encode('utf-8'))

		return m.hexdigest()

	def redirect(self, url):
		if self.redirects == 0:
			self.referrer = self.url_string
		self._set_url(url)
		self.redirects += 1

	def _set_url(self, url):
		#A lot or parsing and unparsing goes on so store both
		self.url_string = self.full_url(url, self.referrer)
		self.url = urlparse.urlparse(self.url_string)

class Response(object):
	def __init__(self, response, start_time):
		self.headers = dict(response.getheaders())
		self.content = response.read()
		end_time = time.time()
		self.time = end_time - start_time
		self.status = response.status
		self.message = response.reason
		self.version = response.version
		if self.status < 300 and self.headers['content-type'].startswith('text/html') and len(self.content) > 0:
			self.is_html = True
		else:
			self.is_html = False

class RequestQueue(Queue.Queue):
	def __init__(self):
		Queue.Queue.__init__(self)
		self._url_lock = threading.Lock()
		self.urls = {}

	def _is_valid(self, url):
		if url == None: return False
		if len(url) == 0: return False

		parts = urlparse.urlparse(url)
		for ignore in session.ignore_url:
			if parts.path.lower().endswith(ignore.lower()): return False

		ext = os.path.splitext(parts.path)[1][1:].lower()
		if ext in session.ignore_ext: return False

		if re.match('http', parts.scheme, re.IGNORECASE) or len(parts.scheme) == 0:
			return True
		else:
			return False

	def _put_url(self, source, url, referrer, block=True, timeout=None):
		if self._is_valid(url):
			req = Request(source, url, referrer)
			hc = req.hash()
			if not hc in self.urls:
				self.urls[hc] = True
				Queue.Queue.put(self, req, block, timeout)

	def put_url(self, source, url, referrer, block=True, timeout=None):
		self._url_lock.acquire()
		try:
			self._put_url(source, url, referrer, block, timeout)
		finally:
			self._url_lock.release()

	def put_urls(self, source, urls, referrer, block=True, timeout=None):
		self._url_lock.acquire()
		try:
			for url in urls:
				self._put_url(source, url, referrer, block, timeout)
		finally:
			self._url_lock.release()

	def put(self, request, block=True, timeout=None):
		if self._is_valid(request.url_string):
			self._url_lock.acquire()
			try:
				hc = request.hash()
				if not hc in self.urls:
					self.urls[hc] = True
					Queue.Queue.put(self, request, block, timeout)
			finally:
				self._url_lock.release()

	def from_list(self, requests, block=True, timeout=None):
		for r in requests:
			Queue.Queue.put(self, r, block, timeout)

	def retry(self, request):
		if request.timeouts >= session.max_retries:
			return False
		else:
			request.timeouts += 1
			Queue.Queue.put(self, request)
			return True

class OutputQueue(Queue.Queue):
	def __init__(self):
		Queue.Queue.__init__(self)
		self._batch_lock = threading.Lock()

	def put(self, module, value, block=True, timeout=None):
		if module == None:
			mod = 'sitecheck'
		else:
			mod = module[8:]

		if type(value) is str:
			Queue.Queue.put(self, (mod, value.encode('utf-8', 'replace') + '\n'), block, timeout)
		else:
			self._batch_lock.acquire()
			try:
				for val in value:
					Queue.Queue.put(self, (mod, val.encode('utf-8', 'replace') + '\n'), block, timeout)
			finally:
				self._batch_lock.release()

#def parse_html(html):
	#try:
		##BeautifulSoup treats the doctype as text (supposedly only if it is malformed)
		#ct = re.sub('<!DOCTYPE[^>]*>', '', html, re.IGNORECASE | re.MULTILINE | re.DOTALL)
		#doc = BeautifulSoup(ct, convertEntities=BeautifulSoup.HTML_ENTITIES)
		#err = None
	#except:
		#doc = None
		#ex = sys.exc_info()
		#err = str(ex[0]) + ' ' + str(ex[1])
	#return doc, err

_ensure_dir_lock = threading.Lock()
def ensure_dir(d):
	_ensure_dir_lock.acquire()
	try:
		if not os.path.exists(d):
			os.makedirs(d)
	finally:
		_ensure_dir_lock.release()

def get_arg(module, name, default):
	val = None
	args = session.modules.get(module[8:])
	if args: val = args.get(name)

	if not val:
		val = default
		OutputQueue.put(module, 'Argument: [' + name + '] not found - using default: [' + str(default) + ']')

	return val

def get_args(module):
	return session.modules[module[8:]]

RequestQueue = RequestQueue()
OutputQueue = OutputQueue()
cookie = ''
