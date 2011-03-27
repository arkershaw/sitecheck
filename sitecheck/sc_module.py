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

import threading, Queue, urlparse, urllib, os, re, time, sys, hashlib, htmlentitydefs
import sc_config

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

		return full_url.replace(' ', '%20')

	def hash(self):
		m = hashlib.sha1()
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
		temp = response.read()
		if temp:
			self.content = unicode(temp, errors='replace')
		else:
			self.content = ''
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
		self.ignore_protocols = ['mailto:', 'javascript:']
		Queue.Queue.__init__(self)
		self._url_lock = threading.Lock()
		self.urls = {}

	def is_valid(self, url):
		if url == None: return False
		if len(url) == 0: return False
		if url.startswith('#') or url.lower() in self.ignore_protocols: return False
		
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
		if self.is_valid(url):
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
		if self.is_valid(request.url_string):
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

		if isinstance(value, basestring):
			Queue.Queue.put(self, (mod, value), block, timeout)
		else:
			self._batch_lock.acquire()
			try:
				for val in value:
					Queue.Queue.put(self, (mod, val), block, timeout)
			finally:
				self._batch_lock.release()

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

class HtmlHelper(object):
	def __init__(self, document):
		self.document = document
		self.flags = re.IGNORECASE | re.DOTALL # | re.MULTILINE

	def get_element(self, element):
		rx = re.compile(r'<\s*%s\b.*?>' % element, self.flags)
		mtchs = rx.finditer(self.document)
		for m in mtchs:
			e = HtmlHelper(m.group(0))
			yield e

	def get_attribute(self, attribute, element=None):
		# Test strings:
		# < form name = name action = test 1 method = get>
		# < form name = "name" action = "test 1" method = "get">

		if element:
			rx = re.compile(r'<\s*(?P<element>%s)\s[^>]*?(?<=\s)%s\s*=\s*(?P<quoted>")?(?P<attr>.*?)(?(quoted)"|[\s>])' \
				% (element, attribute), self.flags)
		else:
			rx = re.compile(r'<\s*(?P<element>[^\s>]+)\s[^>]*?(?<=\s)%s\s*=\s*(?P<quoted>")?(?P<attr>.*?)(?(quoted)"|[\s>])' \
				% attribute, self.flags)

		mtchs = rx.finditer(self.document)
		for m in mtchs:
			yield (m.group('element'), attribute, m.group('attr'))

	def get_text(self, element=None):
		if element:
			rx = re.compile(r'<\s*%s\b[^>]*?>(?P<text>[^<]+?\w[^<]+?)(?:<|$)' % element, self.flags)
		else:
			rx = re.compile(r'(?:^[^<]|>)(?P<text>[^<]+?\w[^<]+?)(?:<|$)', self.flags)

		mtchs = rx.finditer(self.document)
		for m in mtchs:
			yield m.group('text')

	def strip_element(self, elements):
		names = elements
		if type(elements) is str:
			names = (elements)

		for e in names:
			self.document = re.sub(r'<\s*%s\b.*?>.*?<\s*/\s*%s\s*>' % (e, e), \
				'', self.document, flags=self.flags)

	def strip_comments(self):
		self.document = re.sub(r'<\s*!\s*-\s*-.*?-\s*-\s*>', '', self.document, flags=self.flags)

	def get_comments(self):
		rx = re.compile(r'<\s*!\s*-\s*-(?P<comment>.*?)-\s*-\s*>', self.flags)

		mtchs = rx.finditer(self.document)
		for m in mtchs:
			yield m.group('comment')

#http://effbot.org/zone/re-sub.htm#unescape-html
def html_decode(text):
    def fixup(m):
        text = m.group(0)
        if text[:2] == "&#":
            try:
                if text[:3] == "&#x":
                    return unichr(int(text[3:-1], 16))
                else:
                    return unichr(int(text[2:-1]))
            except ValueError:
                pass
        else:
            try:
                text = unichr(htmlentitydefs.name2codepoint[text[1:-1]])
            except KeyError:
                pass
        return text
    return re.sub("&#?\w+;", fixup, text)

RequestQueue = RequestQueue()
OutputQueue = OutputQueue()
cookie = ''
