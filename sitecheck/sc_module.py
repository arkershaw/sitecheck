# -*- coding: utf-8 -*-
import threading, Queue, urlparse, urllib, os, hashlib, re, time
import sc_config
from BeautifulSoup import BeautifulSoup, HTMLParseError

session = sc_config.sc_session()

class Request(object):
	def __init__(self, source, url, referrer):
		self.source = source
		#self.url_string = self.full_url(url, referrer)
		#self.url = urlparse.urlparse(self.url_string)
		self.referrer = referrer
		self._set_url(url)
		self.verb = ''
		self.redirects = 0
		self.timeouts = 0
		self.modules = {} #session.modules
		self.postdata = {}
		self.headers = {}

	def full_url(self, url, referrer):
		parts = urlparse.urlparse(url)
		full_url = url
		if re.match('http', parts.scheme, re.IGNORECASE) or len(parts.scheme) == 0:
			temp = ''
			if parts.netloc == '':
				scheme = urlparse.urlparse(referrer).scheme
				if len(scheme) == 0: scheme = 'http'
				temp += scheme + '://' + session.domain
				if len(session.path) > 0: temp += session.path
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
			keys = self.postdata.keys()
			keys.sort()
			for k in keys:
				pdout.append((k, self.postdata[k][0]))
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
		if self.status < 300 and self.headers['content-type'] == 'text/html' and len(self.content) > 0:
			self.is_html = True
		else:
			self.is_html = False

class RequestQueue(Queue.Queue):
	def __init__(self):
		Queue.Queue.__init__(self)
		self._url_lock = threading.Lock()
		self.urls = {}

	def _put_url(self, source, url, referrer, block=True, timeout=None):
		if url == None: return
		if len(url) == 0: return

		parts = urlparse.urlparse(url)
		ext = os.path.splitext(parts.path)[1][1:].lower()
		if not ext in session.ignore_ext:
			if re.match('http', parts.scheme, re.IGNORECASE) or len(parts.scheme) == 0:
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
		if re.match('http', request.url.scheme, re.IGNORECASE) or len(request.url.scheme) == 0:
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
			OutputQueue.put(None, 'Exceeded max_retries for: [%s]' % request.url_string)
		else:
			request.timeouts += 1
			Queue.Queue.put(self, request)

class OutputQueue(Queue.Queue):
	def put(self, module, value, block=True, timeout=None):
		if module == None:
			mod = 'sitecheck'
		else:
			mod = module[8:]
		Queue.Queue.put(self, (mod, value.encode('utf-8', 'replace') + '\n'), block, timeout)

RequestQueue = RequestQueue()
OutputQueue = OutputQueue()

def parse(html):
	try:
		#BeautifulSoup treats the doctype as text
		ct = re.sub('<!DOCTYPE[^>]*>', '', html, re.IGNORECASE | re.MULTILINE | re.DOTALL)
		doc = BeautifulSoup(ct, convertEntities=BeautifulSoup.HTML_ENTITIES)
	except HTMLParseError:
		doc = None
	except:
		#File "/usr/lib/python2.6/HTMLParser.py", line 107, in feed
		#self.rawdata = self.rawdata + data
		#TypeError: cannot concatenate 'str' and 'NoneType' objects
		doc = None
	return doc

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
	if session.modules.has_key(module[8:]):
		args = session.modules[module[8:]]
		if args:
			if args.has_key(name):
				val = args[name]
	if val == None:
		val = default
		OutputQueue.put(module, 'Argument: [' + name + '] not found - using default: [' + str(default) + ']')
	return val

def get_args(module):
	return session.modules[module[8:]]
