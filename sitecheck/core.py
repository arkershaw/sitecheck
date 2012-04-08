# -*- coding: utf-8 -*-

# Copyright 2009-2012 Andrew Kershaw

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

import sys
import os
import threading
import time
import http.client
import urllib.request
import urllib.parse
import urllib.error
import http.cookies
import socket
import queue
import datetime
import re
import hashlib
import uuid
import pickle
import html.entities
import copy

from sitecheck.reporting import OutputQueue, ReportData, FlatFile

VERSION = '1.5'

class SiteCheck(object):
	def __init__(self, root_path):
		self.root_path = root_path
		self.session = None
		self.output_queue = OutputQueue()
		self.request_queue = None

		self._started = False
		self._threads = []
		self._resume_data = None

	def set_session(self, session):
		if self._started: raise SiteCheckStartedException()

		self.session = session
		self.request_queue = RequestQueue(session)

		if not hasattr(self.session, '_debug'):
			self.session._debug = False

	def initialise_module(self, module):
		try:
			if not hasattr(module, 'initialise'): raise Exception('Initialise method not defined')
			if not hasattr(module, 'process'): raise Exception('Process method not defined')

			module.initialise(self)

			if not self._resume_data:
				if hasattr(module, 'begin'): module.begin()
		except:
			if self.session._debug: raise
			self.output_queue.put_message('ERROR: {0}'.format(str(sys.exc_info()[1])), module.source)
			return False
		else:
			return True

	def is_complete(self):
		if self.session == None: raise SessionNotSetException()

		cmpl = False
		if self.request_queue.empty():
			cmpl = True
			for t in self._threads:
				if t.active:
					cmpl = False

		return cmpl

	def begin(self):
		if self.session == None: raise SessionNotSetException()
		if self._started: raise SiteCheckStartedException()

		self._started = True

		if not self.session.domain[-1] == '/' and len(os.path.splitext(self.session.domain)[1]) == 0:
			self.session.domain = self.session.domain + '/'

		if not re.match('^http', self.session.domain, re.IGNORECASE):
			self.session.domain = 'http://{0}'.format(self.session.domain)

		self.root_path = append(self.root_path, os.sep)
		self.session.output = append(self.session.output, os.sep)

		if len(urllib.parse.urlparse(self.session.domain).netloc) == 0: raise Exception('Invalid domain')

		# Organise file type sets
		self.session.include_ext = self.session.include_ext.difference(self.session.ignore_ext)
		self.session.test_ext = self.session.test_ext.difference(self.session.ignore_ext.union(self.session.include_ext))

		# Start output thread
		if not hasattr(self.session, 'report'):
			self.session.report = FlatFile()
		self.session.report.initialise(self)
		self.session.report.setDaemon(True)
		self.session.report.start()

		# Initialise modules
		self.session.modules = [m for m in self.session.modules if self.initialise_module(m)]

		# Create worker thread pool
		for i in range(self.session.thread_pool):
			thread = Checker(self)
			thread.setDaemon(True)
			thread.start()
			self._threads.append(thread)

		a = self.session.authenticate
		if a.login_url == None or len(a.login_url) == 0:
			self._begin()
		else:
			# Authenticate before spidering begins
			if not a.logout_url == None:
				if not a.logout_url in self.session.ignore_url: self.session.ignore_url.append(a.logout_url)

			auth = Authenticate()
			req = Request(auth.name, a.login_url, self.session.domain)
			req.meta[Authenticate.AUTH_META_KEY] = Authenticate.AUTH_REQUEST
			auth.initialise(self)
			req.modules = [auth]
			self.request_queue.put(req)

	def _begin(self):
		if self._resume_data:
			self._resume()
		else:
			self.request_queue.put_url('', self.session.page, self.session.domain)

	def _resume(self):
		if self._resume_data:
			self.request_queue.load(self._resume_data[1], self._resume_data[2])
			del self._resume_data
		else:
			raise Exception('No suspend data')

	def end(self):
		if self.session == None: raise SessionNotSetException()

		# Wait for worker threads to complete
		Checker.terminate.set()
		for thread in self._threads:
			thread.join()

		if self.is_complete():
			for mod in self.session.modules:
				if hasattr(mod, 'complete'): mod.complete()

		# Wait for log entries to be written
		self.session.report.end()
		self.session.report.join()

	def suspend(self):
		if self.session == None: raise SessionNotSetException()

		dat = self.request_queue.save()

		return pickle.dumps((self.session, dat[0], dat[1]))

	def resume(self, suspend_data):
		if self._started: raise SiteCheckStartedException()

		self._resume_data = pickle.loads(suspend_data)
		self.set_session(self._resume_data[0])

		if hasattr(self.session, '_cookie'):
			del self.session._cookie

# From: http://code.activestate.com/recipes/52308/
class Struct:
	def __init__(self, **kwargs): self.__dict__.update(kwargs)

def append(content, append):
	if content == None and append == None:
		return ''
	elif content == None:
		return append
	elif append == None:
		return content
	elif content.lower().endswith(append.lower()):
		return content
	else:
		return content + append

#def prepend(content, prepend):
	#if content == None and prepend == None:
		#return ''
	#if content == None:
		#return prepend
	#elif prepend == None:
		#return content
	#elif content.lower().startswith(prepend.lower()):
		#return content
	#else:
		#return prepend + content

def dict_to_sorted_list(dict_obj):
	out = []
	keys = list(dict_obj.keys())
	keys.sort()
	for key in keys:
		val = dict_obj[key]
		if type(val) is list or type(val) is tuple:
			for v in val:
				out.append((key, v))
		else:
			out.append((key, val))
	return out

# From: http://stackoverflow.com/questions/547829/how-to-dynamically-load-a-python-class
def get_module(name):
	mod = __import__(name)
	components = name.split('.')
	for comp in components[1:]:
		mod = getattr(mod, comp)
	return mod

def get_class(name):
	cls = get_module(name)
	return cls()

_ensure_dir_lock = threading.Lock()
def ensure_dir(directory):
	with _ensure_dir_lock:
		if not os.path.exists(directory):
			os.makedirs(directory)

class SessionNotSetException(Exception):
	pass

class SiteCheckStartedException(Exception):
	pass

class Checker(threading.Thread):
	terminate = threading.Event()

	def __init__(self, sitecheck):
		super(Checker, self).__init__()
		self.active = False # For determining whether a request is in progress
		self.sitecheck = sitecheck
		self._session = sitecheck.session
		self._output_queue = sitecheck.output_queue
		self._request_queue = sitecheck.request_queue

	def set_verb(self, request):
		if len(request.verb) == 0:
			dom = urllib.parse.urlparse(self._session.domain)
			if not request.domain == dom.netloc:
				# External domain
				request.verb = 'HEAD'
			elif not request.path.startswith(dom.path) and not request.extension in self._session.include_ext:
				# This is hit if path is a file on the current domain but above the current path
				request.verb = 'HEAD'
			elif request.extension in self._session.test_ext:
				request.verb = 'HEAD'
			else:
				request.set_verb()

	def set_headers(self, request):
		hdrs = self._session.headers.copy()
		hdrs.update(request.headers)
		request.headers = hdrs
		if 'Content-Type' in request.headers or 'content-type' in request.headers:
			pass
		else:
			request.headers['Content-Type'] = request.encoding

	def set_cookie(self, request):
		if hasattr(self._session, '_cookie'):
			c = self._session._cookie.output(['key', 'coded_value'], '', ';').strip()
			if 'Cookie' in request.headers:
				request.headers['Cookie'] += c
			elif 'cookie' in request.headers:
				request.headers['cookie'] += c
			else:
				request.headers['Cookie'] = c

	def get_cookie(self, response):
		cookies = response.get_headers('set-cookie')
		if len(cookies) > 0:
			if not hasattr(self._session, '_cookie'): self._session._cookie = http.cookies.SimpleCookie()
			for c in cookies:
				self._session._cookie.load(c)

	def process(self, request, response, report):
		if len(request.modules) == 0: request.modules = self._session.modules
		for mod in request.modules:
			try:
				mod.process(request, response, report)
			except:
				if self._session._debug: raise
				ex = sys.exc_info()
				report.add_message('ERROR: Processing failed with module [{0}].'.format(mod.name), mod.source)
				report.add_message(str(ex[1]), mod.source)

	def fetch(self, request):
		full_path = request.path
		if len(request.query) > 0: full_path += '?' + request.query

		if request.protocol == 'https':
			c = http.client.HTTPSConnection(request.domain, timeout=self._session.request_timeout)
		elif request.protocol == 'http':
			c = http.client.HTTPConnection(request.domain, timeout=self._session.request_timeout)
		else:
			raise Exception('Unrecognised protocol: {0}'.format(request.protocol))

		res = err = None
		try:
			c.connect()
			st = time.time()
			c.request(request.verb, full_path, request.get_post_data(), request.headers)
			r = c.getresponse()
			res = Response(r, st)
		except socket.gaierror:
			ex = sys.exc_info()
			err = 'DNS error {0} {1}'.format(str(ex[0]), str(ex[1])) # Probably
		except socket.timeout:
			ex = sys.exc_info()
			err = 'Timeout {0} {1}'.format(str(ex[0]), str(ex[1]))
		except http.client.IncompleteRead:
			ex = sys.exc_info()
			err = 'Read error {0} {1}'.format(str(ex[0]), str(ex[1]))
		except:
			ex = sys.exc_info()
			err = 'Error {0} {1}'.format(str(ex[0]), str(ex[1]))
		finally:
			c.close()

		return res, err

	def run(self):
		while not Checker.terminate.isSet():
			self.active = False
			Checker.terminate.wait(self._session.wait_seconds)
			try:
				req = self._request_queue.get(block=False)
			except queue.Empty:
				pass
			else:
				self.active = True

				self.set_verb(req)
				self.set_headers(req)
				self.set_cookie(req)

				res, err = self.fetch(req)

				report = ReportData('Method: [{0}]'.format(req.verb))

				if res:
					dom = urllib.parse.urlparse(self._session.domain)
					if req.domain == dom.netloc: self.get_cookie(res)

					report.add_message('Status: [{0}]'.format(str(res.status)))
					if self._session.log.request_headers: report.add_message('Request Headers: {0}'.format(req.headers))
					if self._session.log.post_data and len(req.postdata) > 0: report.add_message('Post Data: {0}'.format(req.get_post_data()))
					if self._session.log.response_headers: report.add_message('Response Headers: {0}'.format(res.headers))

					if res.time > self._session.slow_request:
						report.add_message('WARNING: Slow request: [{0}] ({1:.3f} seconds)'.format(str(req), res.time))

					# Only process markup of error pages once
					if not hasattr(self._session, '_processed'):
						self._session._processed = []

					if (res.status >= 300 and res.status < 400) and req.domain == dom.netloc:
						loc = res.get_headers('location')
						if len(loc) > 0:
							if len(loc) > 1:
								report.add_message('ERROR: Multiple redirect locations found: [{0}]'.format(loc))

							redir, err = self._request_queue.redirect(req, loc[-1])

							if not redir:
								report.add_message('ERROR: {0}'.format(err))
						else:
							report.add_message('ERROR: Redirect with no location: [{0}]'.format(req.referrer))
					elif res.status >= 400 and not res.status in self._session._processed and req.domain == dom.netloc and req.verb == 'HEAD':
						# If first error page is on a HEAD request, get the resource again
						req.set_verb()
						self._request_queue.put(req)
					else:
						if res.status >= 400 and req.domain == dom.netloc:
							if res.status in self._session._processed:
								res.is_html = False
							else:
								self._session._processed.append(res.status)

						self.process(req, res, report)
				else:
					if err:
						report.add_message('ERROR: {0}: [{1}]'.format(err, str(req)))

					if not self._request_queue.retry(req):
						report.add_message('ERROR: Exceeded max retries for: [{0}]'.format(str(req)))

				self._output_queue.put(req, res, report)

class Request(object):
	def __init__(self, source, url, referrer, encoding='application/x-www-form-urlencoded'):
		self.source = source
		self.referrer = referrer
		self.encoding = encoding
		self.boundary = uuid.uuid4().hex
		self.verb = '' # Do not default to GET so we can tell if it is set manually or not
		self.redirects = 0
		self.timeouts = 0
		self.modules = []
		self.postdata = []
		self.headers = {} # Dictionary for httplib
		self._set_url(url)
		self.meta = {}

	def _set_url(self, url):
		url = HtmlHelper.html_decode(url.replace(' ', '%20'))
		url_parts = urllib.parse.urlparse(url)

		if len(url_parts.scheme) == 0:
			# Relative URL - join with referrer
			url = urllib.parse.urljoin(self.referrer, url)
			url_parts = urllib.parse.urlparse(url)

		self.protocol = url_parts.scheme.lower()
		self.domain = url_parts.netloc.lower()
		self.path = url_parts.path
		self.extension = os.path.splitext(url_parts.path)[1][1:].lower()

		if len(url_parts.query) == 0:
			self.query = ''
		else:
			qsin = urllib.parse.parse_qs(url_parts.query, keep_blank_values=True)
			# URL's with querystring parameters in different order are equivalent
			qsout = dict_to_sorted_list(qsin)
			self.query = urllib.parse.urlencode(qsout)

	def get_post_data(self):
		if self.encoding == 'multipart/form-data':
			# Adapted from: http://code.activestate.com/recipes/146306-http-client-to-post-using-multipartform-data/
			dat = []
			for key, value in self.postdata:
				dat.append('--' + self.boundary)
				dat.append('Content-Disposition: form-data; name="{0}"'.format(key))
				dat.append('')
				dat.append(value)
			dat.append('--' + self.boundary + '--')
			dat.append('')
			return r'\r\n'.join(dat)
		else:
			return urllib.parse.urlencode(self.postdata)

	def set_post_data(self, postdata):
		self.postdata = []
		keys = [x for x, y in postdata]
		keys.sort()
		for k in keys:
			for v in [v for v in postdata if v[0] == k]:
				self.postdata.append((k, v[1]))

	def __str__(self):
		url = '{0}://{1}{2}'.format(self.protocol, self.domain, self.path)
		#if len(self.parameters) > 0: url += ';' + self.parameters
		if len(self.query) > 0: url += '?' + self.query
		return url

	def hash(self):
		# Relies on query, post and headers being sorted
		m = hashlib.sha1()
		m.update(self.verb.encode())
		m.update(self.__str__().encode())

		hdrs = dict_to_sorted_list(self.headers)
		if len(hdrs) > 0: m.update(urllib.parse.urlencode(hdrs).encode())

		pd = self.get_post_data()
		if len(pd) > 0: m.update(pd.encode())

		return m.hexdigest()

	def set_verb(self):
		if len(self.get_post_data()) > 0:
			self.verb = 'POST'
		else:
			self.verb = 'GET'

class Response(object):
	def __init__(self, response, start_time):
		end_time = time.time()
		self.headers = response.getheaders()
		html = self.get_header('content-type').startswith('text/html')
		temp = response.read()
		if temp and html:
			self.content = temp.decode('utf-8', errors='replace')
		elif temp:
			self.content = temp
		else:
			self.content = ''
		self.time = end_time - start_time
		self.status = response.status
		self.message = response.reason
		self.version = response.version
		# self.status < 300 and
		if html and len(self.content) > 0:
			self.is_html = True
		else:
			self.is_html = False

	def get_header(self, name):
		hdrs = self.get_headers(name)
		if len(hdrs) > 0:
			return hdrs[0]
		else:
			return ''

	def get_headers(self, name):
		hdrs = [h for h in self.headers if h[0].lower() == name.lower()]
		return [h[1] for h in hdrs]

class RequestQueue(queue.Queue):
	def __init__(self, session):
		super(RequestQueue, self).__init__()
		self.session = session
		self._lock = threading.Lock()
		self.urls = {}

	def is_valid(self, url):
		if url == None: return False
		if len(url) == 0: return False
		if url.startswith('#'): return False

		parts = urllib.parse.urlparse(url)
		for ignore in self.session.ignore_url:
			if parts.path.lower().endswith(ignore.lower()): return False

		ext = os.path.splitext(parts.path)[1][1:].lower()
		if ext in self.session.ignore_ext: return False

		if re.match('^http', parts.scheme, re.IGNORECASE) or len(parts.scheme) == 0:
			return True
		else:
			return False

	def _put_url(self, source, url, referrer, block, timeout):
		req = Request(source, url, referrer)
		if self.is_valid(str(req)):
			hc = req.hash()
			if not hc in self.urls:
				self.urls[hc] = True
				queue.Queue.put(self, req, block, timeout)

	def put_url(self, source, url, referrer, block=True, timeout=None):
		with self._lock:
			if isinstance(url, list):
				for u in url:
					self._put_url(source, u, referrer, block, timeout)
			else:
				self._put_url(source, str(url), referrer, block, timeout)

	def put(self, request, block=True, timeout=None):
		if self.is_valid(str(request)):
			with self._lock:
				hc = request.hash()
				if not hc in self.urls:
					self.urls[hc] = True
					queue.Queue.put(self, request, block, timeout)

	def load(self, urls, requests, block=True, timeout=None):
		self.urls = urls
		for r in requests:
			queue.Queue.put(self, r, block, timeout)

	def save(self, block=False):
		rq = []
		while not self.empty():
			rq.append(self.get(block))
		return (self.urls, rq)

	def retry(self, request):
		if request.timeouts >= self.session.max_retries:
			return False
		else:
			request.timeouts += 1
			queue.Queue.put(self, request)
			return True

	def redirect(self, request, url):
		if request.redirects >= self.session.max_redirects:
			return (False, 'Max redirects exceeded: [{0}]'.format(request.referrer))
		else:
			req = copy.copy(request)
			req._set_url(url)
			if str(req) == str(request):
				return (False, 'Page redirects to itself')
			else:
				if req.redirects == 0:
					req.referrer = str(request)
					req.postdata = [] # Reset to get on redirect
					req.verb = 'GET'

				req.redirects += 1
				queue.Queue.put(self, req)
				return (True, '')

class HtmlHelper(object):
	# From: http://effbot.org/zone/re-sub.htm#unescape-html
	def html_decode(text):
		def fixup(m):
			text = m.group(0)
			if text[:2] == "&#":
				try:
					if text[:3] == "&#x":
						return chr(int(text[3:-1], 16))
					else:
						return chr(int(text[2:-1]))
				except ValueError:
					pass
			else:
				try:
					text = chr(html.entities.name2codepoint[text[1:-1]])
				except KeyError:
					pass
			return text
		return re.sub("&#?\w+;", fixup, text)

	def __init__(self, document):
		self.document = document
		self.flags = re.IGNORECASE | re.DOTALL # | re.MULTILINE

	def get_element(self, element):
		#rx = re.compile(r'<\s*%s\b.*?>' % element, self.flags)
		rx = re.compile(r'<\s*{0}\b[^>]*(?:/\s*>)|(?:>.*?<\s*/\s*{1}\s*>)'.format(element, element), self.flags)
		mtchs = rx.finditer(self.document)
		for m in mtchs:
			yield HtmlHelper(m.group(0))

	def get_attribute(self, attribute, element=None):
		# Test strings:
		# < form name = name action = test 1 method = get>
		# < form name = "name" action = "test 1" method = "get">

		if element:
			rx = re.compile(r'<\s*(?P<element>{0})\s[^>]*?(?<=\s){1}\s*=\s*(?P<quoted>")?(?P<attr>.*?)(?(quoted)"|[\s>])' \
				.format(element, attribute), self.flags)
		else:
			rx = re.compile(r'<\s*(?P<element>[^\s>]+)\s[^>]*?(?<=\s){0}\s*=\s*(?P<quoted>")?(?P<attr>.*?)(?(quoted)"|[\s>])' \
				.format(attribute), self.flags)

		mtchs = rx.finditer(self.document)
		for m in mtchs:
			yield (m.group('element'), attribute, m.group('attr'))

	def get_text(self, element=None):
		if element:
			rx = re.compile(r'<\s*{0}\b[^>]*?>(?P<text>[^<]*?\w[^<]*?)(?:<|$)'.format(element), self.flags)
		else:
			rx = re.compile(r'(?:^[^<]|>)(?P<text>[^<]*?\w[^<]*?)(?:<|$)', self.flags)

		mtchs = rx.finditer(self.document)
		for m in mtchs:
			yield m.group('text')

	def strip_element(self, elements):
		names = elements
		if type(elements) is str:
			names = (elements)

		for e in names:
			self.document = re.sub(r'<\s*{0}\b.*?>.*?<\s*/\s*{1}\s*>'.format(e, e), \
				'', self.document, flags=self.flags)

	def strip_comments(self):
		self.document = re.sub(r'<\s*!\s*-\s*-.*?-\s*-\s*>', '', self.document, flags=self.flags)

	def get_comments(self):
		rx = re.compile(r'<\s*!\s*-\s*-(?P<comment>.*?)-\s*-\s*>', self.flags)

		mtchs = rx.finditer(self.document)
		for m in mtchs:
			yield m.group('comment')

class ModuleBase(object):
	def __init__(self):
		self.name = self.__class__.__name__
		self.source = self.__class__.__name__.lower()

	def initialise(self, sitecheck):
		self.sitecheck = sitecheck
		self.sync_lock = threading.Lock()

	def create_message(self, message):
		self.sitecheck.output_queue.put_message(message, source=self.source)

	def add_message(self, report, message):
		report.add_message(message, source=self.source)

	def add_request(self, url, referrer):
		self.sitecheck.request_queue.put_url(self.name, url, referrer)

	def __getstate__(self):
		state = dict(self.__dict__)
		return self._clean_state(state)

	def _clean_state(self, state):
		del state['sync_lock']
		del state['sitecheck']
		return state

def report(method):
	def inner(self, *args, **kwargs):
		r = ReportData()
		try:
			return method(self, r, *args, **kwargs)
		finally:
			self.sitecheck.output_queue.put_report(r)

	return inner

class Authenticate(ModuleBase):
	AUTH_META_KEY = '__AUTHENTICATION'
	AUTH_REQUEST = 'Request'
	AUTH_RESPONSE = 'Response'

	def _log(self, request, response, report):
		self.add_message(report, 'Method: [{0}]'.format(request.verb))
		self.add_message(report, 'Status: [{0}]'.format(str(response.status)))
		self.add_message(report, 'Request Headers: {0}'.format(request.headers))
		self.add_message(report, 'Response Headers: {0}\n'.format(response.headers))

		if response.status >= 400:
			self.add_message(report, 'ERROR: Authentication Failed')
			if len(request.postdata) > 0:
				self.add_message(report, 'Post Data: {0}'.format(request.get_post_data()))

	def process(self, request, response, report):
		a = self.sitecheck.session.authenticate
		if request.meta[Authenticate.AUTH_META_KEY] == Authenticate.AUTH_REQUEST:
			self._log(request, response, report)

			if a.post:
				url = a.login_url
			else:
				if len(urllib.parse.urlparse(a.login_url).query) > 0:
					sep = '&'
				else:
					sep = '?'
				url = '{0}{1}{2}'.format(a.login_url, sep, urllib.parse.urlencode(a.params, True))

			req = Request(self.name, url, str(request))
			req.meta[Authenticate.AUTH_META_KEY] = Authenticate.AUTH_RESPONSE
			if a.post: req.set_post_data(a.params)
			req.modules = [self]
			self.sitecheck.request_queue.put(req)
		if request.meta[Authenticate.AUTH_META_KEY] == Authenticate.AUTH_RESPONSE:
			self._log(request, response, report)

			self.sitecheck._begin()
